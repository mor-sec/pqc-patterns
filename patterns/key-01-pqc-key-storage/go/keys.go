// Package keys implements pattern KEY-01: generating, encoding and storing
// ML-DSA and ML-KEM keys.
//
// Private keys are stored as their seed (32 bytes for ML-DSA, 64 for ML-KEM)
// in the seed-only PKCS#8 form of RFC 9881 and RFC 9935, PEM-encoded as
// "PRIVATE KEY". Public keys use SubjectPublicKeyInfo, PEM-encoded as
// "PUBLIC KEY". Parsing is strict: only the exact DER this package writes is
// accepted, so every key has one encoding and one key ID.
package keys

import (
	"bytes"
	"crypto/mldsa"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"runtime"
)

// Algorithm names a key type by its FIPS name.
type Algorithm string

const (
	MLDSA65   Algorithm = "ML-DSA-65"
	MLDSA87   Algorithm = "ML-DSA-87" // CNSA 2.0
	MLKEM768  Algorithm = "ML-KEM-768"
	MLKEM1024 Algorithm = "ML-KEM-1024" // CNSA 2.0
)

var oids = map[Algorithm]asn1.ObjectIdentifier{
	MLDSA65:   {2, 16, 840, 1, 101, 3, 4, 3, 18},
	MLDSA87:   {2, 16, 840, 1, 101, 3, 4, 3, 19},
	MLKEM768:  {2, 16, 840, 1, 101, 3, 4, 4, 2},
	MLKEM1024: {2, 16, 840, 1, 101, 3, 4, 4, 3},
}

// SeedSize returns the private seed length: 32 bytes for ML-DSA (FIPS 204
// xi), 64 bytes for ML-KEM (FIPS 203 d || z).
func (a Algorithm) SeedSize() int {
	switch a {
	case MLDSA65, MLDSA87:
		return mldsa.PrivateKeySize
	case MLKEM768, MLKEM1024:
		return mlkem.SeedSize
	}
	return 0
}

// ErrInvalidKey is returned for any malformed, non-canonical or unsupported
// key encoding.
var ErrInvalidKey = errors.New("keys: invalid key encoding")

// KeyPair is a private seed and the public key derived from it.
type KeyPair struct {
	Algorithm Algorithm
	Seed      []byte
	PublicKey []byte
}

// Generate creates a new key pair from the system CSPRNG.
func Generate(alg Algorithm) (*KeyPair, error) {
	if alg.SeedSize() == 0 {
		return nil, fmt.Errorf("keys: unsupported algorithm %q", alg)
	}
	seed := make([]byte, alg.SeedSize())
	rand.Read(seed) // crypto/rand.Read never returns an error since Go 1.24.
	return FromSeed(alg, seed)
}

// FromSeed rebuilds a key pair from its seed.
func FromSeed(alg Algorithm, seed []byte) (*KeyPair, error) {
	key, err := newPrivateKey(alg, seed)
	if err != nil {
		return nil, err
	}
	k := &KeyPair{Algorithm: alg, Seed: bytes.Clone(seed)}
	switch key := key.(type) {
	case *mldsa.PrivateKey:
		k.PublicKey = key.PublicKey().Bytes()
	case *mlkem.DecapsulationKey768:
		k.PublicKey = key.EncapsulationKey().Bytes()
	case *mlkem.DecapsulationKey1024:
		k.PublicKey = key.EncapsulationKey().Bytes()
	}
	return k, nil
}

// PrivateKey returns the usable key: a *mldsa.PrivateKey, a
// *mlkem.DecapsulationKey768 or a *mlkem.DecapsulationKey1024.
func (k *KeyPair) PrivateKey() (any, error) {
	return newPrivateKey(k.Algorithm, k.Seed)
}

func newPrivateKey(alg Algorithm, seed []byte) (any, error) {
	if len(seed) != alg.SeedSize() {
		return nil, fmt.Errorf("keys: %s seed must be %d bytes, got %d", alg, alg.SeedSize(), len(seed))
	}
	switch alg {
	case MLDSA65:
		return mldsa.NewPrivateKey(mldsa.MLDSA65(), seed)
	case MLDSA87:
		return mldsa.NewPrivateKey(mldsa.MLDSA87(), seed)
	case MLKEM768:
		return mlkem.NewDecapsulationKey768(seed)
	case MLKEM1024:
		return mlkem.NewDecapsulationKey1024(seed)
	}
	return nil, fmt.Errorf("keys: unsupported algorithm %q", alg)
}

// KeyID is the lowercase hex SHA-256 of the public key's SubjectPublicKeyInfo
// DER, a stable name for the key in logs, key sets and rotation records.
func (k *KeyPair) KeyID() string {
	sum := sha256.Sum256(spki(k.Algorithm, k.PublicKey))
	return hex.EncodeToString(sum[:])
}

type privateKeyInfo struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type subjectPublicKeyInfo struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func pkcs8(alg Algorithm, seed []byte) []byte {
	// The seed choice of ML-DSA-PrivateKey and ML-KEM-PrivateKey:
	// [0] IMPLICIT OCTET STRING.
	choice, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
	if err != nil {
		panic(err)
	}
	der, err := asn1.Marshal(privateKeyInfo{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: oids[alg]},
		PrivateKey: choice,
	})
	if err != nil {
		panic(err)
	}
	return der
}

func spki(alg Algorithm, pub []byte) []byte {
	der, err := asn1.Marshal(subjectPublicKeyInfo{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oids[alg]},
		PublicKey: asn1.BitString{Bytes: pub, BitLength: 8 * len(pub)},
	})
	if err != nil {
		panic(err)
	}
	return der
}

// PrivateKeyPEM encodes the seed as seed-only PKCS#8 in a "PRIVATE KEY" block.
func (k *KeyPair) PrivateKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8(k.Algorithm, k.Seed)})
}

// PublicKeyPEM encodes the public key as SubjectPublicKeyInfo in a "PUBLIC
// KEY" block.
func (k *KeyPair) PublicKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki(k.Algorithm, k.PublicKey)})
}

func algorithmOf(id pkix.AlgorithmIdentifier) (Algorithm, bool) {
	for alg, oid := range oids {
		if id.Algorithm.Equal(oid) {
			return alg, true
		}
	}
	return "", false
}

func decodePEM(data []byte, typ string) ([]byte, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != typ || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, ErrInvalidKey
	}
	return block.Bytes, nil
}

// ParsePrivateKeyPEM reads a key written by PrivateKeyPEM. Expanded and
// "both" private key forms, encrypted PEM and trailing data are rejected.
func ParsePrivateKeyPEM(data []byte) (*KeyPair, error) {
	der, err := decodePEM(data, "PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	var info privateKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return nil, ErrInvalidKey
	}
	alg, ok := algorithmOf(info.Algorithm)
	n := alg.SeedSize()
	if !ok || len(info.PrivateKey) != 2+n {
		return nil, ErrInvalidKey
	}
	seed := info.PrivateKey[2:]
	if !bytes.Equal(pkcs8(alg, seed), der) {
		return nil, ErrInvalidKey
	}
	return FromSeed(alg, seed)
}

// ParsePublicKeyPEM reads a key written by PublicKeyPEM and checks that it is
// a valid key for its algorithm.
func ParsePublicKeyPEM(data []byte) (Algorithm, []byte, error) {
	der, err := decodePEM(data, "PUBLIC KEY")
	if err != nil {
		return "", nil, err
	}
	var info subjectPublicKeyInfo
	if rest, err := asn1.Unmarshal(der, &info); err != nil || len(rest) != 0 {
		return "", nil, ErrInvalidKey
	}
	alg, ok := algorithmOf(info.Algorithm)
	pub := info.PublicKey.Bytes
	if !ok || !bytes.Equal(spki(alg, pub), der) {
		return "", nil, ErrInvalidKey
	}
	switch alg {
	case MLDSA65:
		_, err = mldsa.NewPublicKey(mldsa.MLDSA65(), pub)
	case MLDSA87:
		_, err = mldsa.NewPublicKey(mldsa.MLDSA87(), pub)
	case MLKEM768:
		_, err = mlkem.NewEncapsulationKey768(pub)
	case MLKEM1024:
		_, err = mlkem.NewEncapsulationKey1024(pub)
	}
	if err != nil {
		return "", nil, ErrInvalidKey
	}
	return alg, bytes.Clone(pub), nil
}

// WritePrivateKeyFile writes the private key PEM to a new file readable only
// by its owner. It refuses to overwrite an existing file.
func WritePrivateKeyFile(path string, k *KeyPair) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(k.PrivateKeyPEM()); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadPrivateKeyFile reads a private key file, refusing files that other
// users can read or write (as OpenSSH does).
func ReadPrivateKeyFile(path string) (*KeyPair, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, &fs.PathError{Op: "open", Path: path, Err: errors.New("private key is accessible by other users")}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(data)
}
