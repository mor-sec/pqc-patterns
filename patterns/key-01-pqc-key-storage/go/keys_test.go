package keys

import (
	"bytes"
	"crypto/mldsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var algorithms = []Algorithm{MLDSA65, MLDSA87, MLKEM768, MLKEM1024}

func TestRoundTrip(t *testing.T) {
	for _, alg := range algorithms {
		k, err := Generate(alg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParsePrivateKeyPEM(k.PrivateKeyPEM())
		if err != nil || got.Algorithm != alg || !bytes.Equal(got.Seed, k.Seed) || !bytes.Equal(got.PublicKey, k.PublicKey) {
			t.Fatalf("%s: private key round trip failed: %v", alg, err)
		}
		pubAlg, pub, err := ParsePublicKeyPEM(k.PublicKeyPEM())
		if err != nil || pubAlg != alg || !bytes.Equal(pub, k.PublicKey) {
			t.Fatalf("%s: public key round trip failed: %v", alg, err)
		}
		if _, err := k.PrivateKey(); err != nil {
			t.Fatal(err)
		}
	}
}

// The ML-DSA encodings must match Go's own crypto/x509, which implements
// RFC 9881 independently of this package.
func TestMatchesStdlibX509(t *testing.T) {
	for _, alg := range []Algorithm{MLDSA65, MLDSA87} {
		k, _ := Generate(alg)
		priv, _ := k.PrivateKey()
		want, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(pkcs8(alg, k.Seed), want) {
			t.Fatalf("%s: PKCS#8 differs from crypto/x509", alg)
		}
		wantPub, err := x509.MarshalPKIXPublicKey(priv.(*mldsa.PrivateKey).PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(spki(alg, k.PublicKey), wantPub) {
			t.Fatalf("%s: SubjectPublicKeyInfo differs from crypto/x509", alg)
		}
	}
}

func TestKeyID(t *testing.T) {
	a, _ := Generate(MLDSA65)
	b, _ := Generate(MLDSA65)
	if len(a.KeyID()) != 64 || a.KeyID() == b.KeyID() {
		t.Fatal("key IDs are not distinct SHA-256 values")
	}
	again, _ := ParsePrivateKeyPEM(a.PrivateKeyPEM())
	if again.KeyID() != a.KeyID() {
		t.Fatal("key ID changed after a round trip")
	}
}

func TestRejectsBadSeed(t *testing.T) {
	if _, err := FromSeed(MLDSA65, make([]byte, 31)); err == nil {
		t.Fatal("short seed accepted")
	}
	if _, err := Generate("RSA-2048"); err == nil {
		t.Fatal("unsupported algorithm accepted")
	}
}

func pemString(typ string, der []byte, headers map[string]string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: typ, Headers: headers, Bytes: der}))
}

// invalidPrivateKeys returns encodings of seed's key that must be rejected.
func invalidPrivateKeys(alg Algorithm, seed []byte) []string {
	good := pkcs8(alg, seed)
	both, _ := asn1.Marshal(struct{ Seed, Expanded []byte }{seed, bytes.Repeat([]byte{1}, 64)})
	expanded, _ := asn1.Marshal(bytes.Repeat([]byte{1}, 64))
	withNull, _ := asn1.Marshal(privateKeyInfo{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: oids[alg], Parameters: asn1.NullRawValue},
		PrivateKey: good[len(good)-2-len(seed):],
	})
	wrap := func(inner []byte) []byte {
		der, _ := asn1.Marshal(privateKeyInfo{Algorithm: pkix.AlgorithmIdentifier{Algorithm: oids[alg]}, PrivateKey: inner})
		return der
	}
	short, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed[1:]})
	rsaOID, _ := asn1.Marshal(privateKeyInfo{
		Algorithm:  pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}},
		PrivateKey: good[len(good)-2-len(seed):],
	})
	return []string{
		pemString("PRIVATE KEY", wrap(both), nil),
		pemString("PRIVATE KEY", wrap(expanded), nil),
		pemString("PRIVATE KEY", wrap(short), nil),
		pemString("PRIVATE KEY", withNull, nil),
		pemString("PRIVATE KEY", rsaOID, nil),
		pemString("PRIVATE KEY", append(bytes.Clone(good), 0), nil),
		pemString("ENCRYPTED PRIVATE KEY", good, nil),
		pemString("PRIVATE KEY", good, map[string]string{"Proc-Type": "4,ENCRYPTED"}),
		pemString("PRIVATE KEY", good, nil) + pemString("PRIVATE KEY", good, nil),
		"not a key",
	}
}

func TestRejectsMalformedPrivateKeys(t *testing.T) {
	for _, alg := range algorithms {
		k, _ := Generate(alg)
		for i, bad := range invalidPrivateKeys(alg, k.Seed) {
			if _, err := ParsePrivateKeyPEM([]byte(bad)); !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("%s: malformed key %d accepted", alg, i)
			}
		}
	}
}

// invalidPublicKeys returns encodings of pub that must be rejected.
func invalidPublicKeys(alg Algorithm, pub []byte) []string {
	good := spki(alg, pub)
	other := MLDSA65
	if alg == MLDSA65 {
		other = MLKEM768
	}
	out := []string{
		pemString("PUBLIC KEY", spki(alg, pub[1:]), nil),
		pemString("PUBLIC KEY", spki(other, pub), nil),
		pemString("PUBLIC KEY", append(bytes.Clone(good), 0), nil),
		pemString("PRIVATE KEY", good, nil),
		pemString("PUBLIC KEY", good, nil) + pemString("PUBLIC KEY", good, nil),
	}
	if alg == MLKEM768 || alg == MLKEM1024 {
		// FIPS 203 section 7.2: every coefficient must be below q = 3329.
		bad := bytes.Clone(pub)
		bad[0], bad[1] = 0xff, 0xff
		out = append(out, pemString("PUBLIC KEY", spki(alg, bad), nil))
	}
	return out
}

func TestRejectsMalformedPublicKeys(t *testing.T) {
	for _, alg := range algorithms {
		k, _ := Generate(alg)
		for i, data := range invalidPublicKeys(alg, k.PublicKey) {
			if _, _, err := ParsePublicKeyPEM([]byte(data)); err == nil {
				t.Fatalf("%s: malformed public key %d accepted", alg, i)
			}
		}
	}
}

func TestPrivateKeyFile(t *testing.T) {
	k, _ := Generate(MLDSA65)
	path := filepath.Join(t.TempDir(), "signing.pem")
	if err := WritePrivateKeyFile(path, k); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode is %v", info.Mode().Perm())
	}
	if err := WritePrivateKeyFile(path, k); err == nil {
		t.Fatal("existing key file overwritten")
	}
	got, err := ReadPrivateKeyFile(path)
	if err != nil || !bytes.Equal(got.Seed, k.Seed) {
		t.Fatalf("read back failed: %v", err)
	}
	os.Chmod(path, 0o644)
	if _, err := ReadPrivateKeyFile(path); err == nil {
		t.Fatal("world-readable key file accepted")
	}
}

type vectorKey struct {
	Algorithm     Algorithm `json:"algorithm"`
	Seed          string    `json:"seed"`
	PrivateKeyPEM string    `json:"private_key_pem"`
	PublicKeyPEM  string    `json:"public_key_pem"`
	KeyID         string    `json:"key_id"`
	Invalid       []string  `json:"invalid_private_key_pems"`
	InvalidPublic []string  `json:"invalid_public_key_pems"`
}

// TestVector checks the shared cross-language vector. Keys are derived from
// the seeds 00 01 02 ..., as in the RFC 9881 and RFC 9935 examples.
// Regenerate it with PQC_WRITE_VECTORS=1 go test ./...
func TestVector(t *testing.T) {
	path := "../testdata/vector.json"
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		var out []vectorKey
		for _, alg := range algorithms {
			seed := make([]byte, alg.SeedSize())
			for i := range seed {
				seed[i] = byte(i)
			}
			k, err := FromSeed(alg, seed)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, vectorKey{
				Algorithm:     alg,
				Seed:          hex.EncodeToString(seed),
				PrivateKeyPEM: string(k.PrivateKeyPEM()),
				PublicKeyPEM:  string(k.PublicKeyPEM()),
				KeyID:         k.KeyID(),
				Invalid:       invalidPrivateKeys(alg, seed),
				InvalidPublic: invalidPublicKeys(alg, k.PublicKey),
			})
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vectorKey
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != len(algorithms) {
		t.Fatal("vector is missing algorithms")
	}
	for _, v := range vectors {
		k, err := ParsePrivateKeyPEM([]byte(v.PrivateKeyPEM))
		if err != nil || k.Algorithm != v.Algorithm || hex.EncodeToString(k.Seed) != v.Seed {
			t.Fatalf("%s: private key mismatch: %v", v.Algorithm, err)
		}
		if string(k.PrivateKeyPEM()) != v.PrivateKeyPEM || string(k.PublicKeyPEM()) != v.PublicKeyPEM || k.KeyID() != v.KeyID {
			t.Fatalf("%s: re-encoding differs", v.Algorithm)
		}
		for i, bad := range v.Invalid {
			if _, err := ParsePrivateKeyPEM([]byte(bad)); err == nil {
				t.Fatalf("%s: invalid key %d accepted", v.Algorithm, i)
			}
		}
		for i, bad := range v.InvalidPublic {
			if _, _, err := ParsePublicKeyPEM([]byte(bad)); err == nil {
				t.Fatalf("%s: invalid public key %d accepted", v.Algorithm, i)
			}
		}
	}
}
