// Package artifacts implements pattern SIG-02: signing release artifacts,
// such as binaries, archives and firmware images, with detached ML-DSA-87
// signatures.
//
// A signature file is UTF-8 text with exactly these lines, in this order:
//
//	pqc-patterns-signature-v1
//	algorithm: ML-DSA-87
//	key: <hex SHA-256 of the signer's SubjectPublicKeyInfo DER>
//	name: <artifact name, printable ASCII without spaces>
//	size: <artifact length in bytes>
//	sha512: <hex SHA-512 of the artifact>
//	signed: <RFC 3339 UTC time, whole seconds>
//	signature: <base64 ML-DSA-87 signature>
//
// The signature covers the first seven lines exactly as written, including
// their line feeds, under the ML-DSA context string Context. Verifiers check
// the signature before they read the artifact, and check the name they
// expected rather than trusting the file's.
package artifacts

import (
	"bytes"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	// Context domain-separates artifact signatures from every other use of
	// the same key (FIPS 204, section 5.2).
	Context   = "pqc-patterns/sig-02/artifact/v1"
	Algorithm = "ML-DSA-87"
	magic     = "pqc-patterns-signature-v1"
	// MaxSignatureFile bounds what Verify will parse.
	MaxSignatureFile = 16 * 1024
	maxNameLen       = 255
)

var (
	ErrMalformed     = errors.New("artifacts: malformed signature file")
	ErrUnknownKey    = errors.New("artifacts: signed by an untrusted key")
	ErrSignature     = errors.New("artifacts: signature does not verify")
	ErrWrongArtifact = errors.New("artifacts: signature is for a different artifact")
)

// Params is the parameter set. Artifact signing keys live for years and the
// signature size rarely matters, so this pattern uses the CNSA 2.0 level.
func Params() mldsa.Parameters { return mldsa.MLDSA87() }

// Statement is what a signature file asserts.
type Statement struct {
	KeyID  string
	Name   string
	Size   int64
	SHA512 []byte
	Signed time.Time
}

func (s *Statement) encode() []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\nalgorithm: %s\nkey: %s\nname: %s\nsize: %d\nsha512: %s\nsigned: %s\n",
		magic, Algorithm, s.KeyID, s.Name, s.Size, hex.EncodeToString(s.SHA512),
		s.Signed.UTC().Format(time.RFC3339))
	return b.Bytes()
}

// KeyID returns the hex SHA-256 of pub's SubjectPublicKeyInfo DER, the same
// key ID as pattern KEY-01.
func KeyID(pub *mldsa.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func validName(name string) bool {
	if len(name) == 0 || len(name) > maxNameLen {
		return false
	}
	for i := 0; i < len(name); i++ {
		if name[i] < 0x21 || name[i] > 0x7e {
			return false
		}
	}
	return true
}

// Signer signs artifacts with one key.
type Signer struct {
	Key *mldsa.PrivateKey
	Now func() time.Time
}

// NewSigner loads a signing key from its 32-byte seed (see KEY-01 for
// storing it).
func NewSigner(seed []byte) (*Signer, error) {
	sk, err := mldsa.NewPrivateKey(Params(), seed)
	if err != nil {
		return nil, err
	}
	return &Signer{Key: sk, Now: time.Now}, nil
}

// Sign reads the artifact to the end and returns the signature file.
// name is how verifiers will refer to the artifact, such as
// "myapp-1.4.2-linux-amd64.tar.gz".
func (s *Signer) Sign(name string, artifact io.Reader) ([]byte, error) {
	if !validName(name) {
		return nil, fmt.Errorf("artifacts: invalid artifact name %q", name)
	}
	h := sha512.New()
	size, err := io.Copy(h, artifact)
	if err != nil {
		return nil, err
	}
	st := Statement{
		KeyID:  KeyID(s.Key.PublicKey()),
		Name:   name,
		Size:   size,
		SHA512: h.Sum(nil),
		Signed: s.Now().UTC().Truncate(time.Second),
	}
	msg := st.encode()
	sig, err := s.Key.Sign(nil, msg, &mldsa.Options{Context: Context})
	if err != nil {
		return nil, err
	}
	return fmt.Appendf(msg, "signature: %s\n", base64.StdEncoding.EncodeToString(sig)), nil
}

// Verifier checks signature files against a set of trusted keys.
type Verifier struct {
	keys map[string]*mldsa.PublicKey
}

// NewVerifier trusts the given public keys.
func NewVerifier(keys ...*mldsa.PublicKey) *Verifier {
	v := &Verifier{keys: make(map[string]*mldsa.PublicKey)}
	for _, k := range keys {
		v.keys[KeyID(k)] = k
	}
	return v
}

// Verify checks sigFile and then that artifact is the one it signs, under
// the name the caller expects. It returns the verified statement.
func (v *Verifier) Verify(sigFile []byte, name string, artifact io.Reader) (*Statement, error) {
	st, msg, sig, err := parse(sigFile)
	if err != nil {
		return nil, err
	}
	pk, ok := v.keys[st.KeyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	if err := mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: Context}); err != nil {
		return nil, ErrSignature
	}
	if st.Name != name {
		return nil, ErrWrongArtifact
	}
	h := sha512.New()
	// Read at most one byte more than the signed size.
	size, err := io.Copy(h, io.LimitReader(artifact, st.Size+1))
	if err != nil {
		return nil, err
	}
	if size != st.Size || !bytes.Equal(h.Sum(nil), st.SHA512) {
		return nil, ErrWrongArtifact
	}
	return st, nil
}

// parse splits a signature file strictly. Every field must be in its one
// canonical spelling, so the signed bytes are exactly what Sign writes.
func parse(file []byte) (*Statement, []byte, []byte, error) {
	if len(file) > MaxSignatureFile || !bytes.HasSuffix(file, []byte("\n")) {
		return nil, nil, nil, ErrMalformed
	}
	lines := strings.Split(string(file[:len(file)-1]), "\n")
	if len(lines) != 8 || lines[0] != magic {
		return nil, nil, nil, ErrMalformed
	}
	fields := make([]string, 0, 7)
	for i, key := range []string{"algorithm", "key", "name", "size", "sha512", "signed", "signature"} {
		value, ok := strings.CutPrefix(lines[i+1], key+": ")
		if !ok {
			return nil, nil, nil, ErrMalformed
		}
		fields = append(fields, value)
	}
	st := &Statement{KeyID: fields[1], Name: fields[2]}
	var err error
	st.Size, err = strconv.ParseInt(fields[3], 10, 64)
	if err != nil || st.Size < 0 {
		return nil, nil, nil, ErrMalformed
	}
	st.SHA512, err = hex.DecodeString(fields[4])
	if err != nil || len(st.SHA512) != sha512.Size {
		return nil, nil, nil, ErrMalformed
	}
	st.Signed, err = time.Parse(time.RFC3339, fields[5])
	if err != nil {
		return nil, nil, nil, ErrMalformed
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(fields[6])
	if err != nil || len(sig) != Params().SignatureSize() {
		return nil, nil, nil, ErrMalformed
	}
	keyID, err := hex.DecodeString(st.KeyID)
	if fields[0] != Algorithm || err != nil || len(keyID) != sha256.Size || !validName(st.Name) {
		return nil, nil, nil, ErrMalformed
	}
	st.KeyID = hex.EncodeToString(keyID)
	msg := file[:len(file)-len(lines[7])-1]
	// Reject any field whose spelling is not canonical (leading zeros,
	// upper-case hex, other time zones), so one statement has one encoding.
	if !bytes.Equal(st.encode(), msg) {
		return nil, nil, nil, ErrMalformed
	}
	return st, msg, sig, nil
}
