package artifacts

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func newSigner(t *testing.T) *Signer {
	t.Helper()
	sk, err := mldsa.GenerateKey(Params())
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Key: sk, Now: time.Now}
}

func sign(t *testing.T, s *Signer, name string, artifact []byte) []byte {
	t.Helper()
	sig, err := s.Sign(name, bytes.NewReader(artifact))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

const name = "myapp-1.4.2-linux-amd64.tar.gz"

func TestSignAndVerify(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	for _, n := range []int{0, 1, 100_000} {
		art := pattern(n)
		sig := sign(t, s, name, art)
		st, err := v.Verify(sig, name, bytes.NewReader(art))
		if err != nil || st.Size != int64(n) || st.KeyID != KeyID(s.Key.PublicKey()) {
			t.Fatalf("size %d: %v", n, err)
		}
	}
}

func TestRejectsModifiedArtifact(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	art := pattern(1000)
	sig := sign(t, s, name, art)
	flipped := bytes.Clone(art)
	flipped[500] ^= 1
	for _, bad := range [][]byte{flipped, art[:999], append(bytes.Clone(art), 0), nil} {
		if _, err := v.Verify(sig, name, bytes.NewReader(bad)); !errors.Is(err, ErrWrongArtifact) {
			t.Fatalf("modified artifact (%d bytes) accepted: %v", len(bad), err)
		}
	}
}

func TestRejectsWrongName(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	art := pattern(10)
	sig := sign(t, s, "myapp-1.4.1-linux-amd64.tar.gz", art)
	if _, err := v.Verify(sig, name, bytes.NewReader(art)); !errors.Is(err, ErrWrongArtifact) {
		t.Fatal("signature for an older release accepted under the new name")
	}
	if _, err := s.Sign("has space", bytes.NewReader(art)); err == nil {
		t.Fatal("name with a space accepted")
	}
	if _, err := s.Sign("", bytes.NewReader(art)); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestRejectsUntrustedKey(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(newSigner(t).Key.PublicKey())
	art := pattern(10)
	if _, err := v.Verify(sign(t, s, name, art), name, bytes.NewReader(art)); !errors.Is(err, ErrUnknownKey) {
		t.Fatal("signature from an untrusted key accepted")
	}
}

func TestRotation(t *testing.T) {
	old, fresh := newSigner(t), newSigner(t)
	v := NewVerifier(old.Key.PublicKey(), fresh.Key.PublicKey())
	art := pattern(10)
	for _, s := range []*Signer{old, fresh} {
		if _, err := v.Verify(sign(t, s, name, art), name, bytes.NewReader(art)); err != nil {
			t.Fatal(err)
		}
	}
}

// resign replaces the statement in sig with edit(statement) and signs it
// again with the given context, producing a well-formed file.
func resign(t *testing.T, s *Signer, sig []byte, edit func(string) string, context string) []byte {
	t.Helper()
	text := string(sig)
	msg := edit(text[:strings.Index(text, "signature: ")])
	raw, err := s.Key.Sign(nil, []byte(msg), &mldsa.Options{Context: context})
	if err != nil {
		t.Fatal(err)
	}
	return []byte(msg + "signature: " + base64.StdEncoding.EncodeToString(raw) + "\n")
}

func TestRejectsOtherContext(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	art := pattern(10)
	sig := resign(t, s, sign(t, s, name, art), func(m string) string { return m }, "pqc-patterns/sig-01/api-request/v2")
	if _, err := v.Verify(sig, name, bytes.NewReader(art)); !errors.Is(err, ErrSignature) {
		t.Fatal("signature under another context accepted")
	}
}

func TestRejectsEditedStatement(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	art := pattern(10)
	sig := sign(t, s, name, art)
	text := string(sig)
	for _, edit := range [][2]string{
		{"size: 10\n", "size: 11\n"},
		{"name: " + name, "name: other.tar.gz"},
		{"signed: 2", "signed: 1"},
	} {
		bad := strings.Replace(text, edit[0], edit[1], 1)
		if _, err := v.Verify([]byte(bad), name, bytes.NewReader(art)); !errors.Is(err, ErrSignature) {
			t.Fatalf("edit %q accepted: %v", edit[1], err)
		}
	}
}

// malformedVariants returns non-canonical or broken copies of a valid file.
func malformedVariants(sig []byte) []string {
	text := string(sig)
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	replaceLine := func(i int, s string) string {
		c := append([]string(nil), lines...)
		c[i] = s
		return strings.Join(c, "\n") + "\n"
	}
	return []string{
		strings.TrimSuffix(text, "\n"),
		strings.ReplaceAll(text, "\n", "\r\n"),
		text + "extra: line\n",
		"\n" + text,
		replaceLine(0, "pqc-patterns-signature-v2"),
		replaceLine(1, "algorithm: ML-DSA-65"),
		replaceLine(2, "key: "+strings.ToUpper(strings.TrimPrefix(lines[2], "key: "))),
		replaceLine(3, "name: "+strings.TrimPrefix(lines[3], "name: ")+" "),
		replaceLine(4, "size: 0"+strings.TrimPrefix(lines[4], "size: ")),
		replaceLine(4, "size: -1"),
		replaceLine(5, "sha512: "+strings.ToUpper(strings.TrimPrefix(lines[5], "sha512: "))),
		replaceLine(6, strings.Replace(lines[6], "Z", "+00:00", 1)),
		replaceLine(7, lines[7]+"="),
		replaceLine(7, "signature: "+strings.TrimPrefix(lines[7], "signature: ")[4:]),
		replaceLine(1, "algorithm:ML-DSA-87"),
		"",
	}
}

func TestRejectsMalformed(t *testing.T) {
	s := newSigner(t)
	v := NewVerifier(s.Key.PublicKey())
	art := pattern(10)
	for i, bad := range malformedVariants(sign(t, s, name, art)) {
		if _, err := v.Verify([]byte(bad), name, bytes.NewReader(art)); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed variant %d accepted: %v", i, err)
		}
	}
	if _, err := v.Verify(bytes.Repeat([]byte("a"), MaxSignatureFile+1), name, bytes.NewReader(art)); !errors.Is(err, ErrMalformed) {
		t.Fatal("oversized file accepted")
	}
}

type vector struct {
	Seed           string   `json:"seed"`
	PublicKey      string   `json:"public_key"`
	KeyID          string   `json:"key_id"`
	Name           string   `json:"name"`
	ArtifactLength int      `json:"artifact_length"`
	Signed         string   `json:"signed"`
	SignatureFile  string   `json:"signature_file"`
	Malformed      []string `json:"malformed_signature_files"`
}

// TestVector checks the shared cross-language vector: the artifact is
// pattern(ArtifactLength). Regenerate it with PQC_WRITE_VECTORS=1 go test ./...
func TestVector(t *testing.T) {
	path := "../testdata/vector.json"
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		seed := make([]byte, 32)
		for i := range seed {
			seed[i] = byte(i)
		}
		s, err := NewSigner(seed)
		if err != nil {
			t.Fatal(err)
		}
		signed := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
		s.Now = func() time.Time { return signed }
		sig := sign(t, s, name, pattern(1000))
		v := vector{
			Seed:           hex.EncodeToString(seed),
			PublicKey:      hex.EncodeToString(s.Key.PublicKey().Bytes()),
			KeyID:          KeyID(s.Key.PublicKey()),
			Name:           name,
			ArtifactLength: 1000,
			Signed:         signed.Format(time.RFC3339),
			SignatureFile:  string(sig),
			Malformed:      malformedVariants(sig),
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(v.Seed)
	s, err := NewSigner(seed)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(s.Key.PublicKey().Bytes()) != v.PublicKey || KeyID(s.Key.PublicKey()) != v.KeyID {
		t.Fatal("public key or key ID mismatch")
	}
	// Our statement for the same inputs must be byte-identical to the signed part.
	signed, _ := time.Parse(time.RFC3339, v.Signed)
	s.Now = func() time.Time { return signed }
	mine := sign(t, s, v.Name, pattern(v.ArtifactLength))
	if cut := strings.Index(v.SignatureFile, "signature: "); string(mine[:cut]) != v.SignatureFile[:cut] {
		t.Fatal("statement encoding differs from the vector")
	}
	verifier := NewVerifier(s.Key.PublicKey())
	if _, err := verifier.Verify([]byte(v.SignatureFile), v.Name, bytes.NewReader(pattern(v.ArtifactLength))); err != nil {
		t.Fatalf("vector signature rejected: %v", err)
	}
	for i, bad := range v.Malformed {
		if _, err := verifier.Verify([]byte(bad), v.Name, bytes.NewReader(pattern(v.ArtifactLength))); !errors.Is(err, ErrMalformed) {
			t.Fatalf("malformed vector %d accepted: %v", i, err)
		}
	}
}
