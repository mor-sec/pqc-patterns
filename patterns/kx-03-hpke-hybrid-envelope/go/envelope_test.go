package envelope

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

var info = []byte("pqc-patterns/kx-03/test")

func TestSuiteIDs(t *testing.T) {
	if kem.ID() != KEMID || kdf.ID() != KDFID || aead.ID() != AEADID {
		t.Fatalf("suite mismatch: %#x %#x %#x", kem.ID(), kdf.ID(), aead.ID())
	}
}

func TestRoundTrip(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("quarterly-report.csv data key")
	msg, err := Seal(priv.PublicKey(), info, []byte("export-17"), pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(priv, info, []byte("export-17"), msg)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}
	if len(priv.PublicKey().Bytes()) != 1216 {
		t.Fatalf("unexpected public key size %d", len(priv.PublicKey().Bytes()))
	}
}

func TestRejectsTampering(t *testing.T) {
	priv, _ := GenerateKey()
	msg, _ := Seal(priv.PublicKey(), info, nil, []byte("secret"))
	// Flip one byte in the header, the ML-KEM part, the X25519 part and the ciphertext.
	for _, i := range []int{0, 6, 6 + 1087, 6 + 1088, 6 + EncLen, len(msg) - 1} {
		bad := bytes.Clone(msg)
		bad[i] ^= 1
		if _, err := Open(priv, info, nil, bad); err == nil {
			t.Fatalf("flipping byte %d was not detected", i)
		}
	}
	if _, err := Open(priv, []byte("other/app"), nil, msg); err == nil {
		t.Fatal("wrong info accepted")
	}
	if _, err := Open(priv, info, []byte("x"), msg); err == nil {
		t.Fatal("wrong aad accepted")
	}
	other, _ := GenerateKey()
	if _, err := Open(other, info, nil, msg); err == nil {
		t.Fatal("wrong recipient key accepted")
	}
}

func TestKeySerialization(t *testing.T) {
	priv, _ := GenerateKey()
	b, err := priv.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadPrivateKey(b)
	if err != nil || !bytes.Equal(again.PublicKey().Bytes(), priv.PublicKey().Bytes()) {
		t.Fatal("private key did not round-trip")
	}
	if len(b) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(b))
	}
}

type vector struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Info       string `json:"info"`
	AAD        string `json:"aad"`
	Plaintext  string `json:"plaintext"`
	Message    string `json:"message"`
}

const vectorPath = "../testdata/vector.json"

// TestVector opens the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		priv, _ := GenerateKey()
		sk, _ := priv.Bytes()
		inf, aad, pt := []byte("pqc-patterns/kx-03/vector"), []byte("vector-aad"), []byte("cross-language test vector")
		msg, _ := Seal(priv.PublicKey(), inf, aad, pt)
		v := vector{hex.EncodeToString(sk), hex.EncodeToString(priv.PublicKey().Bytes()), hex.EncodeToString(inf), hex.EncodeToString(aad), hex.EncodeToString(pt), hex.EncodeToString(msg)}
		out, _ := json.MarshalIndent(v, "", "  ")
		os.MkdirAll("../testdata", 0o755)
		if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	priv, err := LoadPrivateKey(h(v.PrivateKey))
	if err != nil || !bytes.Equal(priv.PublicKey().Bytes(), h(v.PublicKey)) {
		t.Fatal("private key does not match the vector's public key")
	}
	got, err := Open(priv, h(v.Info), h(v.AAD), h(v.Message))
	if err != nil || !bytes.Equal(got, h(v.Plaintext)) {
		t.Fatalf("vector failed: %v", err)
	}
}
