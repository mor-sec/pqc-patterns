package kdf

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

var secret = bytes.Repeat([]byte{0x0b}, 32)

func TestSeparation(t *testing.T) {
	base, err := Derive(secret, nil, "billing-exports/aes-256-gcm/v1", []byte("tenant-42"), 32)
	if err != nil {
		t.Fatal(err)
	}
	others := map[string][]byte{}
	others["purpose"], _ = Derive(secret, nil, "billing-exports/hmac-sha256/v1", []byte("tenant-42"), 32)
	others["context"], _ = Derive(secret, nil, "billing-exports/aes-256-gcm/v1", []byte("tenant-43"), 32)
	others["salt"], _ = Derive(secret, []byte("salt"), "billing-exports/aes-256-gcm/v1", []byte("tenant-42"), 32)
	// Moving a byte between purpose and context must not give the same key.
	others["boundary"], _ = Derive(secret, nil, "billing-exports/aes-256-gcm/v1t", []byte("enant-42"), 32)
	for name, k := range others {
		if bytes.Equal(k, base) {
			t.Errorf("%s change gave the same key", name)
		}
	}
	short, _ := Derive(secret, nil, "billing-exports/aes-256-gcm/v1", []byte("tenant-42"), 16)
	if bytes.Equal(short, base[:16]) {
		t.Error("a 16-byte key is a prefix of the 32-byte key")
	}
}

func TestRejectsBadInput(t *testing.T) {
	for name, f := range map[string]func() error{
		"short secret": func() error { _, err := Derive(secret[:31], nil, "p", nil, 32); return err },
		"no purpose":   func() error { _, err := Derive(secret, nil, "", nil, 32); return err },
		"short key":    func() error { _, err := Derive(secret, nil, "p", nil, 8); return err },
		"long key":     func() error { _, err := Derive(secret, nil, "p", nil, MaxKeyLen+1); return err },
	} {
		if f() != ErrInput {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestHKDFMatchesRFC5869 checks the underlying HKDF against RFC 5869 test
// case 1, so a wrapper bug cannot hide behind a self-generated vector.
func TestHKDFMatchesRFC5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt, _ := hex.DecodeString("000102030405060708090a0b0c")
	info, _ := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	okm, _ := hkdf.Key(sha256.New, ikm, salt, string(info), 42)
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if hex.EncodeToString(okm) != want {
		t.Fatal("HKDF does not match RFC 5869 test case 1")
	}
}

type vector struct {
	Secret  string `json:"secret"`
	Salt    string `json:"salt"`
	Purpose string `json:"purpose"`
	Context string `json:"context"`
	KeyLen  int    `json:"key_len"`
	Info    string `json:"info"`
	Key     string `json:"key"`
}

const vectorPath = "../testdata/vector.json"

// TestVector checks the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		salt := []byte("pqc-patterns example salt")
		ctx := []byte("tenant-42")
		k, _ := Derive(secret, salt, "billing-exports/aes-256-gcm/v1", ctx, 32)
		v := vector{hex.EncodeToString(secret), hex.EncodeToString(salt), "billing-exports/aes-256-gcm/v1",
			hex.EncodeToString(ctx), 32, hex.EncodeToString(Info("billing-exports/aes-256-gcm/v1", ctx, 32)), hex.EncodeToString(k)}
		out, _ := json.MarshalIndent(v, "", "  ")
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
	s, _ := hex.DecodeString(v.Secret)
	salt, _ := hex.DecodeString(v.Salt)
	ctx, _ := hex.DecodeString(v.Context)
	k, err := Derive(s, salt, v.Purpose, ctx, v.KeyLen)
	if err != nil || hex.EncodeToString(k) != v.Key || hex.EncodeToString(Info(v.Purpose, ctx, v.KeyLen)) != v.Info {
		t.Fatal("vector mismatch")
	}
}
