package aead

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	k, err := NewKeyring(1, NewKey())
	if err != nil {
		t.Fatal(err)
	}
	pt := []byte("card ending 4242")
	ad := []byte("customers/42/payment_method")
	blob, err := k.Encrypt(pt, ad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := k.Decrypt(blob, ad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}
}

func TestRejectsTampering(t *testing.T) {
	k, _ := NewKeyring(1, NewKey())
	ad := []byte("customers/42")
	blob, _ := k.Encrypt([]byte("secret"), ad)

	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		if _, err := k.Decrypt(bad, ad); err == nil {
			t.Fatalf("flipping byte %d was not detected", i)
		}
	}
	if _, err := k.Decrypt(blob, []byte("customers/43")); err == nil {
		t.Fatal("wrong associated data accepted")
	}
	if _, err := k.Decrypt(blob[:len(blob)-1], ad); err == nil {
		t.Fatal("truncated ciphertext accepted")
	}
}

func TestRotation(t *testing.T) {
	k, _ := NewKeyring(1, NewKey())
	old, _ := k.Encrypt([]byte("v1 data"), nil)

	if err := k.Add(2, NewKey()); err != nil {
		t.Fatal(err)
	}
	if err := k.Rotate(2); err != nil {
		t.Fatal(err)
	}
	fresh, _ := k.Encrypt([]byte("v2 data"), nil)
	if fresh[4] != 2 {
		t.Fatal("new data not written under the active key")
	}
	if _, err := k.Decrypt(old, nil); err != nil {
		t.Fatal("old data unreadable after rotation")
	}
}

func TestRejectsShortKey(t *testing.T) {
	if _, err := NewKeyring(1, make([]byte, 16)); err == nil {
		t.Fatal("AES-128 key accepted")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	k, _ := NewKeyring(1, NewKey())
	seen := map[string]bool{}
	for range 1000 {
		blob, _ := k.Encrypt([]byte("x"), nil)
		n := string(blob[5:17])
		if seen[n] {
			t.Fatal("nonce reused")
		}
		seen[n] = true
	}
}

type vector struct {
	KeyID          uint32 `json:"key_id"`
	Key            string `json:"key"`
	AssociatedData string `json:"associated_data"`
	Plaintext      string `json:"plaintext"`
	Blob           string `json:"blob"`
}

const vectorPath = "../testdata/vector.json"

// TestVector decrypts the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		key := NewKey()
		k, _ := NewKeyring(7, key)
		pt, ad := []byte("cross-language test vector"), []byte("vectors/sym-01")
		blob, _ := k.Encrypt(pt, ad)
		v := vector{7, hex.EncodeToString(key), hex.EncodeToString(ad), hex.EncodeToString(pt), hex.EncodeToString(blob)}
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
	key, _ := hex.DecodeString(v.Key)
	ad, _ := hex.DecodeString(v.AssociatedData)
	want, _ := hex.DecodeString(v.Plaintext)
	blob, _ := hex.DecodeString(v.Blob)
	k, _ := NewKeyring(v.KeyID, key)
	got, err := k.Decrypt(blob, ad)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("vector failed: %v", err)
	}
}
