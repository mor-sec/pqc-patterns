package stream

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"testing"
)

const seg = SegmentSize

var sizes = []int{0, 1, seg - 1, seg, seg + 1, 3 * seg, 3*seg + 7}

// pattern returns n deterministic bytes, so test failures are reproducible.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

func seal(t *testing.T, key, pt, ad []byte) []byte {
	t.Helper()
	var ct bytes.Buffer
	if err := Encrypt(&ct, bytes.NewReader(pt), key, ad); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

func open(ct, key, ad []byte) ([]byte, error) {
	var pt bytes.Buffer
	err := Decrypt(&pt, bytes.NewReader(ct), key, ad)
	return pt.Bytes(), err
}

func TestRoundTrip(t *testing.T) {
	key := NewKey()
	ad := []byte("backups/2026-10-23.tar")
	for _, n := range sizes {
		pt := pattern(n)
		ct := seal(t, key, pt, ad)
		segments := max(1, (n+seg-1)/seg)
		if want := HeaderSize + n + segments*TagSize; len(ct) != want {
			t.Fatalf("size %d: ciphertext is %d bytes, want %d", n, len(ct), want)
		}
		got, err := open(ct, key, ad)
		if err != nil || !bytes.Equal(got, pt) {
			t.Fatalf("size %d: round trip failed: %v", n, err)
		}
	}
}

// oneByteReader returns at most one byte per Read, like a slow network peer.
type oneByteReader struct{ r io.Reader }

func (o oneByteReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return o.r.Read(p[:1])
}

func TestShortReads(t *testing.T) {
	key := NewKey()
	pt := pattern(2*seg + 3)
	var ct bytes.Buffer
	if err := Encrypt(&ct, oneByteReader{bytes.NewReader(pt)}, key, nil); err != nil {
		t.Fatal(err)
	}
	var got bytes.Buffer
	if err := Decrypt(&got, oneByteReader{&ct}, key, nil); err != nil || !bytes.Equal(got.Bytes(), pt) {
		t.Fatalf("round trip with short reads failed: %v", err)
	}
}

func TestRejectsTruncation(t *testing.T) {
	key := NewKey()
	for _, n := range []int{seg, 2 * seg, 2*seg + 5} {
		ct := seal(t, key, pattern(n), nil)
		// Drop the final segment, cut mid-segment, cut inside the header.
		finalLen := (n-1)%seg + 1 + TagSize
		for _, cut := range []int{finalLen, 1, seg + TagSize, len(ct) - HeaderSize + 1, len(ct)} {
			if cut > len(ct) {
				continue
			}
			if _, err := open(ct[:len(ct)-cut], key, nil); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("size %d: removing %d trailing bytes was not detected (%v)", n, cut, err)
			}
		}
	}
}

func TestRejectsAppendedData(t *testing.T) {
	key := NewKey()
	for _, n := range []int{0, 5, seg} {
		ct := seal(t, key, pattern(n), nil)
		for _, extra := range [][]byte{{0}, make([]byte, TagSize), make([]byte, seg+TagSize)} {
			if _, err := open(append(bytes.Clone(ct), extra...), key, nil); !errors.Is(err, ErrDecrypt) {
				t.Fatalf("size %d: %d appended bytes were not detected", n, len(extra))
			}
		}
	}
	// Two valid streams joined together are not one valid stream.
	a, b := seal(t, key, pattern(seg), nil), seal(t, key, pattern(seg), nil)
	if _, err := open(append(bytes.Clone(a), b[HeaderSize:]...), key, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatal("concatenated streams accepted")
	}
}

func TestRejectsReorderedSegments(t *testing.T) {
	key := NewKey()
	ct := seal(t, key, pattern(3*seg), nil)
	s := seg + TagSize
	swapped := bytes.Clone(ct)
	copy(swapped[HeaderSize:], ct[HeaderSize+s:HeaderSize+2*s])
	copy(swapped[HeaderSize+s:], ct[HeaderSize:HeaderSize+s])
	if _, err := open(swapped, key, nil); !errors.Is(err, ErrDecrypt) {
		t.Fatal("swapped segments accepted")
	}
}

func TestRejectsTampering(t *testing.T) {
	key := NewKey()
	ad := []byte("uploads/42")
	ct := seal(t, key, pattern(100), ad)
	for i := range ct {
		bad := bytes.Clone(ct)
		bad[i] ^= 0x01
		if _, err := open(bad, key, ad); !errors.Is(err, ErrDecrypt) {
			t.Fatalf("flipping byte %d was not detected", i)
		}
	}
	if _, err := open(ct, key, []byte("uploads/43")); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong associated data accepted")
	}
	if _, err := open(ct, NewKey(), ad); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong key accepted")
	}
	if _, err := open(nil, key, ad); !errors.Is(err, ErrDecrypt) {
		t.Fatal("empty input accepted")
	}
}

func TestRejectsShortKey(t *testing.T) {
	if err := Encrypt(io.Discard, bytes.NewReader(nil), make([]byte, 16), nil); err == nil {
		t.Fatal("AES-128 key accepted")
	}
}

func TestHeadersAreUnique(t *testing.T) {
	key := NewKey()
	seen := map[string]bool{}
	for range 1000 {
		h := string(seal(t, key, nil, nil)[:HeaderSize])
		if seen[h] {
			t.Fatal("header reused")
		}
		seen[h] = true
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestPassesThroughIOErrors(t *testing.T) {
	key := NewKey()
	ct := seal(t, key, []byte("x"), nil)
	if err := Decrypt(failingWriter{}, bytes.NewReader(ct), key, nil); err == nil || errors.Is(err, ErrDecrypt) {
		t.Fatalf("write error was hidden: %v", err)
	}
}

type vector struct {
	Key              string `json:"key"`
	AssociatedData   string `json:"associated_data"`
	Salt             string `json:"salt"`
	NoncePrefix      string `json:"nonce_prefix"`
	Plaintext        string `json:"plaintext"`
	Ciphertext       string `json:"ciphertext"`
	LargeLength      int    `json:"large_plaintext_length"`
	LargeCiphertextH string `json:"large_ciphertext_sha256"`
}

const largeLen = 2*seg + 100

func sealFixed(t *testing.T, v vector, pt []byte) []byte {
	t.Helper()
	key, _ := hex.DecodeString(v.Key)
	ad, _ := hex.DecodeString(v.AssociatedData)
	salt, _ := hex.DecodeString(v.Salt)
	prefix, _ := hex.DecodeString(v.NoncePrefix)
	var ct bytes.Buffer
	if err := encrypt(&ct, bytes.NewReader(pt), key, ad, salt, prefix); err != nil {
		t.Fatal(err)
	}
	return ct.Bytes()
}

// TestVector checks the shared cross-language vector. Regenerate it with
// PQC_WRITE_VECTORS=1 go test ./...
func TestVector(t *testing.T) {
	path := "../testdata/vector.json"
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		v := vector{
			Key:            hex.EncodeToString(NewKey()),
			AssociatedData: hex.EncodeToString([]byte("vectors/sym-03")),
			Plaintext:      hex.EncodeToString([]byte("cross-language streaming test vector")),
			LargeLength:    largeLen,
		}
		salt, prefix := make([]byte, SaltSize), make([]byte, PrefixSize)
		rand.Read(salt)
		rand.Read(prefix)
		v.Salt, v.NoncePrefix = hex.EncodeToString(salt), hex.EncodeToString(prefix)
		pt, _ := hex.DecodeString(v.Plaintext)
		v.Ciphertext = hex.EncodeToString(sealFixed(t, v, pt))
		h := sha256.Sum256(sealFixed(t, v, pattern(largeLen)))
		v.LargeCiphertextH = hex.EncodeToString(h[:])
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
	key, _ := hex.DecodeString(v.Key)
	ad, _ := hex.DecodeString(v.AssociatedData)
	pt, _ := hex.DecodeString(v.Plaintext)
	ct, _ := hex.DecodeString(v.Ciphertext)
	if got := sealFixed(t, v, pt); !bytes.Equal(got, ct) {
		t.Fatal("small vector: ciphertext mismatch")
	}
	if got, err := open(ct, key, ad); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("small vector: decrypt failed: %v", err)
	}
	large := sealFixed(t, v, pattern(v.LargeLength))
	if h := sha256.Sum256(large); hex.EncodeToString(h[:]) != v.LargeCiphertextH {
		t.Fatal("large vector: ciphertext hash mismatch")
	}
	if got, err := open(large, key, ad); err != nil || !bytes.Equal(got, pattern(v.LargeLength)) {
		t.Fatalf("large vector: decrypt failed: %v", err)
	}
}
