package apisig

import (
	"bytes"
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

var t0 = time.Unix(1_790_000_000, 0)

func setup(t *testing.T) (*mldsa.PrivateKey, *Verifier, Request) {
	t.Helper()
	sk, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	v := &Verifier{
		Audience: "https://payments.internal",
		Keys:     map[string]*mldsa.PublicKey{"svc-a-2026": sk.PublicKey()},
		Now:      func() time.Time { return t0 },
	}
	r := Request{KeyID: "svc-a-2026", Audience: "https://payments.internal", Timestamp: t0, Method: "POST", Path: "/v1/payments?dry_run=false", Body: []byte(`{"amount":1000}`)}
	return sk, v, r
}

func TestRoundTrip(t *testing.T) {
	sk, v, r := setup(t)
	sig, err := Sign(sk, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 3309 {
		t.Fatalf("unexpected ML-DSA-65 signature size %d", len(sig))
	}
	if err := v.Verify(r, sig); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsTampering(t *testing.T) {
	sk, v, r := setup(t)
	sig, _ := Sign(sk, r)

	cases := map[string]Request{}
	m := r
	m.Body = []byte(`{"amount":9000}`)
	cases["body"] = m
	m = r
	m.Path = "/v1/refunds?dry_run=false"
	cases["path"] = m
	m = r
	m.Method = "PUT"
	cases["method"] = m
	m = r
	m.Timestamp = t0.Add(time.Second)
	cases["timestamp"] = m
	for name, req := range cases {
		if err := v.Verify(req, sig); !errors.Is(err, ErrSignature) {
			t.Errorf("%s: tampering not detected: %v", name, err)
		}
	}

	bad := bytes.Clone(sig)
	bad[100] ^= 1
	if err := v.Verify(r, bad); !errors.Is(err, ErrSignature) {
		t.Error("tampered signature accepted")
	}
}

func TestRejectsOtherAudience(t *testing.T) {
	sk, v, r := setup(t)
	r.Audience = "https://ledger.internal"
	sig, _ := Sign(sk, r)
	// The verifier uses its own audience, whatever the request claims.
	if err := v.Verify(r, sig); !errors.Is(err, ErrSignature) {
		t.Fatal("request signed for another receiver accepted")
	}
	v.Audience = ""
	if err := v.Verify(r, sig); !errors.Is(err, ErrAudience) {
		t.Fatal("verifier without an audience accepted a request")
	}
}

func TestRejectsWrongContext(t *testing.T) {
	sk, v, r := setup(t)
	sig, _ := sk.Sign(nil, r.Message(), &mldsa.Options{Context: "some/other/purpose"})
	if err := v.Verify(r, sig); !errors.Is(err, ErrSignature) {
		t.Fatal("signature from another context accepted")
	}
}

func TestRejectsStaleAndUnknown(t *testing.T) {
	sk, v, r := setup(t)
	r.Timestamp = t0.Add(-6 * time.Minute)
	sig, _ := Sign(sk, r)
	if err := v.Verify(r, sig); !errors.Is(err, ErrStale) {
		t.Fatal("stale request accepted")
	}
	r.Timestamp, r.KeyID = t0, "unknown"
	sig, _ = Sign(sk, r)
	if err := v.Verify(r, sig); !errors.Is(err, ErrUnknownKey) {
		t.Fatal("unknown key accepted")
	}
}

func TestFieldBoundaries(t *testing.T) {
	a := Request{KeyID: "k", Timestamp: t0, Method: "GET", Path: "/ab", Body: []byte("c")}
	b := Request{KeyID: "k", Timestamp: t0, Method: "GET", Path: "/a", Body: []byte("bc")}
	if bytes.Equal(a.Message(), b.Message()) {
		t.Fatal("field boundaries are ambiguous")
	}
}

func TestSeedRoundTrip(t *testing.T) {
	sk, _, _ := setup(t)
	again, err := LoadPrivateKey(sk.Bytes())
	if err != nil || !again.Equal(sk) {
		t.Fatal("seed did not restore the same key")
	}
}

type vector struct {
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	Timestamp int64  `json:"timestamp"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Audience  string `json:"audience"`
	Body      string `json:"body"`
	Signature string `json:"signature"`
}

const vectorPath = "../testdata/vector.json"

// TestVector verifies the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		sk, _ := GenerateKey()
		r := Request{KeyID: "vector-key", Audience: "https://vectors.example", Timestamp: t0, Method: "POST", Path: "/v1/vectors", Body: []byte("cross-language test vector")}
		sig, _ := Sign(sk, r)
		v := vector{hex.EncodeToString(sk.Bytes()), hex.EncodeToString(sk.PublicKey().Bytes()), r.KeyID, r.Timestamp.Unix(), r.Method, r.Path, r.Audience, hex.EncodeToString(r.Body), hex.EncodeToString(sig)}
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
	seed, _ := hex.DecodeString(v.Seed)
	pkBytes, _ := hex.DecodeString(v.PublicKey)
	body, _ := hex.DecodeString(v.Body)
	sig, _ := hex.DecodeString(v.Signature)

	sk, err := LoadPrivateKey(seed)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), pkBytes) {
		t.Fatal("seed does not derive the vector's public key")
	}
	pk, _ := mldsa.NewPublicKey(Params(), pkBytes)
	ver := &Verifier{Audience: v.Audience, Keys: map[string]*mldsa.PublicKey{v.KeyID: pk}, Now: func() time.Time { return time.Unix(v.Timestamp, 0) }}
	r := Request{KeyID: v.KeyID, Timestamp: time.Unix(v.Timestamp, 0), Method: v.Method, Path: v.Path, Body: body}
	if err := ver.Verify(r, sig); err != nil {
		t.Fatal(err)
	}
}
