package tokens

import (
	"bytes"
	"crypto/mldsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

var t0 = time.Unix(1_790_000_000, 0)

const (
	iss = "https://auth.internal"
	aud = "https://payments.internal"
)

func setup(t *testing.T) (*Signer, *Verifier, Claims) {
	t.Helper()
	sk, err := mldsa.GenerateKey(Params())
	if err != nil {
		t.Fatal(err)
	}
	s := &Signer{KeyID: "auth-2026-10", Key: sk}
	v := &Verifier{
		Issuer:   iss,
		Audience: aud,
		Keys:     map[string]*mldsa.PublicKey{"auth-2026-10": sk.PublicKey()},
		Now:      func() time.Time { return t0 },
	}
	c := Claims{Issuer: iss, Subject: "svc-billing", Audience: aud, IssuedAt: t0.Unix(), ExpiresAt: t0.Add(15 * time.Minute).Unix()}
	return s, v, c
}

// forge builds a token from raw header and claims JSON, signed by s.
func forge(t *testing.T, s *Signer, header, claims string, ctx string) string {
	t.Helper()
	input := b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString([]byte(claims))
	sig, err := s.Key.Sign(nil, []byte(input), &mldsa.Options{Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64.EncodeToString(sig)
}

func TestRoundTrip(t *testing.T) {
	s, v, c := setup(t)
	tok, err := s.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.Verify(tok)
	if err != nil || got != c {
		t.Fatalf("got %+v, %v", got, err)
	}
	t.Logf("token is %d bytes", len(tok))
}

func TestRejectsTampering(t *testing.T) {
	s, v, c := setup(t)
	tok, _ := s.Sign(c)
	parts := strings.Split(tok, ".")
	c.Subject = "svc-admin"
	evil, _ := json.Marshal(c)
	forged := parts[0] + "." + b64.EncodeToString(evil) + "." + parts[2]
	if _, err := v.Verify(forged); !errors.Is(err, ErrSignature) {
		t.Fatalf("tampered claims: %v", err)
	}
}

func TestRejectsHeaders(t *testing.T) {
	s, v, c := setup(t)
	claims, _ := json.Marshal(c)
	cases := map[string]struct {
		header string
		want   error
	}{
		"alg none":    {`{"alg":"none","typ":"at+jwt","kid":"auth-2026-10"}`, ErrHeader},
		"alg ES256":   {`{"alg":"ES256","typ":"at+jwt","kid":"auth-2026-10"}`, ErrHeader},
		"other type":  {`{"alg":"ML-DSA-65","typ":"id+jwt","kid":"auth-2026-10"}`, ErrHeader},
		"no type":     {`{"alg":"ML-DSA-65","kid":"auth-2026-10"}`, ErrHeader},
		"jku":         {`{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10","jku":"https://evil.example"}`, ErrMalformed},
		"crit":        {`{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10","crit":["exp"]}`, ErrMalformed},
		"duplicate":   {`{"alg":"none","alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10"}`, ErrMalformed},
		"trailing":    {`{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10"}{}`, ErrMalformed},
		"unknown kid": {`{"alg":"ML-DSA-65","typ":"at+jwt","kid":"other"}`, ErrUnknownKey},
	}
	for name, tc := range cases {
		if _, err := v.Verify(forge(t, s, tc.header, string(claims), "")); !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", name, err, tc.want)
		}
	}
}

func TestRejectsNonEmptyContext(t *testing.T) {
	s, v, c := setup(t)
	claims, _ := json.Marshal(c)
	tok := forge(t, s, `{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10"}`, string(claims), "x")
	if _, err := v.Verify(tok); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature with a context string accepted: %v", err)
	}
}

func TestRejectsOtherKey(t *testing.T) {
	s, v, c := setup(t)
	other, _ := mldsa.GenerateKey(Params())
	s.Key = other
	tok, _ := s.Sign(c)
	if _, err := v.Verify(tok); !errors.Is(err, ErrSignature) {
		t.Fatalf("signature from another key accepted: %v", err)
	}
}

func TestClaimChecks(t *testing.T) {
	s, v, base := setup(t)
	cases := map[string]func(*Claims){
		"issuer":       func(c *Claims) { c.Issuer = "https://evil.example" },
		"audience":     func(c *Claims) { c.Audience = "https://ledger.internal" },
		"expired":      func(c *Claims) { c.ExpiresAt = t0.Add(-time.Minute).Unix() },
		"issued later": func(c *Claims) { c.IssuedAt = t0.Add(time.Minute).Unix() },
		"too long":     func(c *Claims) { c.ExpiresAt = t0.Add(24 * time.Hour).Unix() },
		"no exp":       func(c *Claims) { c.ExpiresAt = 0 },
		"no iat":       func(c *Claims) { c.IssuedAt = 0 },
	}
	for name, mutate := range cases {
		c := base
		mutate(&c)
		tok, _ := s.Sign(c)
		_, err := v.Verify(tok)
		if !errors.Is(err, ErrClaims) && !errors.Is(err, ErrExpired) {
			t.Errorf("%s: accepted (%v)", name, err)
		}
	}
}

func TestMalformed(t *testing.T) {
	s, v, c := setup(t)
	tok, _ := s.Sign(c)
	for name, bad := range map[string]string{
		"two parts":  tok[:strings.LastIndex(tok, ".")],
		"four parts": tok + ".x",
		"padding":    tok + "=",
		"empty":      "",
	} {
		if _, err := v.Verify(bad); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	v.Audience = ""
	if _, err := v.Verify(tok); err == nil {
		t.Error("verifier without an audience accepted a token")
	}
}

type vector struct {
	Seed      string `json:"seed"`
	PublicKey string `json:"public_key"`
	KeyID     string `json:"kid"`
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Now       int64  `json:"now"`
	Token     string `json:"token"`
	Subject   string `json:"expected_sub"`
}

const vectorPath = "../testdata/vector.json"

// TestVector verifies the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		s, _, c := setup(t)
		s.KeyID = "vector-key"
		tok, _ := s.Sign(c)
		v := vector{hex.EncodeToString(s.Key.Bytes()), hex.EncodeToString(s.Key.PublicKey().Bytes()), s.KeyID, iss, aud, t0.Unix(), tok, c.Subject}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vec vector
	if err := json.Unmarshal(raw, &vec); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vec.Seed)
	pkBytes, _ := hex.DecodeString(vec.PublicKey)
	sk, err := mldsa.NewPrivateKey(Params(), seed)
	if err != nil || !bytes.Equal(sk.PublicKey().Bytes(), pkBytes) {
		t.Fatal("seed does not derive the vector's public key")
	}
	pk, _ := mldsa.NewPublicKey(Params(), pkBytes)
	v := &Verifier{Issuer: vec.Issuer, Audience: vec.Audience, Keys: map[string]*mldsa.PublicKey{vec.KeyID: pk}, Now: func() time.Time { return time.Unix(vec.Now, 0) }}
	c, err := v.Verify(vec.Token)
	if err != nil || c.Subject != vec.Subject {
		t.Fatalf("vector: %+v, %v", c, err)
	}
}
