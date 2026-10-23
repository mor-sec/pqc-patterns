// Package tokens implements pattern SESS-02: signed bearer tokens (JWTs)
// with ML-DSA-65, as specified for JOSE in RFC 9964.
//
// A token is a JWS in compact form:
//
//	BASE64URL(header) "." BASE64URL(claims) "." BASE64URL(ML-DSA signature)
//
// The verifier accepts exactly one algorithm and one token type, looks the
// key up by kid, checks the signature before reading any claims, and then
// requires the issuer, audience and lifetime it was configured with.
package tokens

import (
	"bytes"
	"crypto/mldsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

const (
	// Alg is the RFC 9964 JOSE algorithm name. Use ML-DSA-87 where CNSA 2.0
	// applies.
	Alg = "ML-DSA-65"
	// Type is the explicit token type (RFC 8725, section 3.11) for access
	// tokens (RFC 9068). Give each kind of token you issue its own type so
	// one can never be accepted as another.
	Type = "at+jwt"

	DefaultLeeway      = 30 * time.Second
	DefaultMaxLifetime = time.Hour
)

var (
	ErrMalformed  = errors.New("tokens: malformed token")
	ErrHeader     = errors.New("tokens: unexpected algorithm, type or header parameter")
	ErrUnknownKey = errors.New("tokens: unknown key ID")
	ErrSignature  = errors.New("tokens: invalid signature")
	ErrClaims     = errors.New("tokens: wrong issuer or audience")
	ErrExpired    = errors.New("tokens: expired, not yet valid, or lifetime too long")
)

// Params returns the ML-DSA parameter set that matches Alg.
func Params() mldsa.Parameters { return mldsa.MLDSA65() }

// RFC 9964, section 5: the ML-DSA context string for JOSE is empty. JWS gets
// its domain separation from the typ header instead.
var noContext = &mldsa.Options{Context: ""}

var b64 = base64.RawURLEncoding.Strict()

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Claims are the registered claims this pattern sets and checks. Audience is
// always a single string.
type Claims struct {
	Issuer    string `json:"iss"`
	Subject   string `json:"sub"`
	Audience  string `json:"aud"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	ID        string `json:"jti,omitempty"`
}

// Signer issues tokens under one key.
type Signer struct {
	KeyID string
	Key   *mldsa.PrivateKey
}

// Sign returns a compact JWS over c. Signing is hedged (randomised).
func (s *Signer) Sign(c Claims) (string, error) {
	h, err := json.Marshal(header{Alg: Alg, Typ: Type, Kid: s.KeyID})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sig, err := s.Key.Sign(nil, []byte(input), noContext)
	if err != nil {
		return "", err
	}
	return input + "." + b64.EncodeToString(sig), nil
}

// Verifier checks tokens against a set of trusted public keys. It is safe
// for concurrent use as long as its fields are not changed.
type Verifier struct {
	Issuer      string // required: the only issuer accepted
	Audience    string // required: this service's own identifier
	Keys        map[string]*mldsa.PublicKey
	Leeway      time.Duration // clock skew allowance; DefaultLeeway if zero
	MaxLifetime time.Duration // longest exp-iat accepted; DefaultMaxLifetime if zero
	Now         func() time.Time
}

// Verify checks a token and returns its claims. Application-specific claims
// can be read by decoding the payload again after Verify succeeds.
func (v *Verifier) Verify(token string) (Claims, error) {
	var c Claims
	if v.Issuer == "" || v.Audience == "" {
		return c, ErrClaims
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrMalformed
	}
	hb, err1 := b64.DecodeString(parts[0])
	pb, err2 := b64.DecodeString(parts[1])
	sig, err3 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return c, ErrMalformed
	}

	h, ok := parseHeader(hb)
	if !ok {
		return c, ErrMalformed
	}
	if h.Alg != Alg || h.Typ != Type {
		return c, ErrHeader
	}
	pk, known := v.Keys[h.Kid]
	if !known {
		return c, ErrUnknownKey
	}
	input := token[:len(parts[0])+1+len(parts[1])]
	if mldsa.Verify(pk, []byte(input), sig, noContext) != nil {
		return c, ErrSignature
	}

	if json.Unmarshal(pb, &c) != nil {
		return Claims{}, ErrMalformed
	}
	if c.Issuer != v.Issuer || c.Audience != v.Audience {
		return Claims{}, ErrClaims
	}
	now, leeway, maxLife := time.Now(), v.Leeway, v.MaxLifetime
	if v.Now != nil {
		now = v.Now()
	}
	if leeway == 0 {
		leeway = DefaultLeeway
	}
	if maxLife == 0 {
		maxLife = DefaultMaxLifetime
	}
	iat, exp := time.Unix(c.IssuedAt, 0), time.Unix(c.ExpiresAt, 0)
	if c.IssuedAt == 0 || c.ExpiresAt == 0 ||
		!now.Before(exp.Add(leeway)) || now.Add(leeway).Before(iat) || exp.Sub(iat) > maxLife {
		return Claims{}, ErrExpired
	}
	return c, nil
}

// parseHeader accepts exactly the string members alg, typ and kid, each at
// most once. crit, jku, x5u and embedded jwk keys are refused rather than
// ignored, and so are duplicate members, which encoding/json would otherwise
// resolve silently in favour of the last one.
func parseHeader(b []byte) (header, bool) {
	var h header
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return h, false
	}
	seen := map[string]bool{}
	for dec.More() {
		t, err := dec.Token()
		key, isString := t.(string)
		if err != nil || !isString || seen[key] {
			return h, false
		}
		seen[key] = true
		var val string
		if dec.Decode(&val) != nil {
			return h, false
		}
		switch key {
		case "alg":
			h.Alg = val
		case "typ":
			h.Typ = val
		case "kid":
			h.Kid = val
		default:
			return h, false
		}
	}
	if t, err := dec.Token(); err != nil || t != json.Delim('}') {
		return h, false
	}
	if _, err := dec.Token(); err != io.EOF {
		return h, false
	}
	return h, true
}
