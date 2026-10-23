// Package apisig implements pattern SIG-01: signing API requests with
// ML-DSA-65 (FIPS 204) so a receiver can prove who sent a request, that it
// was meant for that receiver, that it was not altered, and that it is recent.
// Replay inside the freshness window is not detected; see Verifier.Verify.
//
// The signed message is a length-prefixed encoding of
//
//	key ID, audience, timestamp (Unix seconds, decimal), HTTP method, path, body
//
// signed under the ML-DSA context string Context, so these signatures can
// never be confused with signatures the same key makes for anything else.
package apisig

import (
	"crypto/mldsa"
	"encoding/binary"
	"errors"
	"math"
	"strconv"
	"time"
)

// Context domain-separates API request signatures (FIPS 204, section 5.2).
const Context = "pqc-patterns/sig-01/api-request/v2"

// DefaultMaxSkew bounds how old or how far in the future a request may be.
const DefaultMaxSkew = 5 * time.Minute

var (
	ErrUnknownKey = errors.New("apisig: unknown key ID")
	ErrStale      = errors.New("apisig: timestamp outside allowed window")
	ErrSignature  = errors.New("apisig: invalid signature")
	ErrAudience   = errors.New("apisig: verifier has no Audience configured")
)

// Params returns the parameter set for general-purpose signing. Use
// mldsa.MLDSA87() where CNSA 2.0 applies.
func Params() mldsa.Parameters { return mldsa.MLDSA65() }

// Request is the part of an HTTP request that is covered by the signature.
type Request struct {
	KeyID string
	// Audience names the receiver the request is for, such as
	// "https://payments.internal". It stops a request signed for one
	// receiver being replayed to another that trusts the same key. It is
	// signed but not sent: the receiver supplies its own.
	Audience  string
	Timestamp time.Time
	Method    string
	Path      string // include the query string
	Body      []byte
}

// Message returns the exact bytes that are signed. It panics if a field is
// 4 GiB or longer, rather than truncating its length prefix.
func (r Request) Message() []byte {
	var out []byte
	for _, f := range [][]byte{
		[]byte(r.KeyID),
		[]byte(r.Audience),
		[]byte(strconv.FormatInt(r.Timestamp.Unix(), 10)),
		[]byte(r.Method),
		[]byte(r.Path),
		r.Body,
	} {
		if len(f) > math.MaxUint32 {
			panic("apisig: request field too long")
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return out
}

// GenerateKey creates a new signing key. Store only sk.Bytes(), the 32-byte
// FIPS 204 seed, in your secret store or KMS.
func GenerateKey() (*mldsa.PrivateKey, error) { return mldsa.GenerateKey(Params()) }

// LoadPrivateKey restores a key from its 32-byte seed.
func LoadPrivateKey(seed []byte) (*mldsa.PrivateKey, error) {
	return mldsa.NewPrivateKey(Params(), seed)
}

// Sign signs r with sk. Signing is hedged (randomised), so two signatures
// over the same request differ; both verify.
func Sign(sk *mldsa.PrivateKey, r Request) ([]byte, error) {
	return sk.Sign(nil, r.Message(), &mldsa.Options{Context: Context})
}

// Verifier checks signed requests against a set of trusted public keys.
// It is safe for concurrent use as long as its fields are not changed.
type Verifier struct {
	// Audience is this receiver's own identity. It is required, and it
	// replaces whatever Audience the request carries.
	Audience string
	Keys     map[string]*mldsa.PublicKey
	MaxSkew  time.Duration
	Now      func() time.Time
}

// Verify checks the key ID, the timestamp window and then the signature over
// r with v.Audience in place of r.Audience. It does not detect a replay to
// this receiver inside the window; pair it with a nonce or idempotency-key
// cache if requests are not idempotent.
func (v *Verifier) Verify(r Request, sig []byte) error {
	if v.Audience == "" {
		return ErrAudience
	}
	r.Audience = v.Audience
	pk, ok := v.Keys[r.KeyID]
	if !ok {
		return ErrUnknownKey
	}
	now, skew := time.Now(), v.MaxSkew
	if v.Now != nil {
		now = v.Now()
	}
	if skew == 0 {
		skew = DefaultMaxSkew
	}
	if d := now.Sub(r.Timestamp); d > skew || d < -skew {
		return ErrStale
	}
	if err := mldsa.Verify(pk, r.Message(), sig, &mldsa.Options{Context: Context}); err != nil {
		return ErrSignature
	}
	return nil
}
