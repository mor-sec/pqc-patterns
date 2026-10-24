// Package digest implements pattern HASH-01: self-describing content
// digests and full-length HMAC tags.
//
// Digests use the Subresource Integrity format, "<alg>-<base64>", such as
// "sha384-ywB1P0Wj...". The algorithm travels with the value, so a verifier
// can raise its minimum later without changing the format, and a stored
// digest never has to be guessed at. The default is SHA-384: it meets
// CNSA 2.0, is not open to length extension, and runs at SHA-512 speed on
// 64-bit hardware.
//
// MACs are HMAC-SHA-384 with a key of at least 32 bytes, compared in
// constant time and never truncated. Derive one MAC key per purpose with
// pattern HASH-02 rather than reusing a key across purposes.
package digest

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
	"io"
	"strings"
)

// Algorithm names, as used in Subresource Integrity.
const (
	SHA256 = "sha256"
	SHA384 = "sha384"
	SHA512 = "sha512"
)

// Default is the algorithm Sum uses.
const Default = SHA384

// Policy is the set of algorithms a verifier accepts.
type Policy map[string]bool

var (
	// Strong accepts SHA-384 and SHA-512 only. Use it for new data.
	Strong = Policy{SHA384: true, SHA512: true}
	// Compatible also accepts SHA-256, for digests written by older
	// systems. SHA-256 is not broken; it is below the CNSA 2.0 bar.
	Compatible = Policy{SHA256: true, SHA384: true, SHA512: true}
)

const (
	// MinKeyLen is the shortest HMAC key accepted.
	MinKeyLen = 32
	// TagLen is the length of an HMAC-SHA-384 tag. Shorter tags are refused.
	TagLen = sha512.Size384
)

var (
	ErrFormat    = errors.New("digest: malformed digest")
	ErrAlgorithm = errors.New("digest: algorithm not allowed by policy")
	ErrMismatch  = errors.New("digest: does not match")
	ErrKey       = errors.New("digest: HMAC key shorter than 32 bytes")
)

func newHash(alg string) func() hash.Hash {
	switch alg {
	case SHA256:
		return sha256.New
	case SHA384:
		return sha512.New384
	case SHA512:
		return sha512.New
	}
	return nil
}

func format(alg string, sum []byte) string {
	return alg + "-" + base64.StdEncoding.EncodeToString(sum)
}

// Sum returns the SHA-384 digest of data in "sha384-<base64>" form.
func Sum(data []byte) string {
	s := sha512.Sum384(data)
	return format(Default, s[:])
}

// SumReader is Sum for data that does not fit in memory, such as a file.
func SumReader(r io.Reader) (string, error) {
	h := sha512.New384()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return format(Default, h.Sum(nil)), nil
}

// Check returns nil if integrity is a well-formed digest of data under an
// algorithm that policy allows. MD5 and SHA-1 are never accepted.
func Check(integrity string, data []byte, policy Policy) error {
	alg, want, err := parse(integrity, policy)
	if err != nil {
		return err
	}
	h := newHash(alg)()
	h.Write(data)
	if subtle.ConstantTimeCompare(h.Sum(nil), want) != 1 {
		return ErrMismatch
	}
	return nil
}

func parse(integrity string, policy Policy) (string, []byte, error) {
	alg, b64, ok := strings.Cut(integrity, "-")
	if !ok {
		return "", nil, ErrFormat
	}
	newH := newHash(alg)
	if newH == nil || !policy[alg] {
		return "", nil, ErrAlgorithm
	}
	sum, err := base64.StdEncoding.Strict().DecodeString(b64)
	// Re-encoding catches non-canonical forms, so each digest has one spelling.
	if err != nil || len(sum) != newH().Size() || base64.StdEncoding.EncodeToString(sum) != b64 {
		return "", nil, ErrFormat
	}
	return alg, sum, nil
}

// Tag returns the HMAC-SHA-384 of msg under key.
func Tag(key, msg []byte) ([]byte, error) {
	if len(key) < MinKeyLen {
		return nil, ErrKey
	}
	m := hmac.New(sha512.New384, key)
	m.Write(msg)
	return m.Sum(nil), nil
}

// Verify checks tag against msg in constant time. A tag of any length other
// than TagLen is refused, so a truncated tag cannot be accepted.
func Verify(key, msg, tag []byte) error {
	want, err := Tag(key, msg)
	if err != nil {
		return err
	}
	if len(tag) != TagLen || !hmac.Equal(want, tag) {
		return ErrMismatch
	}
	return nil
}
