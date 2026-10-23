// Package kdf implements pattern HASH-02: deriving separate, purpose-bound
// keys from one secret with HKDF-SHA-256 (RFC 5869).
//
// The HKDF info input is a length-prefixed encoding of
//
//	"pqc-patterns/hash-02/v1", purpose, context, output length (u16)
//
// so two purposes, two contexts or two output lengths never share key
// material. Without the length, a 16-byte key would be the first half of
// the 32-byte key for the same purpose.
package kdf

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
)

const (
	label = "pqc-patterns/hash-02/v1"
	// MinSecretLen is the smallest input secret accepted: 256 bits.
	MinSecretLen = 32
	// MaxKeyLen is HKDF-SHA-256's output limit, 255 * 32 bytes.
	MaxKeyLen = 255 * sha256.Size
)

var ErrInput = errors.New("kdf: secret shorter than 32 bytes, empty purpose, or bad key length")

// Info returns the exact HKDF info bytes for purpose, context and keyLen.
func Info(purpose string, context []byte, keyLen int) []byte {
	var out []byte
	for _, f := range [][]byte{[]byte(label), []byte(purpose), context} {
		if len(f) > math.MaxUint32 {
			panic("kdf: info field too long")
		}
		out = binary.BigEndian.AppendUint32(out, uint32(len(f)))
		out = append(out, f...)
	}
	return binary.BigEndian.AppendUint16(out, uint16(keyLen))
}

// Derive returns a keyLen-byte key for purpose, such as
// "billing-exports/aes-256-gcm/v1". context binds the key to an instance,
// such as a tenant ID, and may be nil. salt may be nil when secret is
// already uniformly random (a KMS data key or an ML-KEM shared secret);
// otherwise use a fixed, non-secret, random value per application.
func Derive(secret, salt []byte, purpose string, context []byte, keyLen int) ([]byte, error) {
	if len(secret) < MinSecretLen || purpose == "" || keyLen < 16 || keyLen > MaxKeyLen {
		return nil, ErrInput
	}
	return hkdf.Key(sha256.New, secret, salt, string(Info(purpose, context, keyLen)), keyLen)
}
