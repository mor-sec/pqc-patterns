// Package envelope implements pattern KX-03: encrypting a message or data key
// to a recipient's public key with HPKE (RFC 9180) using the hybrid
// post-quantum KEM ML-KEM-768 + X25519 (X-Wing, draft-ietf-hpke-pq).
//
// Ciphersuite: KEM 0x647a (MLKEM768-X25519), KDF 0x0001 (HKDF-SHA256),
// AEAD 0x0002 (AES-256-GCM). Wire format:
//
//	suite (6 bytes: KEM ID || KDF ID || AEAD ID, big-endian) || enc (1120 bytes) || ciphertext || tag
//
// The suite header lets readers reject or migrate old formats (pattern
// AGI-01); HPKE itself binds the suite into the key schedule.
package envelope

import (
	"bytes"
	"crypto/hpke"
	"encoding/binary"
	"errors"
)

const (
	KEMID  uint16 = 0x647a // MLKEM768-X25519 (X-Wing)
	KDFID  uint16 = 0x0001 // HKDF-SHA256
	AEADID uint16 = 0x0002 // AES-256-GCM
	EncLen        = 1120   // ML-KEM-768 ciphertext (1088) || X25519 share (32)
)

var ErrOpen = errors.New("envelope: decryption failed")

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

func suite() []byte {
	var s []byte
	s = binary.BigEndian.AppendUint16(s, KEMID)
	s = binary.BigEndian.AppendUint16(s, KDFID)
	return binary.BigEndian.AppendUint16(s, AEADID)
}

// GenerateKey creates a recipient key pair. Store priv.Bytes() (a 32-byte
// seed) in a secret store; publish PublicKey().Bytes() (1216 bytes).
func GenerateKey() (hpke.PrivateKey, error) { return kem.GenerateKey() }

func LoadPrivateKey(b []byte) (hpke.PrivateKey, error) { return kem.NewPrivateKey(b) }
func LoadPublicKey(b []byte) (hpke.PublicKey, error)   { return kem.NewPublicKey(b) }

// Seal encrypts plaintext to pub. info names the application and purpose
// (for example "billing-exports/v1") and must match on Open. aad is
// authenticated but not encrypted, for example a record ID.
func Seal(pub hpke.PublicKey, info, aad, plaintext []byte) ([]byte, error) {
	enc, sender, err := hpke.NewSender(pub, kdf, aead, info)
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, err
	}
	out := append(suite(), enc...)
	return append(out, ct...), nil
}

// Open decrypts a message produced by Seal in any language in this repo.
func Open(priv hpke.PrivateKey, info, aad, msg []byte) ([]byte, error) {
	if len(msg) < 6+EncLen || !bytes.Equal(msg[:6], suite()) {
		return nil, ErrOpen
	}
	enc, ct := msg[6:6+EncLen], msg[6+EncLen:]
	r, err := hpke.NewRecipient(enc, priv, kdf, aead, info)
	if err != nil {
		return nil, ErrOpen
	}
	pt, err := r.Open(aad, ct)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}
