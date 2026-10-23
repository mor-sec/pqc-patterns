// Package aead implements pattern SYM-01: authenticated encryption at rest
// with AES-256-GCM, versioned key IDs for rotation, and caller-bound
// associated data.
//
// Wire format (all languages in this repo produce and accept the same bytes):
//
//	version (1 byte, 0x01) || key ID (4 bytes, big-endian) || nonce (12 bytes) || ciphertext || tag (16 bytes)
//
// The 5-byte header and the caller's associated data are both authenticated.
package aead

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sync"
)

const (
	Version   byte = 0x01
	KeySize        = 32 // AES-256: 128-bit security even against Grover's algorithm.
	NonceSize      = 12
	TagSize        = 16
	headerLen      = 1 + 4
	overhead       = headerLen + NonceSize + TagSize
)

// ErrDecrypt is returned for every authentication or format failure, so
// callers cannot learn why a ciphertext was rejected.
var ErrDecrypt = errors.New("aead: decryption failed")

// Keyring holds the active key used for new encryptions plus older keys that
// may still be needed to decrypt existing data during rotation. It is safe
// for concurrent use, so keys can be added and rotated while serving traffic.
type Keyring struct {
	mu       sync.RWMutex
	activeID uint32
	keys     map[uint32]cipher.AEAD
}

// NewKeyring creates a keyring whose active key is (id, key).
func NewKeyring(id uint32, key []byte) (*Keyring, error) {
	k := &Keyring{keys: make(map[uint32]cipher.AEAD)}
	if err := k.Add(id, key); err != nil {
		return nil, err
	}
	k.activeID = id
	return k, nil
}

// Add registers a decrypt-only key. Call Rotate to make it the active key.
func (k *Keyring) Add(id uint32, key []byte) error {
	if len(key) != KeySize {
		return fmt.Errorf("aead: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, exists := k.keys[id]; exists {
		return fmt.Errorf("aead: key ID %d already present", id)
	}
	k.keys[id] = gcm
	return nil
}

// Rotate makes an already-added key the active key for new encryptions.
func (k *Keyring) Rotate(id uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if _, ok := k.keys[id]; !ok {
		return fmt.Errorf("aead: unknown key ID %d", id)
	}
	k.activeID = id
	return nil
}

// NewKey returns a fresh random 256-bit key. In production, generate and hold
// keys in a KMS or HSM instead (see pattern KEY-02).
func NewKey() []byte {
	key := make([]byte, KeySize)
	rand.Read(key) // crypto/rand.Read never returns an error since Go 1.24.
	return key
}

// Encrypt seals plaintext under the active key. associatedData binds the
// ciphertext to its context (for example a table name and row ID) so it
// cannot be swapped into another record.
//
// Nonces are random, so a single key must not encrypt more than 2^32
// messages. Rotate well before that.
func (k *Keyring) Encrypt(plaintext, associatedData []byte) ([]byte, error) {
	if uint64(len(associatedData)) > math.MaxUint32 {
		return nil, errors.New("aead: associated data too long")
	}
	k.mu.RLock()
	id := k.activeID
	gcm := k.keys[id]
	k.mu.RUnlock()
	out := make([]byte, headerLen+NonceSize, overhead+len(plaintext))
	out[0] = Version
	binary.BigEndian.PutUint32(out[1:headerLen], id)
	if _, err := rand.Read(out[headerLen:]); err != nil {
		return nil, err
	}
	header, nonce := out[:headerLen], out[headerLen:]
	return gcm.Seal(out, nonce, plaintext, aad(header, associatedData)), nil
}

// Decrypt verifies and opens a blob produced by Encrypt in any language.
func (k *Keyring) Decrypt(blob, associatedData []byte) ([]byte, error) {
	if len(blob) < overhead || blob[0] != Version || uint64(len(associatedData)) > math.MaxUint32 {
		return nil, ErrDecrypt
	}
	k.mu.RLock()
	gcm, ok := k.keys[binary.BigEndian.Uint32(blob[1:headerLen])]
	k.mu.RUnlock()
	if !ok {
		return nil, ErrDecrypt
	}
	header := blob[:headerLen]
	nonce := blob[headerLen : headerLen+NonceSize]
	pt, err := gcm.Open(nil, nonce, blob[headerLen+NonceSize:], aad(header, associatedData))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// aad authenticates the header and the caller's context together. The
// caller's data is length-prefixed so different splits cannot collide.
func aad(header, associatedData []byte) []byte {
	out := make([]byte, 0, len(header)+4+len(associatedData))
	out = append(out, header...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(associatedData)))
	return append(out, associatedData...)
}
