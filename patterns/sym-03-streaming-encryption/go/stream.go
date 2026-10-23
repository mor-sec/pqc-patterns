// Package stream implements pattern SYM-03: encrypting files and streams of
// any size with AES-256-GCM in fixed-size authenticated segments, so memory
// use stays constant and truncation, reordering and appending are detected.
//
// Wire format (all languages in this repo produce and accept the same bytes):
//
//	header:   version (1 byte, 0x01) || salt (32 bytes) || nonce prefix (7 bytes)
//	segments: ciphertext || tag (16 bytes), repeated
//
// Each stream gets its own AES-256 key:
//
//	HKDF-SHA-256(ikm = master key, salt = salt, info = "pqc-patterns/sym-03/v1" || associated data)
//
// Segment i (counting from 0) uses the 12-byte nonce
//
//	nonce prefix (7 bytes) || i (4 bytes, big-endian) || last (1 byte, 0x01 on the final segment, else 0x00)
//
// Every segment holds exactly SegmentSize bytes of plaintext except the last,
// which holds 0 to SegmentSize bytes. An empty input is one empty final
// segment. Because the final segment is marked inside its nonce, dropping
// trailing segments, reordering them or appending data all fail
// authentication.
package stream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

const (
	Version     byte = 0x01
	KeySize          = 32 // AES-256: 128-bit security even against Grover's algorithm.
	SegmentSize      = 64 * 1024
	SaltSize         = 32
	PrefixSize       = 7
	HeaderSize       = 1 + SaltSize + PrefixSize
	TagSize          = 16
	label            = "pqc-patterns/sym-03/v1"
)

// ErrDecrypt is returned for every authentication or format failure, so
// callers cannot learn why a stream was rejected. Read and write errors from
// src and dst are returned unchanged.
var ErrDecrypt = errors.New("stream: decryption failed")

// ErrTooLong is returned when a stream would need more than 2^32 segments
// (256 TiB). Split such data into several streams.
var ErrTooLong = errors.New("stream: input exceeds 2^32 segments")

// NewKey returns a fresh random 256-bit master key. In production, generate
// and hold keys in a KMS or HSM instead (see pattern KEY-02).
func NewKey() []byte {
	key := make([]byte, KeySize)
	rand.Read(key) // crypto/rand.Read never returns an error since Go 1.24.
	return key
}

// Encrypt reads src to EOF and writes the encrypted stream to dst, holding at
// most one segment in memory. associatedData binds the stream to its context
// (for example a bucket and object name) so it cannot be swapped for another.
func Encrypt(dst io.Writer, src io.Reader, key, associatedData []byte) error {
	var salt [SaltSize]byte
	var prefix [PrefixSize]byte
	rand.Read(salt[:])
	rand.Read(prefix[:])
	return encrypt(dst, src, key, associatedData, salt[:], prefix[:])
}

func encrypt(dst io.Writer, src io.Reader, key, associatedData, salt, prefix []byte) error {
	gcm, err := streamCipher(key, salt, associatedData)
	if err != nil {
		return err
	}
	header := make([]byte, 0, HeaderSize)
	header = append(header, Version)
	header = append(append(header, salt...), prefix...)
	if _, err := dst.Write(header); err != nil {
		return err
	}

	// Reading one byte past a full segment tells us whether more follow.
	buf := make([]byte, SegmentSize+1)
	out := make([]byte, 0, SegmentSize+TagSize)
	n := 0
	for i := uint64(0); ; i++ {
		m, err := io.ReadFull(src, buf[n:])
		n += m
		last := false
		switch err {
		case nil:
		case io.EOF, io.ErrUnexpectedEOF:
			last = true
		default:
			return err
		}
		if !last && i == math.MaxUint32 {
			return ErrTooLong
		}
		size := n
		if !last {
			size = SegmentSize
		}
		out = gcm.Seal(out[:0], nonce(prefix, uint32(i), last), buf[:size], nil)
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
		buf[0] = buf[SegmentSize]
		n = 1
	}
}

// Decrypt reads an encrypted stream from src and writes the plaintext to dst.
//
// Each segment is authenticated before it is written, but a truncated stream
// is only detected at the end. Until Decrypt returns nil, treat everything
// written to dst as untrusted: write to a temporary file and rename it into
// place only on success.
func Decrypt(dst io.Writer, src io.Reader, key, associatedData []byte) error {
	header := make([]byte, HeaderSize)
	if _, err := io.ReadFull(src, header); err != nil {
		return readErr(err)
	}
	if header[0] != Version {
		return ErrDecrypt
	}
	salt, prefix := header[1:1+SaltSize], header[1+SaltSize:]
	gcm, err := streamCipher(key, salt, associatedData)
	if err != nil {
		return err
	}

	const segLen = SegmentSize + TagSize
	buf := make([]byte, segLen+1)
	out := make([]byte, 0, SegmentSize)
	n := 0
	for i := uint64(0); ; i++ {
		m, err := io.ReadFull(src, buf[n:])
		n += m
		last := false
		switch err {
		case nil:
		case io.EOF, io.ErrUnexpectedEOF:
			last = true
		default:
			return err
		}
		if i > math.MaxUint32 {
			return ErrDecrypt
		}
		size := n
		if !last {
			size = segLen
		}
		if size < TagSize {
			return ErrDecrypt
		}
		out, err = gcm.Open(out[:0], nonce(prefix, uint32(i), last), buf[:size], nil)
		if err != nil {
			return ErrDecrypt
		}
		if _, err := dst.Write(out); err != nil {
			return err
		}
		if last {
			return nil
		}
		buf[0] = buf[segLen]
		n = 1
	}
}

func streamCipher(key, salt, associatedData []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("stream: key must be %d bytes, got %d", KeySize, len(key))
	}
	streamKey, err := hkdf.Key(sha256.New, key, salt, label+string(associatedData), KeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(streamKey)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func nonce(prefix []byte, i uint32, last bool) []byte {
	n := make([]byte, 0, 12)
	n = append(n, prefix...)
	n = binary.BigEndian.AppendUint32(n, i)
	if last {
		return append(n, 1)
	}
	return append(n, 0)
}

// readErr maps a short header to ErrDecrypt and passes real I/O errors through.
func readErr(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return ErrDecrypt
	}
	return err
}
