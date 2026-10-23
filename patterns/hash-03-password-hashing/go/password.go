// Package password implements pattern HASH-03: storing passwords with
// Argon2id (RFC 9106) in the PHC string format
//
//	$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>
//
// with a fresh 16-byte salt per password, a constant-time comparison, and a
// signal to re-hash when the stored parameters are older than the current
// ones.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id cost parameters.
type Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
}

// Default is RFC 9106's second recommended option: 64 MiB, 3 passes, 4
// lanes. Tune Time upwards until hashing takes about 0.5 s on your servers,
// but never go below OWASP's floor of 19 MiB and 2 passes.
var Default = Params{MemoryKiB: 64 * 1024, Time: 3, Threads: 4}

const (
	saltLen = 16
	hashLen = 32
	// Bounds for stored parameters, so a corrupt or hostile database row
	// cannot make Verify allocate gigabytes.
	maxMemoryKiB = 1 << 20 // 1 GiB
	maxTime      = 16
	maxThreads   = 16
)

var (
	ErrMismatch = errors.New("password: does not match")
	ErrFormat   = errors.New("password: not a supported argon2id PHC string")
)

var b64 = base64.RawStdEncoding.Strict()

// Hash returns a PHC string for password under p.
func Hash(password []byte, p Params) (string, error) {
	if !p.valid() {
		return "", ErrFormat
	}
	salt := make([]byte, saltLen)
	rand.Read(salt) // crypto/rand.Read never returns an error since Go 1.24.
	h := argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, hashLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		p.MemoryKiB, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(h)), nil
}

// Verify checks password against a stored PHC string. On success it reports
// whether the hash should be replaced, because its parameters differ from
// current; re-hash and store the new value while you have the plaintext.
func Verify(password []byte, stored string, current Params) (needsRehash bool, err error) {
	p, salt, want, err := parse(stored)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey(password, salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, ErrMismatch
	}
	return p != current, nil
}

func (p Params) valid() bool {
	return p.Threads >= 1 && p.Threads <= maxThreads &&
		p.Time >= 1 && p.Time <= maxTime &&
		p.MemoryKiB >= 8*uint32(p.Threads) && p.MemoryKiB <= maxMemoryKiB
}

// parse accepts only the canonical form Hash writes: argon2id, version 19,
// parameters in m,t,p order without leading zeros, unpadded base64, a salt
// of at least 16 bytes and a 32-byte hash.
func parse(s string) (Params, []byte, []byte, error) {
	var p Params
	f := strings.Split(s, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" || f[2] != "v=19" {
		return p, nil, nil, ErrFormat
	}
	kv := strings.Split(f[3], ",")
	if len(kv) != 3 {
		return p, nil, nil, ErrFormat
	}
	var vals [3]uint64
	for i, name := range []string{"m=", "t=", "p="} {
		n, ok := strings.CutPrefix(kv[i], name)
		v, err := strconv.ParseUint(n, 10, 32)
		if !ok || err != nil || strconv.FormatUint(v, 10) != n {
			return p, nil, nil, ErrFormat
		}
		vals[i] = v
	}
	if vals[2] > maxThreads {
		return p, nil, nil, ErrFormat
	}
	p = Params{MemoryKiB: uint32(vals[0]), Time: uint32(vals[1]), Threads: uint8(vals[2])}
	salt, err1 := b64.DecodeString(f[4])
	hash, err2 := b64.DecodeString(f[5])
	if !p.valid() || err1 != nil || err2 != nil || len(salt) < saltLen || len(hash) != hashLen {
		return Params{}, nil, nil, ErrFormat
	}
	return p, salt, hash, nil
}
