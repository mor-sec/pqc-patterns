package fixtures

import (
	crand "crypto/rand"
	"math/rand"
	mrand2 "math/rand/v2"
)

func newSessionToken() []byte {
	b := make([]byte, 32)
	// ruleid: pqc-token-weak-random
	rand.Read(b)
	return b
}

func newResetToken() string {
	// ok: pqc-token-weak-random
	return crand.Text()
}

func generate() {
	// ruleid: pqc-token-weak-random
	apiKey := rand.Int63()
	// ruleid: pqc-token-weak-random
	nonce := mrand2.Uint64()
	salt := make([]byte, 16)
	// ok: pqc-token-weak-random
	crand.Read(salt)
	// ok: pqc-token-weak-random
	jitter := rand.Intn(100)
	// ok: pqc-token-weak-random
	shard := mrand2.IntN(8)
	_, _, _, _ = apiKey, nonce, jitter, shard
}
