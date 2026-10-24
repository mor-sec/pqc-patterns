package fixtures

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/md5"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
)

func kx(pub *rsa.PublicKey, priv *ecdh.PrivateKey, peer *ecdh.PublicKey) {
	// ruleid: pqc-kx-rsa-encrypt
	rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte("k"), nil)
	// ruleid: pqc-kx-classical-ecdh
	priv.ECDH(peer)
	// ruleid: pqc-kx-classical-ecdh
	hpke.DHKEM(ecdh.X25519())
	// ok: pqc-kx-classical-ecdh
	hpke.MLKEM768X25519()
}

func sigs(sk *mldsa.PrivateKey, pk *mldsa.PublicKey, msg, sig []byte) {
	// ruleid: pqc-sig-classical-keygen
	rsa.GenerateKey(rand.Reader, 3072)
	// ruleid: pqc-sig-classical-keygen
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// ruleid: pqc-sig-classical-keygen
	ed25519.GenerateKey(rand.Reader)
	// ok: pqc-sig-classical-keygen
	mldsa.GenerateKey(mldsa.MLDSA65())

	// ruleid: pqc-sig-mldsa-no-context
	sk.Sign(nil, msg, nil)
	// ruleid: pqc-sig-mldsa-no-context
	mldsa.Verify(pk, msg, sig, nil)
	// ok: pqc-sig-mldsa-no-context
	sk.Sign(nil, msg, &mldsa.Options{Context: "app/v1"})
	// ok: pqc-sig-mldsa-no-context
	mldsa.Verify(pk, msg, sig, &mldsa.Options{Context: "app/v1"})
}

// Keys and AEADs declared with := have no type annotation for Semgrep.
func inferred(key, msg, pt []byte) {
	k, err := mldsa.GenerateKey(mldsa.MLDSA65())
	_ = err
	// ruleid: pqc-sig-mldsa-no-context
	k.Sign(rand.Reader, msg, nil)
	// ok: pqc-sig-mldsa-no-context
	k.Sign(rand.Reader, msg, &mldsa.Options{Context: "app/v1"})

	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	zero := make([]byte, aead.NonceSize())
	// ruleid: pqc-sym-static-nonce
	aead.Seal(zero, zero, pt, nil)
	// ruleid: pqc-sym-static-nonce
	aead.Seal(nil, make([]byte, 12), pt, nil)
	var arr [12]byte
	// ruleid: pqc-sym-static-nonce
	aead.Seal(nil, arr[:], pt, nil)
	var good [12]byte
	rand.Read(good[:])
	// ok: pqc-sym-static-nonce
	aead.Seal(nil, good[:], pt, nil)
}

func sym(key []byte, gcm cipher.AEAD, pt []byte) {
	block, _ := aes.NewCipher(key)
	// ruleid: pqc-sym-unauthenticated-mode
	cipher.NewCBCEncrypter(block, make([]byte, 16))
	// ruleid: pqc-sym-unauthenticated-mode
	cipher.NewCTR(block, make([]byte, 16))
	// ok: pqc-sym-unauthenticated-mode
	cipher.NewGCM(block)

	short := make([]byte, 16)
	// ruleid: pqc-sym-aes-128
	aes.NewCipher(short)
	long := make([]byte, 32)
	// ok: pqc-sym-aes-128
	aes.NewCipher(long)
	// ruleid: pqc-sym-aes-128
	hpke.AES128GCM()

	// ruleid: pqc-sym-static-nonce
	gcm.Seal(nil, make([]byte, 12), pt, nil)
	fixed := make([]byte, 12)
	// ruleid: pqc-sym-static-nonce
	gcm.Seal(nil, fixed, pt, nil)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	// ok: pqc-sym-static-nonce
	gcm.Seal(nil, nonce, pt, nil)
	n2 := make([]byte, 12)
	_, err := rand.Read(n2)
	_ = err
	// ok: pqc-sym-static-nonce
	gcm.Seal(nil, n2, pt, nil)
}

func tlsConfigs() []*tls.Config {
	// ruleid: pqc-tls-classical-groups
	a := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
	// ok: pqc-tls-classical-groups
	b := &tls.Config{CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519}}
	// ruleid: pqc-tls-min-version
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	// ok: pqc-tls-min-version
	d := &tls.Config{MinVersion: tls.VersionTLS13}
	// ruleid: pqc-tls-no-verify
	e := &tls.Config{InsecureSkipVerify: true}
	// ruleid: pqc-tls-classical-groups
	b.CurvePreferences = []tls.CurveID{tls.X25519}
	// ok: pqc-tls-classical-groups
	b.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
	// ruleid: pqc-tls-min-version
	d.MinVersion = tls.VersionTLS12
	// ruleid: pqc-tls-no-verify
	d.InsecureSkipVerify = true
	return []*tls.Config{a, b, c, d, e}
}

func hashes(b []byte) {
	// ruleid: pqc-hash-weak
	md5.Sum(b)
	// ruleid: pqc-hash-weak
	sha1.New()
	// ok: pqc-hash-weak
	sha256.Sum256(b)
}

func macs(key, msg, got []byte) bool {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	// ruleid: pqc-mac-compare
	if bytes.Equal(m.Sum(nil), got) {
		return true
	}
	want := m.Sum(nil)
	// ruleid: pqc-mac-compare
	if bytes.Equal(got, want) {
		return true
	}
	// ok: pqc-mac-compare
	if bytes.Equal(msg, got) {
		return true
	}
	// ok: pqc-mac-compare
	return hmac.Equal(want, got)
}
