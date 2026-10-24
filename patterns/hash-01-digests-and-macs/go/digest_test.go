package digest

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var abc = []byte("abc")

// FIPS 180-4 example values for "abc".
var abcSums = map[string]string{
	SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	SHA384: "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
	SHA512: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
}

func sri(alg, hexSum string) string {
	b, _ := hex.DecodeString(hexSum)
	return alg + "-" + base64.StdEncoding.EncodeToString(b)
}

func TestSumKnownAnswer(t *testing.T) {
	if got := Sum(abc); got != sri(SHA384, abcSums[SHA384]) {
		t.Fatalf("Sum(abc) = %s", got)
	}
	r, err := SumReader(bytes.NewReader(abc))
	if err != nil || r != Sum(abc) {
		t.Fatal("SumReader differs from Sum")
	}
}

func TestCheck(t *testing.T) {
	for alg, s := range abcSums {
		if err := Check(sri(alg, s), abc, Compatible); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
	if err := Check(Sum(abc), []byte("abd"), Strong); err != ErrMismatch {
		t.Errorf("tampered data: %v", err)
	}
}

func TestCheckRejects(t *testing.T) {
	m := md5.Sum(abc)
	s1 := sha1.Sum(abc)
	good := Sum(abc)
	// Change the last base64 character so only the unused low bits differ.
	b64 := strings.TrimPrefix(sri(SHA256, abcSums[SHA256]), "sha256-")
	nonCanonical := "sha256-" + b64[:len(b64)-2] + "1="
	cases := map[string]struct {
		in     string
		policy Policy
		want   error
	}{
		"md5":            {"md5-" + base64.StdEncoding.EncodeToString(m[:]), Compatible, ErrAlgorithm},
		"sha1":           {"sha1-" + base64.StdEncoding.EncodeToString(s1[:]), Compatible, ErrAlgorithm},
		"sha256 strict":  {sri(SHA256, abcSums[SHA256]), Strong, ErrAlgorithm},
		"upper-case alg": {strings.Replace(good, "sha384", "SHA384", 1), Strong, ErrAlgorithm},
		"no separator":   {strings.Replace(good, "-", "", 1), Strong, ErrFormat},
		"truncated":      {good[:len(good)-8], Strong, ErrFormat},
		"url alphabet":   {strings.NewReplacer("+", "-", "/", "_").Replace(good), Strong, ErrFormat},
		"non-canonical":  {nonCanonical, Compatible, ErrFormat},
		"trailing data":  {good + " sha512-xyz", Strong, ErrFormat},
	}
	for name, c := range cases {
		if err := Check(c.in, abc, c.policy); err != c.want {
			t.Errorf("%s: got %v, want %v", name, err, c.want)
		}
	}
}

// RFC 4231 test case 6: a 131-byte key, larger than the hash block.
var (
	rfcKey = bytes.Repeat([]byte{0xaa}, 131)
	rfcMsg = []byte("Test Using Larger Than Block-Size Key - Hash Key First")
	rfcTag = "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
)

func TestTagKnownAnswer(t *testing.T) {
	tag, err := Tag(rfcKey, rfcMsg)
	if err != nil || hex.EncodeToString(tag) != rfcTag {
		t.Fatalf("HMAC-SHA-384 does not match RFC 4231: %x %v", tag, err)
	}
	if err := Verify(rfcKey, rfcMsg, tag); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	tag, _ := Tag(rfcKey, rfcMsg)
	flipped := bytes.Clone(tag)
	flipped[0] ^= 1
	for name, err := range map[string]error{
		"tampered msg":  Verify(rfcKey, append(bytes.Clone(rfcMsg), '!'), tag),
		"tampered tag":  Verify(rfcKey, rfcMsg, flipped),
		"truncated tag": Verify(rfcKey, rfcMsg, tag[:16]),
		"empty tag":     Verify(rfcKey, rfcMsg, nil),
	} {
		if err != ErrMismatch {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Tag(rfcKey[:31], rfcMsg); err != ErrKey {
		t.Errorf("short key: %v", err)
	}
	if err := Verify(rfcKey[:31], rfcMsg, tag); err != ErrKey {
		t.Errorf("short key verify: %v", err)
	}
}

type vector struct {
	Data   string            `json:"data"`
	Sums   map[string]string `json:"sums"`
	Key    string            `json:"hmac_key"`
	Msg    string            `json:"hmac_msg"`
	Tag    string            `json:"hmac_tag"`
	Reject []string          `json:"reject"`
}

const vectorPath = "../testdata/vector.json"

// TestVector checks the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		data := []byte("pqc-patterns HASH-01 vector")
		key := bytes.Repeat([]byte{0x0b}, 32)
		msg := []byte("POST /v1/exports tenant-42")
		tag, _ := Tag(key, msg)
		v := vector{
			Data: hex.EncodeToString(data),
			Sums: map[string]string{},
			Key:  hex.EncodeToString(key), Msg: hex.EncodeToString(msg), Tag: hex.EncodeToString(tag),
		}
		for _, alg := range []string{SHA256, SHA384, SHA512} {
			h := newHash(alg)()
			h.Write(data)
			v.Sums[alg] = format(alg, h.Sum(nil))
		}
		m := md5.Sum(data)
		v.Reject = []string{
			"md5-" + base64.StdEncoding.EncodeToString(m[:]),
			strings.ToUpper(v.Sums[SHA384][:6]) + v.Sums[SHA384][6:],
			v.Sums[SHA384] + "=",
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(vectorPath, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	data, _ := hex.DecodeString(v.Data)
	for alg, s := range v.Sums {
		if err := Check(s, data, Compatible); err != nil {
			t.Errorf("%s: %v", alg, err)
		}
	}
	if Sum(data) != v.Sums[SHA384] {
		t.Error("Sum differs from the vector")
	}
	for _, s := range v.Reject {
		if Check(s, data, Compatible) == nil {
			t.Errorf("accepted %q", s)
		}
	}
	key, _ := hex.DecodeString(v.Key)
	msg, _ := hex.DecodeString(v.Msg)
	tag, _ := hex.DecodeString(v.Tag)
	if err := Verify(key, msg, tag); err != nil {
		t.Error(err)
	}
}
