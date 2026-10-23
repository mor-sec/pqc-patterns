package password

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

// fast keeps the tests quick. Production code uses Default.
var fast = Params{MemoryKiB: 8 * 1024, Time: 1, Threads: 1}

var pw = []byte("correct horse battery staple")

func TestRoundTrip(t *testing.T) {
	h, err := Hash(pw, fast)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=8192,t=1,p=1$") {
		t.Fatalf("unexpected format %q", h)
	}
	if rehash, err := Verify(pw, h, fast); err != nil || rehash {
		t.Fatalf("verify: rehash=%v err=%v", rehash, err)
	}
	if _, err := Verify([]byte("Correct horse battery staple"), h, fast); !errors.Is(err, ErrMismatch) {
		t.Fatalf("wrong password: %v", err)
	}
}

func TestDefaultParams(t *testing.T) {
	h, err := Hash(pw, Default)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(pw, h, Default); err != nil {
		t.Fatal(err)
	}
}

func TestSaltIsFresh(t *testing.T) {
	a, _ := Hash(pw, fast)
	b, _ := Hash(pw, fast)
	if a == b {
		t.Fatal("two hashes of one password are identical")
	}
}

func TestNeedsRehash(t *testing.T) {
	old, _ := Hash(pw, fast)
	rehash, err := Verify(pw, old, Params{MemoryKiB: 16 * 1024, Time: 2, Threads: 1})
	if err != nil || !rehash {
		t.Fatalf("rehash=%v err=%v", rehash, err)
	}
}

func TestRejectsMalformed(t *testing.T) {
	good, _ := Hash(pw, fast)
	f := strings.Split(good, "$")
	cases := map[string]string{
		"argon2i":      strings.Replace(good, "argon2id", "argon2i", 1),
		"version 16":   strings.Replace(good, "v=19", "v=16", 1),
		"leading zero": strings.Replace(good, "m=8192", "m=08192", 1),
		"plus sign":    strings.Replace(good, "m=8192", "m=+8192", 1),
		"reordered":    strings.Replace(good, "m=8192,t=1,p=1", "t=1,m=8192,p=1", 1),
		"huge memory":  strings.Replace(good, "m=8192", "m=4194304", 1),
		"zero threads": strings.Replace(good, "p=1", "p=0", 1),
		"short salt":   strings.Join([]string{"", f[1], f[2], f[3], b64.EncodeToString([]byte("short")), f[5]}, "$"),
		"padded":       good + "=",
		"short hash":   strings.Join([]string{"", f[1], f[2], f[3], f[4], f[5][:20]}, "$"),
		"bcrypt":       "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
		"empty":        "",
		"extra field":  good + "$x",
	}
	for name, s := range cases {
		if _, err := Verify(pw, s, fast); !errors.Is(err, ErrFormat) {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

type vector struct {
	Password string `json:"password"`
	PHC      string `json:"phc"`
}

const vectorPath = "../testdata/vector.json"

// TestVector checks the shared cross-language fixture. Set
// PQC_WRITE_VECTORS=1 to regenerate it.
func TestVector(t *testing.T) {
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		h, _ := Hash(pw, fast)
		out, _ := json.MarshalIndent(vector{string(pw), h}, "", "  ")
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
	if _, err := Verify([]byte(v.Password), v.PHC, fast); err != nil {
		t.Fatal(err)
	}
}

// TestArgon2idKnownAnswer checks the primitive against the reference
// implementation's output for "password" / "somesalt", m=64 MiB, t=2, p=1
// (from the phc-winner-argon2 README), so a self-generated vector cannot
// hide a wrong Argon2 variant or version.
func TestArgon2idKnownAnswer(t *testing.T) {
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 2, 64*1024, 1, 32)
	if b64.EncodeToString(got) != "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc" {
		t.Fatalf("argon2id mismatch: %s", b64.EncodeToString(got))
	}
}
