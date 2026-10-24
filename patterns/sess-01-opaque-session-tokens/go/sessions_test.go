package sessions

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTestManager() (*Manager, *MemoryStore, *clock) {
	c := &clock{t: time.Date(2026, 10, 23, 9, 0, 0, 0, time.UTC)}
	store := NewMemoryStore()
	m := NewManager(store)
	m.Now = c.now
	return m, store, c
}

func mustCreate(t *testing.T, m *Manager, user string) string {
	t.Helper()
	tok, err := m.Create(user)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestCreateAndValidate(t *testing.T) {
	m, _, _ := newTestManager()
	tok := mustCreate(t, m, "user-42")
	if !strings.HasPrefix(tok, Prefix) || len(tok) != len(Prefix)+43 {
		t.Fatalf("unexpected token shape %q", tok)
	}
	s, err := m.Validate(tok)
	if err != nil || s.UserID != "user-42" {
		t.Fatalf("validate failed: %v", err)
	}
}

func TestStoresOnlyTheHash(t *testing.T) {
	m, store, _ := newTestManager()
	tok := mustCreate(t, m, "user-42")
	enc := strings.TrimPrefix(tok, Prefix)
	for id := range store.sessions {
		if strings.Contains(id, enc) || strings.Contains(enc, id) || len(id) != 64 {
			t.Fatalf("store key %q reveals the token", id)
		}
	}
}

func TestIdleTimeout(t *testing.T) {
	m, store, c := newTestManager()
	tok := mustCreate(t, m, "u")
	c.advance(20 * time.Minute)
	if _, err := m.Validate(tok); err != nil {
		t.Fatal("activity within the idle timeout rejected")
	}
	c.advance(20 * time.Minute)
	if _, err := m.Validate(tok); err != nil {
		t.Fatal("activity did not extend the idle timeout")
	}
	c.advance(DefaultIdleTimeout)
	if _, err := m.Validate(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("idle session accepted")
	}
	if len(store.sessions) != 0 {
		t.Fatal("expired session not deleted")
	}
}

func TestAbsoluteTimeout(t *testing.T) {
	m, _, c := newTestManager()
	tok := mustCreate(t, m, "u")
	for elapsed := time.Duration(0); elapsed < DefaultAbsoluteTimeout-20*time.Minute; elapsed += 20 * time.Minute {
		c.advance(20 * time.Minute)
		if _, err := m.Validate(tok); err != nil {
			t.Fatalf("active session rejected after %v", elapsed)
		}
	}
	c.advance(20 * time.Minute)
	if _, err := m.Validate(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("session outlived the absolute timeout")
	}
}

func TestRotate(t *testing.T) {
	m, _, c := newTestManager()
	start := c.t
	old := mustCreate(t, m, "u")
	c.advance(20 * time.Minute)
	fresh, err := m.Rotate(old)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(old); !errors.Is(err, ErrInvalid) {
		t.Fatal("old token still valid after rotation")
	}
	s, err := m.Validate(fresh)
	if err != nil || s.UserID != "u" {
		t.Fatalf("rotated token invalid: %v", err)
	}
	if !s.Created.Equal(start) {
		t.Fatal("rotation reset the absolute timeout")
	}
	if _, err := m.Rotate(old); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked token rotated")
	}
}

func TestRevoke(t *testing.T) {
	m, _, _ := newTestManager()
	tok := mustCreate(t, m, "u")
	if err := m.Revoke(tok); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Validate(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("revoked token accepted")
	}
	if err := m.Revoke("garbage"); err != nil {
		t.Fatal("revoking a malformed token failed")
	}
}

func TestRejectsUnknownToken(t *testing.T) {
	m, _, _ := newTestManager()
	tok := mustCreate(t, m, "u")
	other, _, _ := newTestManager()
	if _, err := other.Validate(tok); !errors.Is(err, ErrInvalid) {
		t.Fatal("token from another store accepted")
	}
}

func TestTokensAreUnique(t *testing.T) {
	m, _, _ := newTestManager()
	seen := map[string]bool{}
	for range 1000 {
		tok := mustCreate(t, m, "u")
		if seen[tok] {
			t.Fatal("token reused")
		}
		seen[tok] = true
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if FromRequest(r) != "" {
		t.Fatal("token found in a request without a cookie")
	}
	r.AddCookie(Cookie("sess_abc"))
	if FromRequest(r) != "sess_abc" {
		t.Fatal("token not read from cookie")
	}
}

type vector struct {
	Token         string   `json:"token"`
	SessionID     string   `json:"session_id"`
	InvalidTokens []string `json:"invalid_tokens"`
	SetCookie     string   `json:"set_cookie"`
	ClearCookie   string   `json:"clear_cookie"`
}

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// TestVector checks the shared cross-language vector. Regenerate it with
// PQC_WRITE_VECTORS=1 go test ./...
func TestVector(t *testing.T) {
	path := "../testdata/vector.json"
	if os.Getenv("PQC_WRITE_VECTORS") == "1" {
		raw := make([]byte, TokenBytes)
		rand.Read(raw)
		enc := tokenEncoding.EncodeToString(raw)
		last := strings.IndexByte(alphabet, enc[len(enc)-1])
		v := vector{
			Token:     Prefix + enc,
			SessionID: idOf(raw),
			InvalidTokens: []string{
				"",
				enc,
				strings.ToUpper(Prefix) + enc,
				Prefix + enc + "=",
				Prefix + enc[:len(enc)-1],
				Prefix + enc + "A",
				Prefix + "+" + enc[1:],
				Prefix + "/" + enc[1:],
				Prefix + " " + enc[1:],
				Prefix + enc[:len(enc)-1] + string(alphabet[last^1]),
			},
			SetCookie:   Cookie(Prefix + enc).String(),
			ClearCookie: ClearCookie().String(),
		}
		out, _ := json.MarshalIndent(v, "", "  ")
		if err := os.WriteFile(path, append(out, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var v vector
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if id, err := SessionID(v.Token); err != nil || id != v.SessionID {
		t.Fatalf("session ID mismatch: %v", err)
	}
	for _, bad := range v.InvalidTokens {
		if _, err := SessionID(bad); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed token %q accepted", bad)
		}
	}
	if got := Cookie(v.Token).String(); got != v.SetCookie {
		t.Fatalf("Set-Cookie = %q, want %q", got, v.SetCookie)
	}
	if got := ClearCookie().String(); got != v.ClearCookie {
		t.Fatalf("clearing Set-Cookie = %q, want %q", got, v.ClearCookie)
	}
}
