// Package sessions implements pattern SESS-01: opaque, random session tokens
// with server-side state, idle and absolute timeouts, rotation and
// revocation.
//
// A token is Prefix followed by 32 random bytes in unpadded base64url. The
// server stores only SHA-256 of those bytes (the session ID), so a leaked
// session table cannot be replayed as cookies, and looking a session up by
// its hash leaks nothing useful through timing.
//
// Random tokens have no signature for a quantum computer to forge, which is
// why they are the recommended default for browser sessions.
package sessions

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// Prefix marks tokens so secret scanners can find leaked ones. Change it
	// to something unique to your application.
	Prefix = "sess_"
	// TokenBytes of randomness: 256 bits keeps a 128-bit margin against
	// Grover's algorithm.
	TokenBytes = 32
	// CookieName uses the __Host- prefix, so browsers only accept the cookie
	// over HTTPS, for this exact host, with Path=/.
	CookieName = "__Host-session"

	DefaultIdleTimeout     = 30 * time.Minute
	DefaultAbsoluteTimeout = 12 * time.Hour
)

var (
	// ErrInvalid is returned for malformed, unknown, expired and revoked
	// tokens alike, so callers cannot tell them apart.
	ErrInvalid = errors.New("sessions: invalid session")

	tokenEncoding = base64.RawURLEncoding.Strict()
)

// Session is the server-side state for one login.
type Session struct {
	UserID   string
	Created  time.Time
	LastSeen time.Time
}

// Store persists sessions by session ID (lowercase hex SHA-256 of the
// token). Use a database table or a cache such as Redis with a TTL of the
// absolute timeout. It must be safe for concurrent use.
type Store interface {
	Get(id string) (Session, bool, error)
	Put(id string, s Session) error
	Delete(id string) error
}

// Manager issues and checks session tokens.
type Manager struct {
	Store           Store
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	Now             func() time.Time
}

// NewManager returns a Manager with the default timeouts.
func NewManager(store Store) *Manager {
	return &Manager{
		Store:           store,
		IdleTimeout:     DefaultIdleTimeout,
		AbsoluteTimeout: DefaultAbsoluteTimeout,
		Now:             time.Now,
	}
}

// Create starts a new session for userID and returns its token. Call it on
// every successful login, never reusing a token from before the login.
func (m *Manager) Create(userID string) (string, error) {
	now := m.Now()
	return m.issue(Session{UserID: userID, Created: now, LastSeen: now})
}

func (m *Manager) issue(s Session) (string, error) {
	raw := make([]byte, TokenBytes)
	rand.Read(raw) // crypto/rand.Read never returns an error since Go 1.24.
	token := Prefix + tokenEncoding.EncodeToString(raw)
	if err := m.Store.Put(idOf(raw), s); err != nil {
		return "", err
	}
	return token, nil
}

// Validate returns the session for token and records the activity. Expired
// sessions are deleted.
func (m *Manager) Validate(token string) (Session, error) {
	id, err := SessionID(token)
	if err != nil {
		return Session{}, err
	}
	s, ok, err := m.Store.Get(id)
	if err != nil {
		return Session{}, err
	}
	if !ok {
		return Session{}, ErrInvalid
	}
	now := m.Now()
	if now.Sub(s.LastSeen) >= m.IdleTimeout || now.Sub(s.Created) >= m.AbsoluteTimeout {
		if err := m.Store.Delete(id); err != nil {
			return Session{}, err
		}
		return Session{}, ErrInvalid
	}
	s.LastSeen = now
	if err := m.Store.Put(id, s); err != nil {
		return Session{}, err
	}
	return s, nil
}

// Rotate replaces a valid token with a new one for the same session and
// revokes the old one. Call it when the session's privileges change, such as
// after a password change or step-up authentication. The absolute timeout
// still counts from the original login.
func (m *Manager) Rotate(token string) (string, error) {
	s, err := m.Validate(token)
	if err != nil {
		return "", err
	}
	if err := m.Revoke(token); err != nil {
		return "", err
	}
	return m.issue(s)
}

// Revoke ends the session for token, for example on logout. Revoking an
// unknown or malformed token is not an error.
func (m *Manager) Revoke(token string) error {
	id, err := SessionID(token)
	if err != nil {
		return nil
	}
	return m.Store.Delete(id)
}

// SessionID checks the token's format and returns the ID it is stored under.
func SessionID(token string) (string, error) {
	enc, ok := strings.CutPrefix(token, Prefix)
	if !ok || len(enc) != tokenEncoding.EncodedLen(TokenBytes) {
		return "", ErrInvalid
	}
	raw, err := tokenEncoding.DecodeString(enc)
	if err != nil {
		return "", ErrInvalid
	}
	return idOf(raw), nil
}

func idOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Cookie returns the Set-Cookie value for token: host-only, HTTPS-only, not
// readable by JavaScript and not sent on cross-site subresource requests. It
// has no Max-Age, so the browser drops it on exit, and the server's timeouts
// apply either way.
func Cookie(token string) *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// ClearCookie returns the Set-Cookie value that deletes the session cookie.
func ClearCookie() *http.Cookie {
	c := Cookie("")
	c.MaxAge = -1
	return c
}

// FromRequest returns the session token from the request's cookie, or "".
func FromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil {
		return ""
	}
	return c.Value
}

// MemoryStore is an in-process Store for tests and single-instance services.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]Session
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{sessions: make(map[string]Session)}
}

func (m *MemoryStore) Get(id string) (Session, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	return s, ok, nil
}

func (m *MemoryStore) Put(id string, s Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = s
	return nil
}

func (m *MemoryStore) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}
