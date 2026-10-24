//! Pattern SESS-01: opaque, random session tokens with server-side state,
//! idle and absolute timeouts, rotation and revocation.
//!
//! A token is [`PREFIX`] followed by 32 random bytes in unpadded base64url.
//! The server stores only SHA-256 of those bytes (the session ID), so a
//! leaked session table cannot be replayed as cookies, and looking a session
//! up by its hash leaks nothing useful through timing.
//!
//! Random tokens have no signature for a quantum computer to forge, which is
//! why they are the recommended default for browser sessions.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// Marks tokens so secret scanners can find leaked ones. Change it to
/// something unique to your application.
pub const PREFIX: &str = "sess_";
/// 256 bits keeps a 128-bit margin against Grover's algorithm.
pub const TOKEN_BYTES: usize = 32;
/// The `__Host-` prefix makes browsers accept the cookie only over HTTPS,
/// for this exact host, with `Path=/`.
pub const COOKIE_NAME: &str = "__Host-session";
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
pub const DEFAULT_ABSOLUTE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);
const ENCODED_LEN: usize = 43;

/// Server-side state for one login.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session {
    pub user_id: String,
    pub created: SystemTime,
    pub last_seen: SystemTime,
}

pub type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Debug)]
pub enum Error {
    /// Malformed, unknown, expired and revoked tokens alike, so callers
    /// cannot tell them apart.
    Invalid,
    Store(StoreError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Invalid => write!(f, "sessions: invalid session"),
            Error::Store(e) => write!(f, "sessions: store: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<StoreError> for Error {
    fn from(e: StoreError) -> Self {
        Error::Store(e)
    }
}

/// Persists sessions by session ID (lowercase hex SHA-256 of the token).
/// Use a database table or a cache such as Redis with a TTL of the absolute
/// timeout.
pub trait Store: Send + Sync {
    fn get(&self, id: &str) -> Result<Option<Session>, StoreError>;
    fn put(&self, id: &str, session: &Session) -> Result<(), StoreError>;
    fn delete(&self, id: &str) -> Result<(), StoreError>;
}

/// Issues and checks session tokens.
pub struct Manager<S: Store> {
    pub store: S,
    pub idle_timeout: Duration,
    pub absolute_timeout: Duration,
    pub clock: Box<dyn Fn() -> SystemTime + Send + Sync>,
    rng: SystemRandom,
}

impl<S: Store> Manager<S> {
    /// A manager with the default timeouts and the system clock.
    pub fn new(store: S) -> Self {
        Manager {
            store,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            absolute_timeout: DEFAULT_ABSOLUTE_TIMEOUT,
            clock: Box::new(SystemTime::now),
            rng: SystemRandom::new(),
        }
    }

    /// Starts a new session for `user_id` and returns its token. Call it on
    /// every successful login, never reusing a token from before the login.
    pub fn create(&self, user_id: &str) -> Result<String, Error> {
        let now = (self.clock)();
        self.issue(&Session {
            user_id: user_id.to_owned(),
            created: now,
            last_seen: now,
        })
    }

    fn issue(&self, session: &Session) -> Result<String, Error> {
        let mut raw = [0u8; TOKEN_BYTES];
        self.rng.fill(&mut raw).expect("system RNG failed");
        self.store.put(&id_of(&raw), session)?;
        Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(raw)))
    }

    /// Returns the session for `token` and records the activity. Expired
    /// sessions are deleted.
    pub fn validate(&self, token: &str) -> Result<Session, Error> {
        let id = session_id(token)?;
        let mut session = self.store.get(&id)?.ok_or(Error::Invalid)?;
        let now = (self.clock)();
        let since = |t: SystemTime| now.duration_since(t).unwrap_or(Duration::ZERO);
        if since(session.last_seen) >= self.idle_timeout || since(session.created) >= self.absolute_timeout {
            self.store.delete(&id)?;
            return Err(Error::Invalid);
        }
        session.last_seen = now;
        self.store.put(&id, &session)?;
        Ok(session)
    }

    /// Replaces a valid token with a new one for the same session and
    /// revokes the old one. Call it when the session's privileges change.
    /// The absolute timeout still counts from the original login.
    pub fn rotate(&self, token: &str) -> Result<String, Error> {
        let session = self.validate(token)?;
        self.revoke(token)?;
        self.issue(&session)
    }

    /// Ends the session for `token`, for example on logout. Revoking an
    /// unknown or malformed token is not an error.
    pub fn revoke(&self, token: &str) -> Result<(), Error> {
        match session_id(token) {
            Ok(id) => Ok(self.store.delete(&id)?),
            Err(_) => Ok(()),
        }
    }
}

/// Checks the token's format and returns the ID it is stored under.
pub fn session_id(token: &str) -> Result<String, Error> {
    let enc = token.strip_prefix(PREFIX).ok_or(Error::Invalid)?;
    if enc.len() != ENCODED_LEN {
        return Err(Error::Invalid);
    }
    // The default engine rejects padding and non-zero trailing bits, so each
    // token has exactly one valid spelling.
    let raw = URL_SAFE_NO_PAD.decode(enc).map_err(|_| Error::Invalid)?;
    Ok(id_of(&raw))
}

fn id_of(raw: &[u8]) -> String {
    digest(&SHA256, raw)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The `Set-Cookie` value for `token`: host-only, HTTPS-only, not readable
/// by JavaScript and not sent on cross-site subresource requests. It has no
/// `Max-Age`, so the browser drops it on exit, and the server's timeouts
/// apply either way.
pub fn set_cookie(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; Path=/; HttpOnly; Secure; SameSite=Lax")
}

/// The `Set-Cookie` value that deletes the session cookie.
pub fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax")
}

/// Returns the session token from a `Cookie` request header, if present.
pub fn from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == COOKIE_NAME)
        .map(|(_, value)| value)
}

/// An in-process [`Store`] for tests and single-instance services.
#[derive(Default)]
pub struct MemoryStore {
    sessions: Mutex<HashMap<String, Session>>,
}

impl MemoryStore {
    pub fn ids(&self) -> Vec<String> {
        self.sessions.lock().unwrap().keys().cloned().collect()
    }
}

impl Store for MemoryStore {
    fn get(&self, id: &str) -> Result<Option<Session>, StoreError> {
        Ok(self.sessions.lock().unwrap().get(id).cloned())
    }

    fn put(&self, id: &str, session: &Session) -> Result<(), StoreError> {
        self.sessions
            .lock()
            .unwrap()
            .insert(id.to_owned(), session.clone());
        Ok(())
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        self.sessions.lock().unwrap().remove(id);
        Ok(())
    }
}
