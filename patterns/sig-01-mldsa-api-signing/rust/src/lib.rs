//! Pattern SIG-01: signing API requests with ML-DSA-65 (FIPS 204) so a
//! receiver can prove who sent a request, that it was meant for that
//! receiver, that it was not altered, and that it is recent. Replay inside
//! the freshness window is not detected; see [`Verifier::verify_at`].
//!
//! The signed message is a length-prefixed encoding of
//! `key ID, audience, timestamp (Unix seconds, decimal), HTTP method, path, body`,
//! signed under the ML-DSA context string [`CONTEXT`]. Every language in
//! this repo produces and verifies the same bytes.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use getrandom::SysRng;
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed, Signature, SigningKey, VerifyingKey};

/// Domain-separates API request signatures (FIPS 204, section 5.2).
pub const CONTEXT: &[u8] = b"pqc-patterns/sig-01/api-request/v2";
pub const DEFAULT_MAX_SKEW: Duration = Duration::from_secs(300);

/// The parameter set for general-purpose signing. Use `MlDsa87` where
/// CNSA 2.0 applies.
pub type Params = MlDsa65;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    UnknownKey,
    Stale,
    Signature,
    /// The verifier has no audience configured.
    NoAudience,
}

/// The part of an HTTP request that is covered by the signature.
pub struct Request<'a> {
    pub key_id: &'a str,
    /// The receiver the request is for, such as `https://payments.internal`.
    /// It stops a request signed for one receiver being replayed to another
    /// that trusts the same key. It is signed but not sent: the receiver
    /// supplies its own.
    pub audience: &'a str,
    pub timestamp: i64,
    pub method: &'a str,
    /// Include the query string.
    pub path: &'a str,
    pub body: &'a [u8],
}

impl Request<'_> {
    /// The exact bytes that are signed. Panics if a field is 4 GiB or longer,
    /// rather than truncating its length prefix.
    pub fn message(&self) -> Vec<u8> {
        let ts = self.timestamp.to_string();
        let mut out = Vec::new();
        for f in [
            self.key_id.as_bytes(),
            self.audience.as_bytes(),
            ts.as_bytes(),
            self.method.as_bytes(),
            self.path.as_bytes(),
            self.body,
        ] {
            let len = u32::try_from(f.len()).expect("request field too long");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }
}

/// Creates a new signing key and returns it with its 32-byte FIPS 204 seed.
/// Store only the seed, in your secret store or KMS.
pub fn generate_key() -> (SigningKey<Params>, [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("system RNG failed");
    (load_private_key(&seed), seed)
}

/// Restores a key from its 32-byte seed.
pub fn load_private_key(seed: &[u8; 32]) -> SigningKey<Params> {
    SigningKey::from_seed(&Seed::from(*seed))
}

/// Decodes a 1952-byte ML-DSA-65 public key.
pub fn load_public_key(bytes: &[u8]) -> Option<VerifyingKey<Params>> {
    EncodedVerifyingKey::<Params>::try_from(bytes)
        .ok()
        .map(|enc| VerifyingKey::decode(&enc))
}

/// Signs `r`. Signing is hedged (randomised), so two signatures over the same
/// request differ; both verify.
pub fn sign(sk: &SigningKey<Params>, r: &Request) -> Vec<u8> {
    sk.expanded_key()
        .sign_randomized(&r.message(), CONTEXT, &mut SysRng)
        .expect("context is under 255 bytes and the system RNG works")
        .encode()
        .to_vec()
}

/// Checks signed requests against a set of trusted public keys.
pub struct Verifier {
    /// This receiver's own identity. It replaces whatever audience the
    /// request carries.
    pub audience: String,
    pub keys: HashMap<String, VerifyingKey<Params>>,
    pub max_skew: Duration,
}

impl Verifier {
    /// Checks the key ID, the timestamp window against `now` (Unix seconds),
    /// then the signature over `r` with `self.audience` in place of
    /// `r.audience`. It does not detect a replay to this receiver inside the
    /// window; pair it with a nonce or idempotency-key cache if requests are
    /// not idempotent.
    pub fn verify_at(&self, r: &Request, sig: &[u8], now: i64) -> Result<(), VerifyError> {
        if self.audience.is_empty() {
            return Err(VerifyError::NoAudience);
        }
        let r = Request {
            audience: &self.audience,
            ..*r
        };
        let pk = self.keys.get(r.key_id).ok_or(VerifyError::UnknownKey)?;
        if now.abs_diff(r.timestamp) > self.max_skew.as_secs() {
            return Err(VerifyError::Stale);
        }
        let sig = Signature::<Params>::try_from(sig).map_err(|_| VerifyError::Signature)?;
        if pk.verify_with_context(&r.message(), CONTEXT, &sig) {
            Ok(())
        } else {
            Err(VerifyError::Signature)
        }
    }

    pub fn verify(&self, r: &Request, sig: &[u8]) -> Result<(), VerifyError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs() as i64;
        self.verify_at(r, sig, now)
    }
}
