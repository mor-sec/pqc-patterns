//! Pattern SESS-02: signed bearer tokens (JWTs) with ML-DSA-65, as specified
//! for JOSE in RFC 9964.
//!
//! A token is a JWS in compact form:
//! `BASE64URL(header) "." BASE64URL(claims) "." BASE64URL(ML-DSA signature)`.
//! The verifier accepts exactly one algorithm and one token type, looks the
//! key up by `kid`, checks the signature before reading any claims, and then
//! requires the issuer, audience and lifetime it was configured with.

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use getrandom::SysRng;
use ml_dsa::{MlDsa65, Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The RFC 9964 JOSE algorithm name. Use ML-DSA-87 where CNSA 2.0 applies.
pub const ALG: &str = "ML-DSA-65";
/// The explicit token type (RFC 8725, section 3.11) for access tokens
/// (RFC 9068). Give each kind of token you issue its own type.
pub const TYPE: &str = "at+jwt";
pub const DEFAULT_LEEWAY: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_LIFETIME: Duration = Duration::from_secs(3600);

/// RFC 9964, section 5: the ML-DSA context string for JOSE is empty. JWS
/// gets its domain separation from the `typ` header instead.
const JOSE_CONTEXT: &[u8] = &[];

pub type Params = MlDsa65;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    Header,
    UnknownKey,
    Signature,
    Claims,
    Expired,
}

/// Only these three header parameters are accepted, so `crit`, `jku`, `x5u`
/// and embedded `jwk` keys are refused rather than ignored.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    alg: String,
    typ: String,
    kid: String,
}

/// The registered claims this pattern sets and checks. `aud` is always a
/// single string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Issues tokens under one key.
pub struct Signer {
    pub key_id: String,
    pub key: SigningKey<Params>,
}

impl Signer {
    /// Returns a compact JWS over `claims`. Signing is hedged (randomised).
    pub fn sign(&self, claims: &Claims) -> String {
        let header = Header {
            alg: ALG.into(),
            typ: TYPE.into(),
            kid: self.key_id.clone(),
        };
        let input = format!(
            "{}.{}",
            B64.encode(serde_json::to_vec(&header).expect("header serialises")),
            B64.encode(serde_json::to_vec(claims).expect("claims serialise"))
        );
        let sig = self
            .key
            .expanded_key()
            .sign_randomized(input.as_bytes(), JOSE_CONTEXT, &mut SysRng)
            .expect("the system RNG works");
        format!("{input}.{}", B64.encode(sig.encode()))
    }
}

/// Checks tokens against a set of trusted public keys.
pub struct Verifier {
    /// The only issuer accepted.
    pub issuer: String,
    /// This service's own identifier.
    pub audience: String,
    pub keys: HashMap<String, VerifyingKey<Params>>,
    pub leeway: Duration,
    pub max_lifetime: Duration,
}

impl Verifier {
    pub fn new(issuer: &str, audience: &str, keys: HashMap<String, VerifyingKey<Params>>) -> Self {
        Verifier {
            issuer: issuer.into(),
            audience: audience.into(),
            keys,
            leeway: DEFAULT_LEEWAY,
            max_lifetime: DEFAULT_MAX_LIFETIME,
        }
    }

    /// Checks `token` against `now` (Unix seconds) and returns its claims.
    pub fn verify_at(&self, token: &str, now: i64) -> Result<Claims, VerifyError> {
        if self.issuer.is_empty() || self.audience.is_empty() {
            return Err(VerifyError::Claims);
        }
        let parts: Vec<&str> = token.split('.').collect();
        let [h, p, s] = parts[..] else {
            return Err(VerifyError::Malformed);
        };
        let decode = |x: &str| B64.decode(x).map_err(|_| VerifyError::Malformed);
        let (hb, pb, sb) = (decode(h)?, decode(p)?, decode(s)?);

        let header: Header = serde_json::from_slice(&hb).map_err(|_| VerifyError::Malformed)?;
        if header.alg != ALG || header.typ != TYPE {
            return Err(VerifyError::Header);
        }
        let pk = self.keys.get(&header.kid).ok_or(VerifyError::UnknownKey)?;
        let sig = Signature::<Params>::try_from(sb.as_slice()).map_err(|_| VerifyError::Signature)?;
        let input = &token[..h.len() + 1 + p.len()];
        if !pk.verify_with_context(input.as_bytes(), JOSE_CONTEXT, &sig) {
            return Err(VerifyError::Signature);
        }

        let c: Claims = serde_json::from_slice(&pb).map_err(|_| VerifyError::Malformed)?;
        if c.iss != self.issuer || c.aud != self.audience {
            return Err(VerifyError::Claims);
        }
        let leeway = self.leeway.as_secs() as i64;
        let lifetime = (c.exp as i128) - (c.iat as i128);
        if c.iat == 0
            || c.exp == 0
            || now >= c.exp.saturating_add(leeway)
            || now.saturating_add(leeway) < c.iat
            || lifetime > self.max_lifetime.as_secs() as i128
        {
            return Err(VerifyError::Expired);
        }
        Ok(c)
    }

    pub fn verify(&self, token: &str) -> Result<Claims, VerifyError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before 1970")
            .as_secs() as i64;
        self.verify_at(token, now)
    }
}
