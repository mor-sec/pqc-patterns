//! Pattern HASH-02: deriving separate, purpose-bound keys from one secret
//! with HKDF-SHA-256 (RFC 5869).
//!
//! The HKDF info input is a length-prefixed encoding of
//! `"pqc-patterns/hash-02/v1", purpose, context, output length (u16)`, so two
//! purposes, two contexts or two output lengths never share key material.
//! Without the length, a 16-byte key would be the first half of the 32-byte
//! key for the same purpose.

use aws_lc_rs::hkdf::{HKDF_SHA256, KeyType, Salt};

const LABEL: &[u8] = b"pqc-patterns/hash-02/v1";
/// The smallest input secret accepted: 256 bits.
pub const MIN_SECRET_LEN: usize = 32;
/// HKDF-SHA-256's output limit, 255 * 32 bytes.
pub const MAX_KEY_LEN: usize = 255 * 32;

#[derive(Debug, PartialEq, Eq)]
pub struct InputError;

/// The exact HKDF info bytes for `purpose`, `context` and `key_len`.
pub fn info(purpose: &str, context: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    for f in [LABEL, purpose.as_bytes(), context] {
        let len = u32::try_from(f.len()).expect("info field of 4 GiB or more");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(f);
    }
    let len = u16::try_from(key_len).expect("key length checked by derive");
    out.extend_from_slice(&len.to_be_bytes());
    out
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

/// Returns a `key_len`-byte key for `purpose`, such as
/// `"billing-exports/aes-256-gcm/v1"`. `context` binds the key to an instance,
/// such as a tenant ID, and may be empty. `salt` may be empty when `secret`
/// is already uniformly random (a KMS data key or an ML-KEM shared secret);
/// otherwise use a fixed, non-secret, random value per application.
pub fn derive(
    secret: &[u8],
    salt: &[u8],
    purpose: &str,
    context: &[u8],
    key_len: usize,
) -> Result<Vec<u8>, InputError> {
    if secret.len() < MIN_SECRET_LEN || purpose.is_empty() || !(16..=MAX_KEY_LEN).contains(&key_len) {
        return Err(InputError);
    }
    let info = info(purpose, context, key_len);
    let info = [info.as_slice()];
    let prk = Salt::new(HKDF_SHA256, salt).extract(secret);
    let okm = prk.expand(&info, Len(key_len)).map_err(|_| InputError)?;
    let mut out = vec![0u8; key_len];
    okm.fill(&mut out).map_err(|_| InputError)?;
    Ok(out)
}
