//! Pattern HASH-01: self-describing content digests and full-length HMAC
//! tags.
//!
//! Digests use the Subresource Integrity format, `<alg>-<base64>`, such as
//! `sha384-ywB1P0Wj...`. The algorithm travels with the value, so a verifier
//! can raise its minimum later without changing the format. The default is
//! SHA-384: it meets CNSA 2.0, is not open to length extension, and runs at
//! SHA-512 speed on 64-bit hardware.
//!
//! MACs are HMAC-SHA-384 with a key of at least 32 bytes, compared in
//! constant time and never truncated. Derive one MAC key per purpose with
//! pattern HASH-02 rather than reusing a key across purposes.

use std::io::{self, Read};

use aws_lc_rs::{digest, hmac};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Sha256,
    Sha384,
    Sha512,
}

impl Alg {
    /// The Subresource Integrity name, such as `sha384`.
    pub fn name(self) -> &'static str {
        match self {
            Alg::Sha256 => "sha256",
            Alg::Sha384 => "sha384",
            Alg::Sha512 => "sha512",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        [Alg::Sha256, Alg::Sha384, Alg::Sha512]
            .into_iter()
            .find(|a| a.name() == name)
    }

    fn algorithm(self) -> &'static digest::Algorithm {
        match self {
            Alg::Sha256 => &digest::SHA256,
            Alg::Sha384 => &digest::SHA384,
            Alg::Sha512 => &digest::SHA512,
        }
    }
}

/// The algorithm [`sum`] uses.
pub const DEFAULT: Alg = Alg::Sha384;
/// Accepts SHA-384 and SHA-512 only. Use it for new data.
pub const STRONG: &[Alg] = &[Alg::Sha384, Alg::Sha512];
/// Also accepts SHA-256, for digests written by older systems. SHA-256 is
/// not broken; it is below the CNSA 2.0 bar.
pub const COMPATIBLE: &[Alg] = &[Alg::Sha256, Alg::Sha384, Alg::Sha512];

/// The shortest HMAC key accepted.
pub const MIN_KEY_LEN: usize = 32;
/// The length of an HMAC-SHA-384 tag. Shorter tags are refused.
pub const TAG_LEN: usize = 48;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The digest string is malformed.
    Format,
    /// The algorithm is unknown or not allowed by the policy.
    Algorithm,
    /// The digest or tag does not match.
    Mismatch,
    /// The HMAC key is shorter than [`MIN_KEY_LEN`].
    Key,
}

fn format(alg: Alg, sum: &[u8]) -> String {
    format!("{}-{}", alg.name(), STANDARD.encode(sum))
}

/// The digest of `data` under `alg`. Use [`sum`] unless you need another
/// algorithm for compatibility.
pub fn sum_with(alg: Alg, data: &[u8]) -> String {
    format(alg, digest::digest(alg.algorithm(), data).as_ref())
}

/// The SHA-384 digest of `data` in `sha384-<base64>` form.
pub fn sum(data: &[u8]) -> String {
    sum_with(DEFAULT, data)
}

/// [`sum`] for data that does not fit in memory, such as a file.
pub fn sum_reader(mut r: impl Read) -> io::Result<String> {
    let mut ctx = digest::Context::new(DEFAULT.algorithm());
    let mut buf = [0u8; 64 * 1024];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => ctx.update(&buf[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(format(DEFAULT, ctx.finish().as_ref()))
}

/// Checks that `integrity` is a well-formed digest of `data` under an
/// algorithm `policy` allows. MD5 and SHA-1 are never accepted.
pub fn check(integrity: &str, data: &[u8], policy: &[Alg]) -> Result<(), Error> {
    let (name, b64) = integrity.split_once('-').ok_or(Error::Format)?;
    let alg = Alg::from_name(name)
        .filter(|a| policy.contains(a))
        .ok_or(Error::Algorithm)?;
    let want = STANDARD.decode(b64).map_err(|_| Error::Format)?;
    // Re-encoding catches non-canonical forms, so each digest has one spelling.
    if want.len() != alg.algorithm().output_len() || STANDARD.encode(&want) != b64 {
        return Err(Error::Format);
    }
    if digest::digest(alg.algorithm(), data).as_ref() != want.as_slice() {
        return Err(Error::Mismatch);
    }
    Ok(())
}

fn hmac_key(key: &[u8]) -> Result<hmac::Key, Error> {
    if key.len() < MIN_KEY_LEN {
        return Err(Error::Key);
    }
    Ok(hmac::Key::new(hmac::HMAC_SHA384, key))
}

/// The HMAC-SHA-384 of `msg` under `key`.
pub fn tag(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(hmac::sign(&hmac_key(key)?, msg).as_ref().to_vec())
}

/// Checks `tag` against `msg` in constant time. A tag of any length other
/// than [`TAG_LEN`] is refused, so a truncated tag cannot be accepted.
pub fn verify(key: &[u8], msg: &[u8], tag: &[u8]) -> Result<(), Error> {
    let key = hmac_key(key)?;
    if tag.len() != TAG_LEN {
        return Err(Error::Mismatch);
    }
    hmac::verify(&key, msg, tag).map_err(|_| Error::Mismatch)
}
