//! Pattern SYM-03: encrypting files and streams of any size with AES-256-GCM
//! in fixed-size authenticated segments, so memory use stays constant and
//! truncation, reordering and appending are detected.
//!
//! Wire format, shared by every language in this repo:
//!
//! ```text
//! header:   version (1 byte, 0x01) || salt (32 bytes) || nonce prefix (7 bytes)
//! segments: ciphertext || tag (16 bytes), repeated
//! ```
//!
//! Each stream gets its own AES-256 key:
//! `HKDF-SHA-256(ikm = master key, salt = salt, info = "pqc-patterns/sym-03/v1" || associated data)`.
//! Segment `i` uses the nonce `prefix || i (u32, big-endian) || last (0x01 on
//! the final segment, else 0x00)`. Every segment holds exactly
//! [`SEGMENT_SIZE`] bytes of plaintext except the last, which holds 0 to
//! [`SEGMENT_SIZE`] bytes.

use std::fmt;
use std::io::{self, ErrorKind, Read, Write};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

pub const VERSION: u8 = 0x01;
/// AES-256 keeps 128-bit security even against Grover's algorithm.
pub const KEY_SIZE: usize = 32;
pub const SEGMENT_SIZE: usize = 64 * 1024;
pub const SALT_SIZE: usize = 32;
pub const PREFIX_SIZE: usize = 7;
pub const HEADER_SIZE: usize = 1 + SALT_SIZE + PREFIX_SIZE;
pub const TAG_SIZE: usize = 16;
const LABEL: &[u8] = b"pqc-patterns/sym-03/v1";

#[derive(Debug)]
pub enum Error {
    /// Every authentication or format failure, so callers cannot learn why a
    /// stream was rejected.
    Decrypt,
    /// The input would need more than 2^32 segments (256 TiB).
    TooLong,
    KeyLength(usize),
    /// A read or write error from the caller's reader or writer.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Decrypt => write!(f, "stream: decryption failed"),
            Error::TooLong => write!(f, "stream: input exceeds 2^32 segments"),
            Error::KeyLength(n) => write!(f, "stream: key must be {KEY_SIZE} bytes, got {n}"),
            Error::Io(e) => write!(f, "stream: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

/// Returns a fresh random 256-bit master key. In production, generate and
/// hold keys in a KMS or HSM instead (see pattern KEY-02).
pub fn new_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    SystemRandom::new().fill(&mut key).expect("system RNG failed");
    key
}

/// Reads `src` to the end and writes the encrypted stream to `dst`, holding
/// at most one segment in memory. `associated_data` binds the stream to its
/// context (for example a bucket and object name).
pub fn encrypt(src: impl Read, dst: impl Write, key: &[u8], associated_data: &[u8]) -> Result<(), Error> {
    let mut salt = [0u8; SALT_SIZE];
    let mut prefix = [0u8; PREFIX_SIZE];
    let rng = SystemRandom::new();
    rng.fill(&mut salt).expect("system RNG failed");
    rng.fill(&mut prefix).expect("system RNG failed");
    encrypt_with_header(src, dst, key, associated_data, &salt, &prefix)
}

fn encrypt_with_header(
    mut src: impl Read,
    mut dst: impl Write,
    key: &[u8],
    associated_data: &[u8],
    salt: &[u8; SALT_SIZE],
    prefix: &[u8; PREFIX_SIZE],
) -> Result<(), Error> {
    let cipher = stream_cipher(key, salt, associated_data)?;
    dst.write_all(&[VERSION])?;
    dst.write_all(salt)?;
    dst.write_all(prefix)?;

    // Reading one byte past a full segment tells us whether more follow.
    let mut buf = vec![0u8; SEGMENT_SIZE + 1];
    let mut n = 0;
    for i in 0u64.. {
        n += read_full(&mut src, &mut buf[n..])?;
        let last = n <= SEGMENT_SIZE;
        if !last && i == u32::MAX as u64 {
            return Err(Error::TooLong);
        }
        let size = if last { n } else { SEGMENT_SIZE };
        let tag = cipher
            .seal_in_place_separate_tag(nonce(prefix, i as u32, last), Aad::empty(), &mut buf[..size])
            .expect("AES-GCM seal failed");
        dst.write_all(&buf[..size])?;
        dst.write_all(tag.as_ref())?;
        if last {
            break;
        }
        buf[0] = buf[SEGMENT_SIZE];
        n = 1;
    }
    Ok(())
}

/// Reads an encrypted stream from `src` and writes the plaintext to `dst`.
///
/// Each segment is authenticated before it is written, but a truncated
/// stream is only detected at the end. Until this returns `Ok`, treat
/// everything written to `dst` as untrusted: write to a temporary file and
/// rename it into place only on success.
pub fn decrypt(
    mut src: impl Read,
    mut dst: impl Write,
    key: &[u8],
    associated_data: &[u8],
) -> Result<(), Error> {
    let mut header = [0u8; HEADER_SIZE];
    if read_full(&mut src, &mut header)? < HEADER_SIZE || header[0] != VERSION {
        return Err(Error::Decrypt);
    }
    let salt: &[u8; SALT_SIZE] = header[1..1 + SALT_SIZE].try_into().unwrap();
    let prefix: &[u8; PREFIX_SIZE] = header[1 + SALT_SIZE..].try_into().unwrap();
    let cipher = stream_cipher(key, salt, associated_data)?;

    const SEG_LEN: usize = SEGMENT_SIZE + TAG_SIZE;
    let mut buf = vec![0u8; SEG_LEN + 1];
    let mut n = 0;
    for i in 0u64.. {
        n += read_full(&mut src, &mut buf[n..])?;
        let last = n <= SEG_LEN;
        if i > u32::MAX as u64 {
            return Err(Error::Decrypt);
        }
        let size = if last { n } else { SEG_LEN };
        if size < TAG_SIZE {
            return Err(Error::Decrypt);
        }
        let plaintext = cipher
            .open_in_place(nonce(prefix, i as u32, last), Aad::empty(), &mut buf[..size])
            .map_err(|_| Error::Decrypt)?;
        dst.write_all(plaintext)?;
        if last {
            break;
        }
        buf[0] = buf[SEG_LEN];
        n = 1;
    }
    Ok(())
}

fn stream_cipher(key: &[u8], salt: &[u8], associated_data: &[u8]) -> Result<LessSafeKey, Error> {
    if key.len() != KEY_SIZE {
        return Err(Error::KeyLength(key.len()));
    }
    let info = [LABEL, associated_data];
    let prk = Salt::new(HKDF_SHA256, salt).extract(key);
    let okm = prk
        .expand(&info, &AES_256_GCM)
        .expect("HKDF output length is valid");
    Ok(LessSafeKey::new(UnboundKey::from(okm)))
}

fn nonce(prefix: &[u8; PREFIX_SIZE], i: u32, last: bool) -> Nonce {
    let mut n = [0u8; NONCE_LEN];
    n[..PREFIX_SIZE].copy_from_slice(prefix);
    n[PREFIX_SIZE..PREFIX_SIZE + 4].copy_from_slice(&i.to_be_bytes());
    n[NONCE_LEN - 1] = last as u8;
    Nonce::assume_unique_for_key(n)
}

/// Fills `buf` unless the reader ends first, and returns the bytes read.
fn read_full(src: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match src.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

#[cfg(test)]
mod vector {
    use super::*;
    use aws_lc_rs::digest::{SHA256, digest};

    #[derive(serde::Deserialize)]
    struct Vector {
        key: String,
        associated_data: String,
        salt: String,
        nonce_prefix: String,
        plaintext: String,
        ciphertext: String,
        large_plaintext_length: usize,
        large_ciphertext_sha256: String,
    }

    fn pattern(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

    /// The shared cross-language vector, generated by the Go implementation.
    #[test]
    fn matches_shared_vector() {
        let raw = std::fs::read_to_string("../testdata/vector.json").unwrap();
        let v: Vector = serde_json::from_str(&raw).unwrap();
        let key = hex::decode(&v.key).unwrap();
        let ad = hex::decode(&v.associated_data).unwrap();
        let salt: [u8; SALT_SIZE] = hex::decode(&v.salt).unwrap().try_into().unwrap();
        let prefix: [u8; PREFIX_SIZE] = hex::decode(&v.nonce_prefix).unwrap().try_into().unwrap();
        let seal = |pt: &[u8]| {
            let mut ct = Vec::new();
            encrypt_with_header(pt, &mut ct, &key, &ad, &salt, &prefix).unwrap();
            ct
        };

        let pt = hex::decode(&v.plaintext).unwrap();
        let ct = hex::decode(&v.ciphertext).unwrap();
        assert_eq!(seal(&pt), ct);
        let mut out = Vec::new();
        decrypt(&ct[..], &mut out, &key, &ad).unwrap();
        assert_eq!(out, pt);

        let large = pattern(v.large_plaintext_length);
        let large_ct = seal(&large);
        assert_eq!(hex::encode(digest(&SHA256, &large_ct)), v.large_ciphertext_sha256);
        let mut out = Vec::new();
        decrypt(&large_ct[..], &mut out, &key, &ad).unwrap();
        assert_eq!(out, large);
    }
}
