//! Pattern SYM-01: authenticated encryption at rest with AES-256-GCM,
//! versioned key IDs for rotation, and caller-bound associated data.
//!
//! Wire format, shared by every language in this repo:
//!
//! ```text
//! version (1 byte, 0x01) || key ID (4 bytes, big-endian) || nonce (12 bytes) || ciphertext || tag (16 bytes)
//! ```
//!
//! The 5-byte header and the caller's associated data are both authenticated.

use std::collections::HashMap;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

pub const VERSION: u8 = 0x01;
/// AES-256 keeps 128-bit security even against Grover's algorithm.
pub const KEY_SIZE: usize = 32;
const HEADER_LEN: usize = 5;
const TAG_LEN: usize = 16;
const OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN;

/// Returned for every authentication or format failure, so callers cannot
/// learn why a ciphertext was rejected.
#[derive(Debug, PartialEq, Eq)]
pub struct DecryptError;

#[derive(Debug, PartialEq, Eq)]
pub enum KeyError {
    WrongLength(usize),
    Duplicate(u32),
    Unknown(u32),
}

/// The active key used for new encryptions plus older keys that may still be
/// needed to decrypt existing data during rotation.
pub struct Keyring {
    active_id: u32,
    keys: HashMap<u32, LessSafeKey>,
    rng: SystemRandom,
}

impl Keyring {
    pub fn new(id: u32, key: &[u8]) -> Result<Self, KeyError> {
        let mut k = Keyring {
            active_id: id,
            keys: HashMap::new(),
            rng: SystemRandom::new(),
        };
        k.add(id, key)?;
        Ok(k)
    }

    /// Registers a decrypt-only key. Call [`Keyring::rotate`] to make it active.
    pub fn add(&mut self, id: u32, key: &[u8]) -> Result<(), KeyError> {
        if key.len() != KEY_SIZE {
            return Err(KeyError::WrongLength(key.len()));
        }
        if self.keys.contains_key(&id) {
            return Err(KeyError::Duplicate(id));
        }
        let unbound = UnboundKey::new(&AES_256_GCM, key).map_err(|_| KeyError::WrongLength(key.len()))?;
        self.keys.insert(id, LessSafeKey::new(unbound));
        Ok(())
    }

    /// Makes an already-added key the active key for new encryptions.
    pub fn rotate(&mut self, id: u32) -> Result<(), KeyError> {
        if !self.keys.contains_key(&id) {
            return Err(KeyError::Unknown(id));
        }
        self.active_id = id;
        Ok(())
    }

    /// Seals `plaintext` under the active key. `associated_data` binds the
    /// ciphertext to its context (for example a table name and row ID).
    ///
    /// Nonces are random, so one key must not encrypt more than 2^32
    /// messages. Rotate well before that.
    pub fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> Vec<u8> {
        let key = &self.keys[&self.active_id];
        let mut out = Vec::with_capacity(OVERHEAD + plaintext.len());
        out.push(VERSION);
        out.extend_from_slice(&self.active_id.to_be_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        self.rng.fill(&mut nonce).expect("system RNG failed");
        out.extend_from_slice(&nonce);

        let mut body = plaintext.to_vec();
        let aad = aad(&out[..HEADER_LEN], associated_data);
        key.seal_in_place_append_tag(Nonce::assume_unique_for_key(nonce), Aad::from(aad), &mut body)
            .expect("AES-GCM seal failed");
        out.extend_from_slice(&body);
        out
    }

    /// Verifies and opens a blob produced by `encrypt` in any language.
    pub fn decrypt(&self, blob: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, DecryptError> {
        if blob.len() < OVERHEAD || blob[0] != VERSION {
            return Err(DecryptError);
        }
        let id = u32::from_be_bytes(blob[1..HEADER_LEN].try_into().unwrap());
        let key = self.keys.get(&id).ok_or(DecryptError)?;
        let nonce = Nonce::try_assume_unique_for_key(&blob[HEADER_LEN..HEADER_LEN + NONCE_LEN])
            .map_err(|_| DecryptError)?;
        let mut body = blob[HEADER_LEN + NONCE_LEN..].to_vec();
        let aad = aad(&blob[..HEADER_LEN], associated_data);
        let pt = key
            .open_in_place(nonce, Aad::from(aad), &mut body)
            .map_err(|_| DecryptError)?;
        Ok(pt.to_vec())
    }
}

/// A fresh random 256-bit key. In production, generate and hold keys in a
/// KMS or HSM instead (pattern KEY-02).
pub fn new_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    SystemRandom::new().fill(&mut key).expect("system RNG failed");
    key
}

/// Authenticates the header and the caller's context together. The caller's
/// data is length-prefixed so different splits cannot collide.
fn aad(header: &[u8], associated_data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + 4 + associated_data.len());
    out.extend_from_slice(header);
    let len = u32::try_from(associated_data.len()).expect("associated data of 4 GiB or more");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(associated_data);
    out
}
