//! Pattern KX-03: encrypting a message or data key to a recipient's public
//! key with HPKE (RFC 9180) using the hybrid post-quantum KEM
//! ML-KEM-768 + X25519 (X-Wing, draft-ietf-hpke-pq).
//!
//! Ciphersuite: KEM 0x647a (MLKEM768-X25519), KDF 0x0001 (HKDF-SHA256),
//! AEAD 0x0002 (AES-256-GCM). Wire format, shared by every language in this
//! repo:
//!
//! ```text
//! suite (6 bytes: KEM ID || KDF ID || AEAD ID, big-endian) || enc (1120 bytes) || ciphertext || tag
//! ```

use hpke_rs::{Hpke, HpkePrivateKey, HpkePublicKey, Mode};
use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
use hpke_rs_libcrux::HpkeLibcrux;

pub const KEM_ID: u16 = 0x647a;
pub const KDF_ID: u16 = 0x0001;
pub const AEAD_ID: u16 = 0x0002;
/// ML-KEM-768 ciphertext (1088 bytes) followed by the X25519 share (32 bytes).
pub const ENC_LEN: usize = 1120;
const SUITE_LEN: usize = 6;

#[derive(Debug, PartialEq, Eq)]
pub struct OpenError;

fn hpke() -> Hpke<HpkeLibcrux> {
    Hpke::new(
        Mode::Base,
        KemAlgorithm::XWingDraft06,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::Aes256Gcm,
    )
}

fn suite() -> [u8; SUITE_LEN] {
    let mut s = [0u8; SUITE_LEN];
    s[0..2].copy_from_slice(&KEM_ID.to_be_bytes());
    s[2..4].copy_from_slice(&KDF_ID.to_be_bytes());
    s[4..6].copy_from_slice(&AEAD_ID.to_be_bytes());
    s
}

/// Creates a recipient key pair: a 32-byte private seed to keep in a secret
/// store and a 1216-byte public key to publish.
pub fn generate_key() -> (HpkePrivateKey, HpkePublicKey) {
    hpke()
        .generate_key_pair()
        .expect("key generation failed")
        .into_keys()
}

pub fn load_private_key(seed: &[u8]) -> HpkePrivateKey {
    HpkePrivateKey::new(seed.to_vec())
}

pub fn load_public_key(bytes: &[u8]) -> HpkePublicKey {
    HpkePublicKey::new(bytes.to_vec())
}

/// Encrypts `plaintext` to `recipient`. `info` names the application and
/// purpose (for example `billing-exports/v1`) and must match on open. `aad`
/// is authenticated but not encrypted, for example a record ID.
pub fn seal(recipient: &HpkePublicKey, info: &[u8], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let (enc, ct) = hpke()
        .seal(recipient, info, aad, plaintext, None, None, None)
        .expect("HPKE seal failed");
    let mut out = Vec::with_capacity(SUITE_LEN + enc.len() + ct.len());
    out.extend_from_slice(&suite());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ct);
    out
}

/// Decrypts a message produced by `seal` in any language in this repo.
pub fn open(recipient: &HpkePrivateKey, info: &[u8], aad: &[u8], msg: &[u8]) -> Result<Vec<u8>, OpenError> {
    if msg.len() < SUITE_LEN + ENC_LEN || msg[..SUITE_LEN] != suite() {
        return Err(OpenError);
    }
    let (enc, ct) = msg[SUITE_LEN..].split_at(ENC_LEN);
    hpke()
        .open(enc, recipient, info, aad, ct, None, None, None)
        .map_err(|_| OpenError)
}
