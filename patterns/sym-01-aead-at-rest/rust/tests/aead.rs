use std::collections::HashSet;

use sym_01_aead_at_rest::{KeyError, Keyring, new_key};

#[test]
fn round_trip() {
    let k = Keyring::new(1, &new_key()).unwrap();
    let ad = b"customers/42/payment_method";
    let blob = k.encrypt(b"card ending 4242", ad);
    assert_eq!(k.decrypt(&blob, ad).unwrap(), b"card ending 4242");
}

#[test]
fn rejects_tampering() {
    let k = Keyring::new(1, &new_key()).unwrap();
    let ad = b"customers/42";
    let blob = k.encrypt(b"secret", ad);
    for i in 0..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 1;
        assert!(k.decrypt(&bad, ad).is_err(), "flipping byte {i} was not detected");
    }
    assert!(k.decrypt(&blob, b"customers/43").is_err());
    assert!(k.decrypt(&blob[..blob.len() - 1], ad).is_err());
}

#[test]
fn rotation() {
    let mut k = Keyring::new(1, &new_key()).unwrap();
    let old = k.encrypt(b"v1 data", b"");
    k.add(2, &new_key()).unwrap();
    k.rotate(2).unwrap();
    let fresh = k.encrypt(b"v2 data", b"");
    assert_eq!(fresh[4], 2);
    assert_eq!(k.decrypt(&old, b"").unwrap(), b"v1 data");
}

#[test]
fn rejects_short_key() {
    assert_eq!(Keyring::new(1, &[0u8; 16]).err(), Some(KeyError::WrongLength(16)));
}

#[test]
fn nonces_are_unique() {
    let k = Keyring::new(1, &new_key()).unwrap();
    let mut seen = HashSet::new();
    for _ in 0..1000 {
        let blob = k.encrypt(b"x", b"");
        assert!(seen.insert(blob[5..17].to_vec()), "nonce reused");
    }
}

#[derive(serde::Deserialize)]
struct Vector {
    key_id: u32,
    key: String,
    associated_data: String,
    plaintext: String,
    blob: String,
}

#[test]
fn cross_language_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let v: Vector = serde_json::from_str(&raw).unwrap();
    let k = Keyring::new(v.key_id, &hex::decode(v.key).unwrap()).unwrap();
    let pt = k
        .decrypt(
            &hex::decode(v.blob).unwrap(),
            &hex::decode(v.associated_data).unwrap(),
        )
        .unwrap();
    assert_eq!(pt, hex::decode(v.plaintext).unwrap());
}
