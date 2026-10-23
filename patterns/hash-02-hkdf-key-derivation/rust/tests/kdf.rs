use hash_02_hkdf_key_derivation::*;

const SECRET: [u8; 32] = [0x0b; 32];
const PURPOSE: &str = "billing-exports/aes-256-gcm/v1";

#[test]
fn separation() {
    let base = derive(&SECRET, b"", PURPOSE, b"tenant-42", 32).unwrap();
    for other in [
        derive(&SECRET, b"", "billing-exports/hmac-sha256/v1", b"tenant-42", 32),
        derive(&SECRET, b"", PURPOSE, b"tenant-43", 32),
        derive(&SECRET, b"salt", PURPOSE, b"tenant-42", 32),
        derive(&SECRET, b"", "billing-exports/aes-256-gcm/v1t", b"enant-42", 32),
    ] {
        assert_ne!(other.unwrap(), base);
    }
    let short = derive(&SECRET, b"", PURPOSE, b"tenant-42", 16).unwrap();
    assert_ne!(short, base[..16]);
}

#[test]
fn rejects_bad_input() {
    assert_eq!(derive(&SECRET[..31], b"", "p", b"", 32), Err(InputError));
    assert_eq!(derive(&SECRET, b"", "", b"", 32), Err(InputError));
    assert_eq!(derive(&SECRET, b"", "p", b"", 8), Err(InputError));
    assert_eq!(derive(&SECRET, b"", "p", b"", MAX_KEY_LEN + 1), Err(InputError));
}

#[derive(serde::Deserialize)]
struct Vector {
    secret: String,
    salt: String,
    purpose: String,
    context: String,
    key_len: usize,
    info: String,
    key: String,
}

#[test]
fn cross_language_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let v: Vector = serde_json::from_str(&raw).unwrap();
    let h = |s: &str| hex::decode(s).unwrap();
    assert_eq!(hex::encode(info(&v.purpose, &h(&v.context), v.key_len)), v.info);
    let k = derive(&h(&v.secret), &h(&v.salt), &v.purpose, &h(&v.context), v.key_len).unwrap();
    assert_eq!(hex::encode(k), v.key);
}
