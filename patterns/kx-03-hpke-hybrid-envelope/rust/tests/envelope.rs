use kx_03_hpke_hybrid_envelope::*;

const INFO: &[u8] = b"pqc-patterns/kx-03/test";

#[test]
fn round_trip() {
    let (sk, pk) = generate_key();
    assert_eq!(pk.as_slice().len(), 1216);
    let msg = seal(&pk, INFO, b"export-17", b"quarterly-report.csv data key");
    assert_eq!(
        open(&sk, INFO, b"export-17", &msg).unwrap(),
        b"quarterly-report.csv data key"
    );
}

#[test]
fn rejects_tampering() {
    let (sk, pk) = generate_key();
    let msg = seal(&pk, INFO, b"", b"secret");
    for i in [0, 6, 6 + 1087, 6 + 1088, 6 + ENC_LEN, msg.len() - 1] {
        let mut bad = msg.clone();
        bad[i] ^= 1;
        assert!(
            open(&sk, INFO, b"", &bad).is_err(),
            "flipping byte {i} was not detected"
        );
    }
    assert!(open(&sk, b"other/app", b"", &msg).is_err());
    assert!(open(&sk, INFO, b"x", &msg).is_err());
    let (other, _) = generate_key();
    assert!(open(&other, INFO, b"", &msg).is_err());
}

#[derive(serde::Deserialize)]
struct Vector {
    private_key: String,
    public_key: String,
    info: String,
    aad: String,
    plaintext: String,
    message: String,
}

fn vector() -> Vector {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn opens_go_vector() {
    let v = vector();
    let h = |s: &str| hex::decode(s).unwrap();
    let sk = load_private_key(&h(&v.private_key)).unwrap();
    assert_eq!(
        open(&sk, &h(&v.info), &h(&v.aad), &h(&v.message)).unwrap(),
        h(&v.plaintext)
    );
}

#[test]
fn seals_to_go_vector_key() {
    // Encrypt to the vector's public key, then open with its private key: proves
    // this crate's encapsulation matches the key format other languages publish.
    let v = vector();
    let h = |s: &str| hex::decode(s).unwrap();
    let msg = seal(
        &load_public_key(&h(&v.public_key)).unwrap(),
        INFO,
        b"",
        b"rust to anyone",
    );
    assert_eq!(
        open(&load_private_key(&h(&v.private_key)).unwrap(), INFO, b"", &msg).unwrap(),
        b"rust to anyone"
    );
}

#[test]
fn rejects_wrong_key_lengths() {
    assert!(load_public_key(&[0u8; PUBLIC_KEY_LEN - 1]).is_none());
    assert!(load_private_key(&[0u8; 64]).is_none());
}
