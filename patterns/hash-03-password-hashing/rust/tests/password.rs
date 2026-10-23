use argon2::{Algorithm, Argon2, Version};
use base64ct::{Base64Unpadded, Encoding};
use hash_03_password_hashing::*;

const FAST: Params = Params {
    memory_kib: 8 * 1024,
    time: 1,
    threads: 1,
};
const PW: &[u8] = b"correct horse battery staple";

#[test]
fn round_trip() {
    let h = hash(PW, FAST).unwrap();
    assert!(h.starts_with("$argon2id$v=19$m=8192,t=1,p=1$"));
    assert_eq!(verify(PW, &h, FAST), Ok(false));
    assert_eq!(
        verify(b"Correct horse battery staple", &h, FAST),
        Err(Error::Mismatch)
    );
    assert_ne!(hash(PW, FAST).unwrap(), h, "salt is not fresh");
}

#[test]
fn needs_rehash() {
    let h = hash(PW, FAST).unwrap();
    let newer = Params {
        memory_kib: 16 * 1024,
        time: 2,
        threads: 1,
    };
    assert_eq!(verify(PW, &h, newer), Ok(true));
}

#[test]
fn rejects_malformed() {
    let good = hash(PW, FAST).unwrap();
    let f: Vec<&str> = good.split('$').collect();
    let short_salt = [
        "",
        f[1],
        f[2],
        f[3],
        &Base64Unpadded::encode_string(b"short"),
        f[5],
    ]
    .join("$");
    let short_hash = ["", f[1], f[2], f[3], f[4], &f[5][..20]].join("$");
    for bad in [
        good.replace("argon2id", "argon2i"),
        good.replace("v=19", "v=16"),
        good.replace("m=8192", "m=08192"),
        good.replace("m=8192", "m=+8192"),
        good.replace("m=8192,t=1,p=1", "t=1,m=8192,p=1"),
        good.replace("m=8192", "m=4194304"),
        good.replace("p=1", "p=0"),
        short_salt,
        format!("{good}="),
        short_hash,
        "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW".to_string(),
        String::new(),
        format!("{good}$x"),
    ] {
        assert_eq!(verify(PW, &bad, FAST), Err(Error::Format), "{bad}");
    }
}

#[test]
fn argon2id_known_answer() {
    let p = argon2::Params::new(64 * 1024, 2, 1, Some(32)).unwrap();
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(b"password", b"somesalt", &mut out)
        .unwrap();
    assert_eq!(
        Base64Unpadded::encode_string(&out),
        "CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc"
    );
}

#[derive(serde::Deserialize)]
struct Vector {
    password: String,
    phc: String,
}

#[test]
fn cross_language_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let v: Vector = serde_json::from_str(&raw).unwrap();
    assert_eq!(verify(v.password.as_bytes(), &v.phc, FAST), Ok(false));
}
