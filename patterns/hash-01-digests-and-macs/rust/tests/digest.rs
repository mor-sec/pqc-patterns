use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use hash_01_digests_and_macs::*;

const ABC_SHA384: &str =
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";

#[test]
fn sum_known_answer() {
    // FIPS 180-4 example value for "abc".
    let raw = hex::decode(ABC_SHA384).unwrap();
    assert_eq!(sum(b"abc"), format!("sha384-{}", STANDARD.encode(raw)));
    assert_eq!(sum_reader(&b"abc"[..]).unwrap(), sum(b"abc"));
}

#[test]
fn check_rejects() {
    let good = sum(b"abc");
    assert_eq!(check(&good, b"abc", STRONG), Ok(()));
    assert_eq!(check(&good, b"abd", STRONG), Err(Error::Mismatch));
    let old = sum_with(Alg::Sha256, b"abc");
    assert_eq!(check(&old, b"abc", COMPATIBLE), Ok(()));
    assert_eq!(check(&old, b"abc", STRONG), Err(Error::Algorithm));
    assert_eq!(
        check("md5-kAFQmDzST7DWlj99KOF/cg==", b"abc", COMPATIBLE),
        Err(Error::Algorithm)
    );
    assert_eq!(
        check(&good.replacen('-', "", 1), b"abc", STRONG),
        Err(Error::Format)
    );
    assert_eq!(check(&good[..good.len() - 8], b"abc", STRONG), Err(Error::Format));
    assert_eq!(check(&format!("{good}="), b"abc", STRONG), Err(Error::Format));
    let url = good.replace('+', "-").replace('/', "_");
    assert_ne!(check(&url, b"abc", STRONG), Ok(()));
}

#[test]
fn tag_known_answer() {
    // RFC 4231 test case 6: a 131-byte key, larger than the hash block.
    let key = [0xaa; 131];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let t = tag(&key, msg).unwrap();
    assert_eq!(
        hex::encode(&t),
        "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"
    );
    assert_eq!(verify(&key, msg, &t), Ok(()));
    let mut flipped = t.clone();
    flipped[0] ^= 1;
    assert_eq!(verify(&key, msg, &flipped), Err(Error::Mismatch));
    assert_eq!(verify(&key, b"other", &t), Err(Error::Mismatch));
    assert_eq!(verify(&key, msg, &t[..16]), Err(Error::Mismatch));
    assert_eq!(tag(&key[..31], msg), Err(Error::Key));
    assert_eq!(verify(&key[..31], msg, &t), Err(Error::Key));
}

#[derive(serde::Deserialize)]
struct Vector {
    data: String,
    sums: std::collections::BTreeMap<String, String>,
    hmac_key: String,
    hmac_msg: String,
    hmac_tag: String,
    reject: Vec<String>,
}

#[test]
fn go_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let v: Vector = serde_json::from_str(&raw).unwrap();
    let data = hex::decode(&v.data).unwrap();
    for s in v.sums.values() {
        assert_eq!(check(s, &data, COMPATIBLE), Ok(()), "{s}");
    }
    assert_eq!(&sum(&data), &v.sums["sha384"]);
    for s in &v.reject {
        assert!(check(s, &data, COMPATIBLE).is_err(), "{s}");
    }
    let key = hex::decode(&v.hmac_key).unwrap();
    let msg = hex::decode(&v.hmac_msg).unwrap();
    assert_eq!(verify(&key, &msg, &hex::decode(&v.hmac_tag).unwrap()), Ok(()));
}
