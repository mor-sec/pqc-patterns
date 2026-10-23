use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ml_dsa::{EncodedVerifyingKey, Seed, SigningKey, VerifyingKey};
use sess_02_mldsa_signed_tokens::*;

const T0: i64 = 1_790_000_000;
const ISS: &str = "https://auth.internal";
const AUD: &str = "https://payments.internal";

fn key() -> SigningKey<Params> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).unwrap();
    SigningKey::<Params>::from_seed(&Seed::from(seed))
}

fn setup() -> (Signer, Verifier, Claims) {
    let sk = key();
    let pk = sk.expanded_key().verifying_key().clone();
    let v = Verifier::new(ISS, AUD, HashMap::from([("auth-2026-10".to_string(), pk)]));
    let c = Claims {
        iss: ISS.into(),
        sub: "svc-billing".into(),
        aud: AUD.into(),
        iat: T0,
        exp: T0 + 900,
        jti: None,
    };
    (
        Signer {
            key_id: "auth-2026-10".into(),
            key: sk,
        },
        v,
        c,
    )
}

type Mutation = Box<dyn Fn(&mut Claims)>;

fn forge(s: &Signer, header: &str, claims: &Claims, ctx: &[u8]) -> String {
    let input = format!(
        "{}.{}",
        B64.encode(header),
        B64.encode(serde_json::to_vec(claims).unwrap())
    );
    let sig = s
        .key
        .expanded_key()
        .sign_deterministic(input.as_bytes(), ctx)
        .unwrap();
    format!("{input}.{}", B64.encode(sig.encode()))
}

#[test]
fn round_trip() {
    let (s, v, c) = setup();
    assert_eq!(v.verify_at(&s.sign(&c), T0), Ok(c));
}

#[test]
fn rejects_tampering() {
    let (s, v, c) = setup();
    let tok = s.sign(&c);
    let parts: Vec<&str> = tok.split('.').collect();
    let evil = Claims {
        sub: "svc-admin".into(),
        ..c
    };
    let forged = format!(
        "{}.{}.{}",
        parts[0],
        B64.encode(serde_json::to_vec(&evil).unwrap()),
        parts[2]
    );
    assert_eq!(v.verify_at(&forged, T0), Err(VerifyError::Signature));
}

#[test]
fn rejects_headers() {
    let (s, v, c) = setup();
    for (header, want) in [
        (
            r#"{"alg":"none","typ":"at+jwt","kid":"auth-2026-10"}"#,
            VerifyError::Header,
        ),
        (
            r#"{"alg":"ES256","typ":"at+jwt","kid":"auth-2026-10"}"#,
            VerifyError::Header,
        ),
        (
            r#"{"alg":"ML-DSA-65","typ":"id+jwt","kid":"auth-2026-10"}"#,
            VerifyError::Header,
        ),
        (
            r#"{"alg":"ML-DSA-65","kid":"auth-2026-10"}"#,
            VerifyError::Malformed,
        ),
        (
            r#"{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10","jku":"https://evil.example"}"#,
            VerifyError::Malformed,
        ),
        (
            r#"{"alg":"none","alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10"}"#,
            VerifyError::Malformed,
        ),
        (
            r#"{"alg":"ML-DSA-65","typ":"at+jwt","kid":"other"}"#,
            VerifyError::UnknownKey,
        ),
    ] {
        assert_eq!(
            v.verify_at(&forge(&s, header, &c, b""), T0),
            Err(want),
            "{header}"
        );
    }
}

#[test]
fn rejects_non_empty_context() {
    let (s, v, c) = setup();
    let tok = forge(
        &s,
        r#"{"alg":"ML-DSA-65","typ":"at+jwt","kid":"auth-2026-10"}"#,
        &c,
        b"x",
    );
    assert_eq!(v.verify_at(&tok, T0), Err(VerifyError::Signature));
}

#[test]
fn rejects_other_key() {
    let (mut s, v, c) = setup();
    s.key = key();
    assert_eq!(v.verify_at(&s.sign(&c), T0), Err(VerifyError::Signature));
}

#[test]
fn claim_checks() {
    let (s, v, base) = setup();
    let cases: [(&str, Mutation, VerifyError); 7] = [
        (
            "issuer",
            Box::new(|c| c.iss = "https://evil.example".into()),
            VerifyError::Claims,
        ),
        (
            "audience",
            Box::new(|c| c.aud = "https://ledger.internal".into()),
            VerifyError::Claims,
        ),
        ("expired", Box::new(|c| c.exp = T0 - 60), VerifyError::Expired),
        (
            "issued later",
            Box::new(|c| c.iat = T0 + 60),
            VerifyError::Expired,
        ),
        (
            "too long",
            Box::new(|c| c.exp = T0 + 86_400),
            VerifyError::Expired,
        ),
        ("no iat", Box::new(|c| c.iat = 0), VerifyError::Expired),
        (
            "extreme exp",
            Box::new(|c| c.exp = i64::MAX),
            VerifyError::Expired,
        ),
    ];
    for (name, mutate, want) in cases {
        let mut c = base.clone();
        mutate(&mut c);
        assert_eq!(v.verify_at(&s.sign(&c), T0), Err(want), "{name}");
    }
}

#[test]
fn malformed() {
    let (s, v, c) = setup();
    let tok = s.sign(&c);
    let two = &tok[..tok.rfind('.').unwrap()];
    for bad in [
        two.to_string(),
        format!("{tok}.x"),
        format!("{tok}="),
        String::new(),
    ] {
        assert_eq!(v.verify_at(&bad, T0), Err(VerifyError::Malformed));
    }
}

#[derive(serde::Deserialize)]
struct Vector {
    seed: String,
    public_key: String,
    kid: String,
    iss: String,
    aud: String,
    now: i64,
    token: String,
    expected_sub: String,
}

#[test]
fn cross_language_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let vec: Vector = serde_json::from_str(&raw).unwrap();
    let seed: [u8; 32] = hex::decode(&vec.seed).unwrap().try_into().unwrap();
    let pk_bytes = hex::decode(&vec.public_key).unwrap();
    let sk = SigningKey::<Params>::from_seed(&Seed::from(seed));
    assert_eq!(
        sk.expanded_key().verifying_key().encode().as_slice(),
        pk_bytes.as_slice()
    );
    let pk = VerifyingKey::decode(&EncodedVerifyingKey::<Params>::try_from(pk_bytes.as_slice()).unwrap());
    let v = Verifier::new(&vec.iss, &vec.aud, HashMap::from([(vec.kid, pk)]));
    assert_eq!(v.verify_at(&vec.token, vec.now).unwrap().sub, vec.expected_sub);
}
