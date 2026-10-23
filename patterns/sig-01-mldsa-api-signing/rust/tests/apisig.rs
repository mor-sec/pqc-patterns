use std::collections::HashMap;

use sig_01_mldsa_api_signing::*;

const T0: i64 = 1_790_000_000;

fn setup() -> (ml_dsa::SigningKey<Params>, Verifier) {
    let (sk, _) = generate_key();
    let mut keys = HashMap::new();
    keys.insert(
        "svc-a-2026".to_string(),
        sk.expanded_key().verifying_key().clone(),
    );
    (
        sk,
        Verifier {
            keys,
            max_skew: DEFAULT_MAX_SKEW,
        },
    )
}

fn req<'a>() -> Request<'a> {
    Request {
        key_id: "svc-a-2026",
        timestamp: T0,
        method: "POST",
        path: "/v1/payments?dry_run=false",
        body: br#"{"amount":1000}"#,
    }
}

#[test]
fn round_trip() {
    let (sk, v) = setup();
    let sig = sign(&sk, &req());
    assert_eq!(sig.len(), 3309);
    assert_eq!(v.verify_at(&req(), &sig, T0), Ok(()));
}

#[test]
fn rejects_tampering() {
    let (sk, v) = setup();
    let sig = sign(&sk, &req());
    let tampered = [
        Request {
            body: br#"{"amount":9000}"#,
            ..req()
        },
        Request {
            path: "/v1/refunds?dry_run=false",
            ..req()
        },
        Request {
            method: "PUT",
            ..req()
        },
        Request {
            timestamp: T0 + 1,
            ..req()
        },
    ];
    for r in &tampered {
        assert_eq!(v.verify_at(r, &sig, T0), Err(VerifyError::Signature));
    }
    let mut bad = sig.clone();
    bad[100] ^= 1;
    assert_eq!(v.verify_at(&req(), &bad, T0), Err(VerifyError::Signature));
    assert_eq!(v.verify_at(&req(), &sig[..100], T0), Err(VerifyError::Signature));
}

#[test]
fn rejects_wrong_context() {
    let (sk, v) = setup();
    let sig = sk
        .expanded_key()
        .sign_deterministic(&req().message(), b"some/other/purpose")
        .unwrap();
    assert_eq!(
        v.verify_at(&req(), &sig.encode(), T0),
        Err(VerifyError::Signature)
    );
}

#[test]
fn rejects_stale_and_unknown() {
    let (sk, v) = setup();
    let old = Request {
        timestamp: T0 - 360,
        ..req()
    };
    assert_eq!(v.verify_at(&old, &sign(&sk, &old), T0), Err(VerifyError::Stale));
    let unknown = Request {
        key_id: "unknown",
        ..req()
    };
    assert_eq!(
        v.verify_at(&unknown, &sign(&sk, &unknown), T0),
        Err(VerifyError::UnknownKey)
    );
}

#[test]
fn field_boundaries() {
    let a = Request {
        path: "/ab",
        body: b"c",
        ..req()
    };
    let b = Request {
        path: "/a",
        body: b"bc",
        ..req()
    };
    assert_ne!(a.message(), b.message());
}

#[test]
fn seed_round_trip() {
    let (sk, seed) = generate_key();
    assert_eq!(load_private_key(&seed), sk);
}

#[derive(serde::Deserialize)]
struct Vector {
    seed: String,
    public_key: String,
    key_id: String,
    timestamp: i64,
    method: String,
    path: String,
    body: String,
    signature: String,
}

#[test]
fn cross_language_vector() {
    let raw =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../testdata/vector.json")).unwrap();
    let v: Vector = serde_json::from_str(&raw).unwrap();
    let seed: [u8; 32] = hex::decode(&v.seed).unwrap().try_into().unwrap();
    let pk_bytes = hex::decode(&v.public_key).unwrap();
    let sk = load_private_key(&seed);
    assert_eq!(
        sk.expanded_key().verifying_key().encode().as_slice(),
        pk_bytes.as_slice(),
        "seed derives a different public key"
    );

    let pk = load_public_key(&pk_bytes).unwrap();
    let verifier = Verifier {
        keys: HashMap::from([(v.key_id.clone(), pk)]),
        max_skew: DEFAULT_MAX_SKEW,
    };
    let body = hex::decode(&v.body).unwrap();
    let r = Request {
        key_id: &v.key_id,
        timestamp: v.timestamp,
        method: &v.method,
        path: &v.path,
        body: &body,
    };
    assert_eq!(
        verifier.verify_at(&r, &hex::decode(&v.signature).unwrap(), v.timestamp),
        Ok(())
    );
}
