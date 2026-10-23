# SIG-01: Signing API requests with ML-DSA

## Intent

Let a service prove that an API request came from a specific caller, was meant for that service, was not changed in transit, and is fresh, using a signature that stays secure against quantum attacks.

## When to use it

- Service-to-service or webhook calls where the receiver must verify the sender independently of TLS, for example through proxies, queues or logs.
- Use mTLS (KX-02, planned) when transport-level identity is enough.
- Use SESS-02 (planned) for bearer tokens such as JWTs.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Algorithm | ML-DSA-65 (FIPS 204) | NIST's general-purpose post-quantum signature. 1952-byte public keys, 3309-byte signatures. |
| CNSA 2.0 variant | ML-DSA-87 | Required for national security systems. |
| Context string | `pqc-patterns/sig-01/api-request/v2` | FIPS 204 domain separation: a signature made for this purpose cannot be replayed as a signature for anything else the key signs. |
| Signed message | Length-prefixed key ID, audience, timestamp, method, path with query, body | Covers everything that changes the request's meaning. Length prefixes stop field-boundary tricks. |
| Audience | The receiver's own identity, such as `https://payments.internal` | Stops a request signed for one receiver being replayed to another that trusts the same key, for example another webhook tenant or staging. The verifier always uses its configured audience, never one taken from the request. |
| Freshness | Timestamp within ±5 minutes | Bounds replay to the same receiver. Add a nonce or idempotency-key cache for non-idempotent endpoints. |
| Private key storage | The 32-byte FIPS 204 seed | Smallest form, and every library here can expand it. |

Hedged (randomised) signing is the default. Signatures over the same request differ, and all of them verify.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/apisig.go](go/apisig.go) | Standard library `crypto/mldsa` (Go 1.27+) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | RustCrypto `ml-dsa` 0.1 (see the warning below) |
| Java | [java/.../ApiSigner.java](java/src/main/java/io/github/morsec/pqcpatterns/sig01/ApiSigner.java) | Bouncy Castle 1.86 |

```go
sig, _ := apisig.Sign(sk, apisig.Request{KeyID: "svc-a-2026", Audience: "https://payments.internal", Timestamp: time.Now(), Method: "POST", Path: "/v1/payments", Body: body})
// Send KeyID, Timestamp and base64(sig) as headers. The receiver rebuilds Request and calls Verify,
// which signs over its own Audience, so a request meant for another service fails.
verifier := &apisig.Verifier{Audience: "https://payments.internal", Keys: trusted}
err := verifier.Verify(req, sig)
```

Tests cover round trips, tampering with each signed field, a request signed for another audience, a corrupted signature, a signature under a different context, stale and unknown keys, field-boundary ambiguity, seed round trips, and verification of the shared Go-generated vector in [testdata/vector.json](testdata/vector.json).

**Library notes**

- **Rust:** `aws-lc-rs` offers ML-DSA only behind an unstable feature and does not expose context strings, so this pattern uses RustCrypto `ml-dsa`. Its README states it has not been independently audited. Treat that as a risk acceptance and track it.
- **Java:** the JDK 24+ built-in ML-DSA does not support context strings (JEP 497 non-goal), so this pattern uses Bouncy Castle, which also runs on Java 21 LTS.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| RSA, ECDSA or Ed25519 for new long-lived signing keys | Broken by Shor's algorithm | `pqc.sig.classical-keygen` (planned) |
| Signing only the body | Path, method or timestamp can be swapped | Review item |
| Concatenating fields without lengths or a delimiter that cannot appear in fields | `/a` + `bc` equals `/ab` + `c` | Review item |
| No context string, or one shared across purposes | Signatures can be replayed across protocols | `pqc.sig.mldsa-no-context` (planned) |
| No timestamp or replay window | Captured requests can be replayed forever | Review item |
| Using HashML-DSA (pre-hash) without a need for it | Adds an option CNSA 2.0 disallows and most verifiers do not need | Review item |

## Threat notes

- Protects request authenticity and integrity against classical and quantum attackers.
- Harvest-now-decrypt-later does not apply to signatures, but forgery does once a quantum computer exists, so long-lived verification keys matter most.
- Does not provide confidentiality; use TLS (KX-01).
- Does not stop replay to the same receiver inside the window by itself. Replay to a different receiver fails because the audience is signed.

## Migration

1. Have the receiver accept both the old classical signature header and the new ML-DSA header, and log which one each caller uses.
2. Move callers to ML-DSA one at a time, tracked by key ID.
3. Reject classical signatures once the logs show no remaining callers.
4. Distribute ML-DSA public keys through the same channel as today (config, JWKS-style endpoint or service registry). They are 1952 bytes, so check size limits.

## References

- [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) (ML-DSA, context strings in section 5.2)
- Go [`crypto/mldsa`](https://pkg.go.dev/crypto/mldsa), Rust [`ml-dsa`](https://docs.rs/ml-dsa), [Bouncy Castle](https://www.bouncycastle.org/), [JEP 497](https://openjdk.org/jeps/497)
