# KX-01: Hybrid post-quantum TLS 1.3

## Intent

Make every TLS connection your service opens or accepts use a hybrid post-quantum key exchange, so recorded traffic cannot be decrypted later by a quantum computer.

## When to use it

- Any HTTPS, gRPC or other TLS endpoint, client or server.
- Strict mode for service-to-service traffic where you control both ends.
- Compatible mode for public endpoints until all clients support hybrid groups.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Protocol | TLS 1.3 only | Hybrid groups are defined for TLS 1.3 only. |
| Key exchange | `X25519MLKEM768`, then `SecP256r1MLKEM768` | Hybrid groups from [RFC 10024](https://datatracker.ietf.org/doc/html/rfc10024). X25519MLKEM768 is the IANA-recommended default. |
| Classical fallback | `x25519`, compatible mode only | Keeps old clients working while you measure them. |
| Monitoring | Log the negotiated group and alert on classical connections | Defaults change silently with library upgrades and config flags. |
| Certificates | Classical (ECDSA P-256 or RSA) for now | Harvest-now-decrypt-later attacks target key exchange, not authentication. ML-DSA certificates are covered by PKI-01. |

**CNSA 2.0 variant:** put `SecP384r1MLKEM1024` first. Go and Bouncy Castle support it; rustls's aws-lc-rs provider does not yet.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/hybridtls.go](go/hybridtls.go) | Standard library `crypto/tls` (hybrid on by default since Go 1.24) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `rustls` 0.23 with the `aws-lc-rs` provider and `prefer-post-quantum` |
| Java | [java/.../HybridTls.java](java/src/main/java/io/github/morsec/pqcpatterns/kx01/HybridTls.java) | Bouncy Castle JSSE 1.86 on Java 21+. On JDK 27+ SunJSSE accepts the same `setNamedGroups` call ([JEP 527](https://openjdk.org/jeps/527)). |

```go
srv := &http.Server{TLSConfig: hybridtls.ServerConfig(cert, hybridtls.Strict)}
// In a VerifyConnection hook or access log:
if err := hybridtls.RequireHybrid(conn.ConnectionState()); err != nil { metrics.ClassicalTLS.Inc() }
```

Tests run real handshakes and check that:

- Strict client and server negotiate `X25519MLKEM768`.
- A strict server rejects a classical-only client.
- A compatible server accepts that client and the monitoring check flags it.
- TLS 1.2 is refused.

**Library notes**

- **Go:** the defaults already prefer hybrid groups, but `GODEBUG=tlsmlkem=0` or an explicit `CurvePreferences` list elsewhere in your code turns them off. Setting the list here makes the policy visible in code review.
- **Java:** Bouncy Castle JSSE has no public API for the negotiated group, so the tests prove hybrid negotiation by making it the only option. Use strict mode where you need that guarantee.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| `CurvePreferences` or `namedGroups` listing only classical curves | Disables post-quantum key exchange | [`pqc-tls-classical-groups`](../../rules/) |
| Allowing TLS 1.2 or lower | No hybrid groups, and weaker handshakes | [`pqc-tls-min-version`](../../rules/) |
| `GODEBUG=tlsmlkem=0`, or the `jdk.tls.namedGroups` property with classical groups only | Silent global downgrade | [`pqc-tls-godebug-downgrade`](../../rules/) |
| `InsecureSkipVerify`, trust-all managers, hostname verification off | Key exchange strength is irrelevant if the peer is not authenticated | [`pqc-tls-no-verify`](../../rules/) |
| Pure `MLKEM768` or `MLKEM1024` groups without a classical half | Not recommended outside CNSA 2.0 contexts yet | Review item |

## Threat notes

- Protects session confidentiality against harvest-now-decrypt-later.
- Does not make authentication quantum-safe. That needs post-quantum certificates (PKI-01), which matter only once quantum computers exist, not for recorded traffic.
- Hybrid ClientHellos are about 1.2 KB larger. Some middleboxes and old load balancers mishandle them, so test through your real network path.

## Migration

1. Upgrade the TLS stack (Go 1.24+, rustls 0.23.22+, Bouncy Castle JSSE 1.86, which these tests use, or JDK 27+).
2. Deploy compatible mode everywhere and log the negotiated group.
3. Fix or upgrade clients that still negotiate classical groups.
4. Switch internal services to strict mode; keep public endpoints compatible until the classical share is negligible.

## References

- [RFC 10024](https://datatracker.ietf.org/doc/html/rfc10024) (hybrid key agreement for TLS 1.3)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3)
- Go [`crypto/tls`](https://pkg.go.dev/crypto/tls), [rustls](https://docs.rs/rustls), [Bouncy Castle JSSE](https://www.bouncycastle.org/), [JEP 527](https://openjdk.org/jeps/527)
