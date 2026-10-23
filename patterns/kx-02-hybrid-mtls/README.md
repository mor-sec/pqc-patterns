# KX-02: Mutual TLS between services with hybrid key exchange

## Intent

Let two services authenticate each other with certificates and protect the traffic between them against harvest-now-decrypt-later, using TLS 1.3 with a hybrid post-quantum key exchange. The server also checks which client it is talking to, not just that the client has a certificate from the internal CA.

## When to use it

- Service-to-service traffic inside your platform, such as a service mesh, internal RPC or a database proxy, where both ends are under your control.
- Use KX-01 for public endpoints where clients don't have certificates.
- Use SIG-01 when the receiver must verify the sender after the request has left the TLS connection, for example through queues or logs.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Protocol | TLS 1.3 only | Hybrid groups are defined for TLS 1.3 only. |
| Key exchange | `X25519MLKEM768`, then `SecP256r1MLKEM768`, with no classical fallback | Both ends are yours, so there is no reason to accept a classical-only peer. RFC 10024 groups. |
| Client authentication | Required, against an internal CA that is only used for workload certificates | A certificate from a public CA, or from a CA shared with other uses, says nothing about whether a caller is one of your services. |
| Client identity | Exactly one URI SAN, such as `spiffe://example.org/billing` | A stable, structured name. SPIFFE-compatible, so it works with SPIRE and most meshes. |
| Authorisation | Allow-list of client identities, checked inside the handshake | Trusting the CA proves who the caller is. The allow-list decides whether it may connect. Rejecting in the handshake means a disallowed caller never reaches application code. |
| Server identity | DNS name, verified by the client | Standard hostname verification. |
| Certificates | ECDSA P-256 (P-384 for CNSA 2.0) for now, short-lived | Post-quantum certificates are tracked in PKI-01. Short lifetimes, such as hours or days, limit the damage from a stolen key. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/mtls.go](go/mtls.go) | Standard library `crypto/tls` |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `rustls` 0.23 with `aws-lc-rs`, and `x509-parser` to read the URI SAN |
| Java | [java/.../HybridMtls.java](java/src/main/java/io/github/morsec/pqcpatterns/kx02/HybridMtls.java) | Bouncy Castle JSSE 1.86 on Java 21+ |

```go
allowed := []string{"spiffe://example.org/billing"}
srv := &http.Server{TLSConfig: mtls.ServerConfig(cert, workloadCAs, allowed)}

// In a handler, for decisions finer than the allow-list:
id, _ := mtls.PeerIdentity(*r.TLS)
```

```java
SSLContext ctx = HybridMtls.serverContext(keyManagers, workloadCaTrustManagers, Set.of("spiffe://example.org/billing"));
SSLServerSocket s = HybridMtls.serverSocket(ctx, 8443); // applies TLS 1.3, hybrid groups and client auth
```

In Java the TLS version, groups and the client-certificate requirement live in `SSLParameters`, not in the `SSLContext`. Create sockets and engines through `HybridMtls`, which applies them, rather than through the context's own factories.

Tests run real handshakes with a test CA and check that:

- Mutual authentication succeeds, uses `X25519MLKEM768` (Go and Rust check this directly; Java offers only hybrid groups), and the server sees the client's identity.
- A client with no certificate is refused.
- A client certificate from another CA is refused.
- A client from the right CA but not on the allow-list is refused.
- A client offering only classical groups is refused.
- The client refuses a server certificate for a different name.

**Library notes**

- **Go:** the allow-list runs in `VerifyConnection`, which Go calls after chain verification on every handshake, including resumed sessions.
- **Rust:** rustls has no hook for identity checks, so the pattern wraps `WebPkiClientVerifier` in a verifier that checks the chain first and then the URI SAN.
- **Java:** the allow-list wraps the PKIX `X509ExtendedTrustManager`, so the check runs inside the handshake for sockets and engines alike.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Trusting any certificate from the CA, with no allow-list | Every workload that can get a certificate can call every service | Review item |
| `VerifyClientCertIfGiven`, `RequestClientCert` or `wantClientAuth` | A client without a certificate gets through | Review item |
| Authorising on the Common Name | CNs are free text and often reused; SANs are the standard place for identity | Review item |
| Checking identity in application code after the handshake | Easy to miss on one route; the connection is already established | Review item |
| Using the public web PKI, or a CA shared with other uses, as the client CA | Anyone who can get a certificate from that CA can authenticate | Review item |
| Classical-only groups, TLS 1.2, or verification turned off | As in KX-01 | [`pqc-tls-classical-groups`](../../rules/), [`pqc-tls-min-version`](../../rules/), [`pqc-tls-no-verify`](../../rules/) |

## Threat notes

- Protects confidentiality against harvest-now-decrypt-later, and authenticates both ends against classical attackers.
- Authentication is not yet quantum-safe. That needs ML-DSA certificates (PKI-01). It matters once a quantum computer exists, not for traffic recorded today.
- The allow-list is only as good as the CA's issuance policy. If an attacker can get any certificate with an allowed URI SAN, they are that service.
- Revocation is not checked. Use short-lived certificates instead.

## Migration

1. Stand up an internal workload CA, or use SPIRE or your mesh's CA, and issue each service a certificate with a URI SAN.
2. Deploy KX-01 compatible mode first if some services are not yet on a hybrid-capable TLS stack.
3. Turn on client certificates with the allow-list in log-only mode: accept everyone, and record which identities would be refused.
4. Switch to this pattern once the logs are clean.

## References

- [RFC 10024](https://datatracker.ietf.org/doc/html/rfc10024) (hybrid key agreement for TLS 1.3)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3, section 4.4.2 for client certificates)
- [SPIFFE X.509-SVID](https://github.com/spiffe/spiffe/blob/main/standards/X509-SVID.md)
- Go [`crypto/tls`](https://pkg.go.dev/crypto/tls), [rustls](https://docs.rs/rustls), [Bouncy Castle JSSE](https://www.bouncycastle.org/)
