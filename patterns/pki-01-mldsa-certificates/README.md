# PKI-01: ML-DSA certificates and fully post-quantum TLS

## Intent

Issue certificates with ML-DSA keys and signatures, and run TLS 1.3 connections where both halves resist a quantum attacker: the key exchange (hybrid ML-KEM, as in KX-01) and the authentication (ML-DSA signatures on the handshake and on every certificate in the chain).

## When to use it

- Internal services and private PKIs where you control the CA, the servers and every client. Start with long-lived trust, such as root and intermediate CAs and code-signing roots, because those must stay unforgeable for their whole lifetime.
- Not yet for public, browser-facing endpoints. Public CAs and browsers do not issue or accept ML-DSA certificates today. Keep KX-01 there.
- If your threat is recorded traffic (harvest-now-decrypt-later), KX-01 already covers it. ML-DSA certificates protect against a quantum attacker who forges authentication in real time, which only matters once such a computer exists. The reason to start now is that PKI rollouts take years.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Certificate signature | ML-DSA-65 (`id-ml-dsa-65`, OID 2.16.840.1.101.3.4.3.18) | NIST category 3, the same default as SIG-01. The certificate format is [RFC 9881](https://datatracker.ietf.org/doc/html/rfc9881). Use ML-DSA-87 for CNSA 2.0. |
| Whole chain | ML-DSA at every level, root included | A chain is only as strong as its weakest signature. An ML-DSA leaf issued by an ECDSA CA can still be forged by forging the CA's signature. |
| Handshake signature | TLS signature schemes `mldsa65` (0x0905) and `mldsa87` (0x0906) only | Code points from [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/). Offering classical schemes too would let an attacker who can forge them pick one. |
| Chain checking on the client | The client refuses any certificate signed with anything but ML-DSA | `signature_algorithms_cert` is only a request: [RFC 8446 section 4.4.2.2](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.2.2) lets a server send a chain outside it. |
| Key exchange | Hybrid groups only, as in KX-01 strict mode | Quantum-safe authentication over a classical key exchange would still expose recorded traffic. |
| Keys | Generated where they are used; the CA receives a PKCS#10 request | The private key never leaves the service. The CA checks the request's signature, which proves the requester holds the key. |
| Rollout | A separate ML-DSA CA, with clients that trust both CAs during migration | See Migration. A single certificate cannot carry both signature types in a way today's TLS stacks accept. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | Not yet | Go 1.27 has ML-DSA in `crypto/mldsa`, but `crypto/x509` and `crypto/tls` cannot parse or verify ML-DSA certificates yet. This pattern will add Go once they can. |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `rustls` 0.23 and `rustls-webpki` 0.103 with `aws-lc-rs`; `rcgen` 0.14 (`aws_lc_rs_unstable` feature) for keys and requests |
| Java | [java/.../MlDsaCertificates.java](java/src/main/java/io/github/morsec/pqcpatterns/pki01/MlDsaCertificates.java) | Bouncy Castle 1.86 (`bcpkix` for requests) and Bouncy Castle JSSE 1.86 on Java 21+ |

Create a key and a request for your CA:

```rust
let key = pki_01_mldsa_certificates::generate_key()?;
let req = pki_01_mldsa_certificates::csr(&key, vec!["ledger.internal".into()])?;
send_to_ca(req.pem()?);                // keep key.serialize_der() in your secret store
```

```java
KeyPair key = MlDsaCertificates.generateKeyPair();
PKCS10CertificationRequest req = MlDsaCertificates.csr(key, new X500Name("CN=ledger"), List.of("ledger.internal"));
```

Then serve and connect with the strict configuration:

```rust
let server = server_config(chain, key)?;   // ML-DSA chain from your CA
let client = client_config(ml_dsa_roots)?; // accepts ML-DSA chains only
```

```java
SSLContext ctx = MlDsaCertificates.context(null, MlDsaCertificates.trustManagers(mlDsaRoot));
SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket("ledger.internal", 443);
s.setSSLParameters(MlDsaCertificates.clientParameters()); // TLS 1.3, hybrid groups, ML-DSA only, hostname check
```

As in KX-01, the Java policy lives in `SSLParameters`, so apply it to every socket and engine.

Tests run real handshakes with a test CA and check that:

- A fully post-quantum handshake succeeds: ML-DSA chain, ML-DSA handshake signature and `X25519MLKEM768` (Rust checks the group directly; Java offers only hybrid groups).
- In Java, the CA issues the server certificate from the request, after checking its signature.
- A classical server certificate is refused.
- An ML-DSA leaf issued by an ECDSA CA is refused. The Java test makes the client advertise ECDSA in `signature_algorithms_cert` so the server sends that chain, which proves the client checks the chain itself.
- A chain from a CA the client does not trust is refused.
- A certificate for the wrong hostname is refused (Java).
- The request is signed with `id-ml-dsa-65` and carries the requested names.

**Library notes**

- **Rust:** the pattern restricts the provider's `signature_verification_algorithms` to ML-DSA-65 and ML-DSA-87. rustls uses that list both for the handshake signature and for every certificate in the chain, so one setting covers both. `rcgen` can create ML-DSA keys, requests and certificates, but cannot yet parse ML-DSA requests, so a Rust CA would need another parser.
- **Java:** signature schemes in `SSLParameters` cover the handshake signature only. The pattern also sets `AlgorithmConstraints` that refuse non-ML-DSA signatures, which Bouncy Castle JSSE applies to every certificate in the peer's chain. `keyManagers` uses Bouncy Castle's PKCS12 key store, because the JDK's needs a JDK ML-DSA implementation (JDK 24+) to read the keys back.
- **Size:** an ML-DSA-65 certificate is about 5.5 KB, against about 0.5 KB for ECDSA P-256. The Rust test's server flight with one certificate is about 10 KB. With an intermediate it passes 15 KB, more than a typical initial TCP congestion window, which costs an extra round trip. Certificate compression does not help much because keys and signatures are random.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| ML-DSA leaf certificates under a classical root or intermediate | The chain can be forged at the classical link | Review item |
| Offering classical signature schemes alongside ML-DSA on the client | An attacker who can forge the classical scheme chooses it | Review item |
| Relying on `signature_algorithms_cert` without checking the chain on the client | The server may send any chain | Review item |
| Generating the key on the CA and shipping it to the service | The private key leaves its owner; a request does the same job | Review item |
| Disabling certificate checks while testing ML-DSA interop | Leaves an unauthenticated connection behind | [`pqc-tls-no-verify`](../../rules/) |
| ML-DSA certificates over a classical-only key exchange | Recorded traffic is still exposed | [`pqc-tls-classical-groups`](../../rules/) |

## Threat notes

- Protects authentication against a quantum attacker who can forge classical signatures, as long as every certificate in the chain and the handshake are ML-DSA and the client accepts nothing else.
- Does not protect against a compromised CA key, mis-issuance or a stolen service key. Keep certificates short-lived and the CA offline or in an HSM, as with classical PKI.
- Revocation (CRLs and OCSP responses) must be signed with ML-DSA too, or it becomes the weak link. These tests do not cover revocation.
- ML-DSA TLS code points are still in an Internet-Draft. Pin library versions and test interop between the stacks you run before relying on them across vendors.

## Migration

1. Deploy KX-01 first. It protects recorded traffic now, and this pattern builds on it.
2. Stand up a separate ML-DSA root and intermediate, ideally in an HSM that supports ML-DSA.
3. Add the ML-DSA root to every client's trust store next to the classical one, and let clients negotiate ML-DSA when the server offers it.
4. Issue ML-DSA certificates to servers from requests, and serve them to clients that offer ML-DSA signature schemes. Bouncy Castle JSSE does this when its key store holds both a classical and an ML-DSA entry. rustls needs a small `ResolvesServerCert` that checks the ClientHello's signature schemes.
5. When every client offers ML-DSA, switch servers and clients to the strict configuration in this pattern and retire the classical CA.

## References

- [RFC 9881](https://datatracker.ietf.org/doc/html/rfc9881) (ML-DSA in X.509 certificates)
- [draft-ietf-tls-mldsa](https://datatracker.ietf.org/doc/draft-ietf-tls-mldsa/) (ML-DSA signature schemes for TLS 1.3)
- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA)
- [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) (TLS 1.3), [RFC 2986](https://www.rfc-editor.org/rfc/rfc2986) (PKCS#10)
- [rustls](https://docs.rs/rustls), [rcgen](https://docs.rs/rcgen), [Bouncy Castle](https://www.bouncycastle.org/)
