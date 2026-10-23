# KX-03: Hybrid envelope encryption with HPKE (ML-KEM-768 + X25519)

## Intent

Encrypt a message, or a data key, to a recipient's public key so that it stays confidential even if the ciphertext is stored today and attacked later with a quantum computer.

## When to use it

- Encrypting exports, backups, files or queue messages to a specific service or person.
- Wrapping per-record data keys for SYM-01 when the unwrapping side holds a key pair rather than a KMS key.
- Use TLS (KX-01) for data in transit between live endpoints; this pattern is for data that is stored or forwarded.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Framework | HPKE, RFC 9180, base mode | Standard, analysed, and available in all three languages, so there is no home-made KEM-plus-KDF glue. |
| KEM | MLKEM768-X25519 ("X-Wing"), code point `0x647a` | Hybrid: an attacker must break both ML-KEM-768 and X25519. Specified for HPKE in draft-ietf-hpke-pq. |
| KDF | HKDF-SHA256 (`0x0001`) | Default HPKE KDF, supported everywhere. |
| AEAD | AES-256-GCM (`0x0002`) | Same reasoning as SYM-01. |
| `info` | Application and purpose, for example `billing-exports/v1` | Binds ciphertexts to one use, so they cannot be redirected. |
| Private key storage | 32-byte seed | Compact, and every library here accepts it. |

Wire format, identical in all three languages:

```
suite (6 bytes: KEM ID || KDF ID || AEAD ID) || enc (1120 bytes) || ciphertext || tag (16)
```

The suite prefix lets readers reject unknown formats and migrate to new suites (AGI-01).

**CNSA 2.0 variant:** CNSA 2.0 requires ML-KEM-1024 and does not use X25519. Go offers `hpke.MLKEM1024P384()` and `hpke.MLKEM1024()`. Bouncy Castle and hpke-rs support ML-KEM-1024 as well; a CNSA variant of this pattern is planned.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/envelope.go](go/envelope.go) | Standard library `crypto/hpke` (Go 1.26+) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `hpke-rs` 0.8 with the `hpke-rs-libcrux` provider (formally verified ML-KEM, not independently audited) |
| Java | [java/.../Envelope.java](java/src/main/java/io/github/morsec/pqcpatterns/kx03/Envelope.java) | Bouncy Castle 1.86 `org.bouncycastle.crypto.hpke` |

```go
msg, _ := envelope.Seal(recipientPub, []byte("billing-exports/v1"), []byte("export-17"), dataKey)
dataKey, err := envelope.Open(recipientPriv, []byte("billing-exports/v1"), []byte("export-17"), msg)
```

Tests cover round trips, bit flips in the suite header, the ML-KEM ciphertext, the X25519 share and the AEAD ciphertext, wrong `info`, wrong `aad`, the wrong recipient, and the shared vector in [testdata/vector.json](testdata/vector.json). Rust and Java both open the Go-generated message, which shows the three implementations interoperate.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| RSA-OAEP or RSA-KEM key wrapping | Broken by Shor's algorithm; stored ciphertexts are exposed later | `pqc.kx.rsa-encrypt` (planned) |
| ECIES or raw ECDH plus a KDF | Same quantum exposure | `pqc.kx.classical-ecdh` (planned) |
| ML-KEM alone, without a classical component | ML-KEM is new; hybrid keeps today's security if a flaw is found | Review item |
| Hand-rolled KEM combiners (`sha256(ss1 || ss2)`) | Easy to get wrong; use HPKE or X-Wing's specified combiner | Review item |
| Empty or shared `info` across applications | Ciphertexts can be replayed into the wrong context | Review item |
| Reusing one ephemeral key or `enc` for many recipients | HPKE derives fresh keys per `Seal`; do not cache them | Review item |

## Threat notes

- Protects confidentiality and integrity against classical and quantum attackers, including harvest-now-decrypt-later.
- This is the pattern with the highest harvest-now-decrypt-later exposure if done classically, because the ciphertexts are designed to be stored.
- Base mode does not authenticate the sender. Sign the message with SIG-01 if the recipient must know who sent it.

## Migration

1. Generate an X-Wing key pair for each recipient and publish the public key next to the existing RSA or EC key.
2. Senders switch to this pattern and tag messages with the suite prefix; recipients accept both formats.
3. Re-wrap stored data keys under the new key in the background, newest and most sensitive first.
4. Retire the classical recipient key when no stored items reference it.

## References

- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) (HPKE)
- [draft-ietf-hpke-pq](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/) (post-quantum and hybrid KEMs for HPKE)
- [draft-connolly-cfrg-xwing-kem](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) (X-Wing)
- [FIPS 203](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf) (ML-KEM)
- Go [`crypto/hpke`](https://pkg.go.dev/crypto/hpke), Rust [`hpke-rs`](https://docs.rs/hpke-rs), [Bouncy Castle](https://www.bouncycastle.org/)
