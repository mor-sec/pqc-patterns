# Choosing algorithms

The patterns use a small set of defaults so that services built from them interoperate. This page explains each choice and when to deviate.

## Key exchange and public-key encryption: hybrid ML-KEM-768 + X25519

ML-KEM (FIPS 203) is the NIST-standard post-quantum key encapsulation mechanism. The patterns always combine it with X25519, so the shared secret stays safe as long as either algorithm holds:

- ML-KEM is much younger than elliptic curves, and its implementations have had less scrutiny. The hybrid keeps today's classical security as a floor.
- The cost is small: X25519 adds 32 bytes to each side's message, next to ML-KEM-768's 1,184-byte encapsulation key and 1,088-byte ciphertext.
- Hybrid is what the ecosystem has standardised on. TLS uses the `X25519MLKEM768` group ([RFC 10024](https://datatracker.ietf.org/doc/html/rfc10024)) and HPKE has hybrid KEMs in draft.

ML-KEM-768 targets NIST security category 3, roughly AES-192. Use ML-KEM-1024 (category 5) where CNSA 2.0 applies or policy requires it.

## Signatures: ML-DSA-65

ML-DSA (FIPS 204) is the NIST-standard lattice signature scheme. The patterns use ML-DSA-65 (category 3), and ML-DSA-87 under CNSA 2.0.

| | Public key | Signature |
| --- | --- | --- |
| Ed25519 | 32 bytes | 64 bytes |
| ECDSA P-256 | 64 bytes | about 72 bytes |
| ML-DSA-65 | 1,952 bytes | 3,309 bytes |
| ML-DSA-87 | 2,592 bytes | 4,627 bytes |

The size is the main cost. It matters for tokens in headers, certificates in TLS handshakes and anything with many signatures. Each pattern page notes where it bites.

Signatures in these patterns are pure ML-DSA, not hybrid. Hybrid (composite) signatures are still being standardised, and there is no harvest-now risk for signatures, so a classical half buys less than it does for key exchange.

Always pass a **context string** when signing. ML-DSA's context binds a signature to one purpose, so a signature made for API requests cannot be replayed as, say, a token. The checker flags ML-DSA calls without one in Go and Rust.

### Other signature schemes

- **SLH-DSA** (FIPS 205) is hash-based. Its security rests only on the hash function, which makes it attractive for long-lived roots such as firmware signing, but signatures are 7.8 KB to 49 KB and signing is slow. Not used in these patterns yet.
- **FN-DSA** (Falcon) has smaller signatures than ML-DSA but is much harder to implement safely. Not used here.

## Symmetric encryption: AES-256-GCM

Quantum search (Grover's algorithm) at most halves the effective key length, so 256-bit keys keep a wide margin and 128-bit keys do not. The patterns use AES-256-GCM with random 96-bit nonces and a limit on messages per key. See [SYM-01](../patterns/sym-01-aead-at-rest.md).

## Hashing and key derivation

SHA-256 and above are fine. SHA-384 or SHA-512 meet CNSA 2.0. MD5 and SHA-1 are broken classically and the checker flags them.

- To derive keys from a shared secret, use HKDF with a distinct label per purpose. See [HASH-02](../patterns/hash-02-hkdf-key-derivation.md).
- To store passwords, use a memory-hard function such as Argon2id, never a plain hash. Quantum computers change little here, but this is one of the most common weak spots that turns up in a crypto inventory. See [HASH-03](../patterns/hash-03-password-hashing.md).

## CNSA 2.0

The NSA's CNSA 2.0 suite applies to US National Security Systems and is often copied by regulated industries. Its main differences from the defaults here:

- ML-KEM-1024 and ML-DSA-87 only, with no smaller parameter sets.
- SHA-384 or SHA-512, and AES-256.
- It expects pure post-quantum algorithms in the end state, so hybrid is a transition step.

Where a pattern has a CNSA 2.0 variant, its page says so under **Recommended construction**.
