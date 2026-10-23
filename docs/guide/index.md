# Start here

This guide is for engineers who own services that use cryptography and need to move them to post-quantum algorithms. It assumes you know what TLS, a signature and an AEAD are, but not the new algorithms.

## What a quantum computer breaks

A large enough quantum computer would break the public-key algorithms almost everything uses today: RSA, Diffie-Hellman and elliptic curves (ECDH, ECDSA, Ed25519, X25519). It does not break symmetric cryptography. AES-256 and SHA-256 or larger stay safe.

The two halves of public-key cryptography have different deadlines:

| | Key exchange and encryption | Signatures and authentication |
| --- | --- | --- |
| Attack | Record traffic or ciphertext now, decrypt it once a quantum computer exists ("harvest now, decrypt later") | Forge a signature once a quantum computer exists |
| When it matters | **Today**, for any data that must stay secret beyond the arrival of a quantum computer | When a quantum computer exists, except for anything that must stay trustworthy for years, such as CA roots and firmware signing keys |
| Fix | ML-KEM, combined with X25519 in a hybrid | ML-DSA |

So the order of work is: key exchange and encryption first, long-lived signing keys next, short-lived authentication last.

## Where to start

1. **Find what you have.** Run the [checker](../checker.md) over your code, and log the negotiated TLS group on your endpoints (see [KX-01](../patterns/kx-01-hybrid-tls.md)). [Planning a migration](migration.md) covers the rest of the inventory.
2. **Turn on hybrid TLS.** [KX-01](../patterns/kx-01-hybrid-tls.md) for any endpoint and [KX-02](../patterns/kx-02-hybrid-mtls.md) for mutual TLS between services. Most current TLS stacks support it, and it protects recorded traffic immediately.
3. **Fix stored and enveloped data.** [KX-03](../patterns/kx-03-hpke-hybrid-envelope.md) replaces RSA-OAEP and ECIES for encrypting to a public key. [SYM-01](../patterns/sym-01-aead-at-rest.md) covers data at rest, and [SYM-03](../patterns/sym-03-streaming-encryption.md) covers large files and streams.
4. **Move signatures, starting with long-lived ones.** [SIG-01](../patterns/sig-01-mldsa-api-signing.md) signs API requests, [SESS-02](../patterns/sess-02-mldsa-signed-tokens.md) signs bearer tokens, and [PKI-01](../patterns/pki-01-mldsa-certificates.md) moves certificates and TLS authentication to ML-DSA.

## How to read a pattern page

Every pattern page has the same sections:

- **Intent** and **When to use it** say what job it does and when to pick a different pattern.
- **Recommended construction** is the decision table: each choice with a reason. Start here if you are reviewing someone else's design.
- **Code** links to the implementation in each language and lists what the tests prove.
- **Anti-patterns** lists what to look for in review, with the checker rule that finds it.
- **Threat notes** say what the pattern does and does not protect against.
- **Migration** gives the steps from the classical version.
