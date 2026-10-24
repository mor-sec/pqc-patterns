# The quantum problem

This page explains, without maths, what a quantum computer would break, what it would not, and why the work has to start before one exists. It is written for anyone who touches code or systems that use cryptography, whatever their background. Words in links are defined in the [glossary](glossary.md).

## In one minute

- Almost every system today uses two kinds of cryptography: **symmetric** (one shared secret key, such as AES) and **public-key** (a key pair, such as RSA or elliptic curves).
- A large quantum computer would break **public-key** cryptography completely. That covers how two computers agree on a key ([key exchange](glossary.md#key-exchange)) and how they prove who they are ([digital signatures](glossary.md#digital-signature)).
- It would only dent **symmetric** cryptography and hashing. AES-256, SHA-256 and SHA-3 stay safe.
- No such computer exists yet, but attackers can record encrypted traffic today and decrypt it later. That makes key exchange an urgent problem now, not a future one.
- New public-key algorithms, [ML-KEM](glossary.md#ml-kem) and [ML-DSA](glossary.md#ml-dsa), were standardised by NIST in 2024. The patterns in this repo show how to use them.

## Two kinds of cryptography

**Symmetric cryptography** uses one secret key that both sides hold. It is like a safe with a combination: whoever knows the combination can lock and unlock it. AES is the standard example. It is fast, and it does nearly all of the actual work of encrypting your data, whether in a TLS connection or a database. Hash functions such as SHA-256, and MACs built from them, belong to the same family.

The weak spot of symmetric cryptography is getting the shared key to both sides in the first place. You cannot send it in the clear.

**Public-key cryptography** solves that. Each side has a key pair: a public key it can hand to anyone, and a private key it keeps. It is used for two jobs:

1. **Key exchange.** Two parties who have never met agree on a fresh shared key over an open network, so they can switch to fast symmetric encryption. Every HTTPS connection starts this way, today usually with [X25519](glossary.md#x25519) or [ECDH](glossary.md#diffie-hellman-and-ecdh).
2. **Signatures.** The owner of a private key signs a message, and anyone with the public key can check that the message came from them and was not changed. Signatures are behind TLS certificates, software updates, signed tokens and API authentication. Common algorithms are [RSA](glossary.md#rsa), [ECDSA](glossary.md#ecdsa) and [Ed25519](glossary.md#ed25519).

So a typical secure connection uses both: public-key cryptography to agree a key and prove identity, then symmetric cryptography for the data.

## What a quantum computer changes

A quantum computer is not just a faster computer. For most tasks it is no better than a normal one. But for a few specific maths problems it is dramatically faster, and two of those problems matter for cryptography.

### Shor's algorithm breaks public-key cryptography

RSA is safe because multiplying two large primes is easy but working out which primes were multiplied is, for a normal computer, practically impossible. Elliptic-curve cryptography relies on a different problem of the same kind (the discrete logarithm). Breaking a 2048-bit RSA key or a 256-bit elliptic-curve key with today's best methods would take longer than the age of the universe.

[Shor's algorithm](glossary.md#shors-algorithm), run on a large enough quantum computer, solves both problems quickly. It does not weaken RSA and elliptic curves a little; it breaks them outright, and making the keys bigger does not help in any useful way. Anyone who can run it can:

- recover the private key behind any public key, so they can **forge signatures** and impersonate servers, CAs and software publishers, and
- recover the shared key from a **recorded key exchange**, so they can **decrypt the traffic** that followed.

### Grover's algorithm only dents symmetric cryptography

The best a quantum computer can do against a good symmetric cipher is a faster brute-force search, using [Grover's algorithm](glossary.md#grovers-algorithm). It turns a search over 2<sup>n</sup> keys into roughly 2<sup>n/2</sup> steps, so it at best halves the key's effective length in bits:

- **AES-256** drops to about 128 bits of security. That is still far beyond reach, so AES-256 stays safe.
- **AES-128** drops to about 64 bits on paper. In practice Grover's steps have to run one after another on a single machine and cannot be split across many, so even AES-128 is not considered practically breakable. The patterns use AES-256 anyway, so there is no question to argue about.
- **Hash functions** such as SHA-256, SHA-384, SHA-512 and SHA-3 lose even less. SHA-256 and above are fine.

This is why the migration is about replacing public-key algorithms, not about replacing AES or SHA-2.

## What breaks and what does not

| Use | Today's algorithm | Against a quantum computer | What to use |
| --- | --- | --- | --- |
| Key exchange (TLS, VPNs, SSH) | ECDH, X25519, Diffie-Hellman | **Broken** (Shor) | Hybrid ML-KEM + X25519: [KX-01](../patterns/kx-01-hybrid-tls.md), [KX-02](../patterns/kx-02-hybrid-mtls.md) |
| Encrypting to someone's public key | RSA-OAEP, ECIES, PGP | **Broken** (Shor) | Hybrid ML-KEM in HPKE: [KX-03](../patterns/kx-03-hpke-hybrid-envelope.md) |
| Signatures, certificates, tokens | RSA, ECDSA, Ed25519 | **Broken** (Shor) | ML-DSA: [SIG-01](../patterns/sig-01-mldsa-api-signing.md), [SIG-02](../patterns/sig-02-artifact-signing.md), [SESS-02](../patterns/sess-02-mldsa-signed-tokens.md), [PKI-01](../patterns/pki-01-mldsa-certificates.md) |
| Encrypting data | AES-256-GCM, ChaCha20-Poly1305 | Safe | Keep it: [SYM-01](../patterns/sym-01-aead-at-rest.md), [SYM-03](../patterns/sym-03-streaming-encryption.md) |
| Hashing, MACs, key derivation | SHA-256 and up, SHA-3, HMAC, HKDF | Safe | Keep it: [HASH-01](../patterns/hash-01-digests-and-macs.md), [HASH-02](../patterns/hash-02-hkdf-key-derivation.md) |
| Passwords | Argon2id, scrypt, bcrypt | Little change | Keep it: [HASH-03](../patterns/hash-03-password-hashing.md) |
| Already weak | MD5, SHA-1, DES, 3DES, RC4 | Broken without a quantum computer | Replace now: the [checker](../checker.md) finds them |

## Why act before a quantum computer exists

Nobody knows when a quantum computer big enough to run Shor's algorithm against real keys will exist. Today's machines are far too small and too error-prone. Estimates range from around ten years to never, and they have been coming down as the algorithms improve. Three things make waiting a bad bet anyway.

**Harvest now, decrypt later.** An attacker who records your encrypted traffic today can store it and decrypt it once a quantum computer exists. Nothing in the recording tells you it happened. Any data that must stay secret for years, such as health records, financial data, credentials or trade secrets, is already exposed if the key exchange that protected it is classical. [Forward secrecy](glossary.md#forward-secrecy) does not help here, because the attacker breaks each recorded key exchange directly. This is why key exchange comes first.

**Long-lived signatures.** A forged signature only works once a quantum computer exists, so most signatures have more time. The exception is anything that must be trusted for many years: CA root certificates, firmware and secure-boot keys, and devices in the field that cannot easily be updated. Those keys need replacing well before the deadline.

**Migration is slow.** Finding every use of cryptography, upgrading libraries, changing protocols and file formats, and rolling keys across a fleet takes years in a large organisation. [Planning a migration](migration.md) covers how to work out your own deadline with [Mosca's inequality](glossary.md#moscas-inequality). Governments have already set dates: NIST plans to deprecate RSA and elliptic curves in its standards from 2030 and disallow them from 2035, and [CNSA 2.0](glossary.md#cnsa-20) expects US national security systems to move sooner.

## What replaces RSA and elliptic curves

[Post-quantum cryptography](glossary.md#post-quantum-cryptography) means new public-key algorithms built on maths problems that neither normal nor quantum computers are known to solve efficiently. They run on ordinary computers; you do not need quantum hardware to use them. NIST finished the first standards in 2024:

- **[ML-KEM](glossary.md#ml-kem)** (FIPS 203) replaces key exchange and public-key encryption.
- **[ML-DSA](glossary.md#ml-dsa)** (FIPS 204) replaces signatures.
- **[SLH-DSA](glossary.md#slh-dsa)** (FIPS 205) is a slower, larger alternative for signatures that relies only on hash functions.

The new algorithms are fast, but their keys and signatures are much larger: an ML-DSA-65 signature is about 3.3 KB against 64 bytes for Ed25519. They are also young compared with RSA and elliptic curves. That is why the patterns use a [hybrid](glossary.md#hybrid) for key exchange, combining ML-KEM with X25519 so the result is safe as long as either one holds. [Choosing algorithms](algorithms.md) explains each default.

## Where to go next

- [Start here](index.md) gives the order of work and points to the first patterns to adopt.
- [Choosing algorithms](algorithms.md) explains the parameter choices.
- [Planning a migration](migration.md) covers inventory, priorities and rollout.
- The [glossary](glossary.md) defines every term used on this site.
