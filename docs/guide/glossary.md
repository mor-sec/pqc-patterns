# Glossary

Short, plain definitions of the terms used across this site. Where a term is quantum-vulnerable, or a pattern covers it, the entry says so. For the bigger picture, read [The quantum problem](quantum-threat.md).

## AEAD

Authenticated encryption with associated data. A symmetric cipher mode that both hides data and detects any change to it, and can also protect unencrypted fields such as headers. AES-GCM and ChaCha20-Poly1305 are AEADs. Safe against quantum computers with 256-bit keys. See [SYM-01](../patterns/sym-01-aead-at-rest.md) and [SYM-03](../patterns/sym-03-streaming-encryption.md).

## AES

The Advanced Encryption Standard, the most widely used symmetric cipher. It comes with 128, 192 or 256-bit keys. A quantum computer at best halves the effective key length ([Grover's algorithm](#grovers-algorithm)), so AES-256 stays safe. The patterns use AES-256-GCM.

## Argon2id

A password hashing function that is deliberately slow and memory-hungry, so guessing passwords is expensive even with specialised hardware. Quantum computers change little here. See [HASH-03](../patterns/hash-03-password-hashing.md).

## Asymmetric cryptography

Another name for [public-key cryptography](#public-key-cryptography).

## Bits of security

A rough measure of how much work an attack takes: n bits means about 2<sup>n</sup> operations. 128 bits is the usual target, and is far beyond any realistic attacker. NIST's [security categories](#nist-security-categories) for post-quantum algorithms are defined against AES key search.

## Certificate

A signed document that binds a public key to a name, such as a domain. A [certificate authority](#certificate-authority) signs it so that clients can trust the key. Today's certificates use RSA or ECDSA signatures, which a quantum computer can forge. See [PKI-01](../patterns/pki-01-mldsa-certificates.md).

## Certificate authority

An organisation or service (CA) that signs certificates. Root CA keys are trusted for decades, so they are among the first signing keys to move to post-quantum algorithms.

## CNSA 2.0

The NSA's Commercial National Security Algorithm Suite 2.0, a list of required algorithms and deadlines for US national security systems. It requires ML-KEM-1024, ML-DSA-87, AES-256 and SHA-384 or above. Regulated industries often follow it. See [Choosing algorithms](algorithms.md#cnsa-20).

## Context string

A short label passed to ML-DSA when signing and verifying, which binds a signature to one purpose. It stops a signature made for one job, such as an API request, being replayed as another, such as a token. See [SIG-01](../patterns/sig-01-mldsa-api-signing.md).

## CRQC

Cryptographically relevant quantum computer: one large and reliable enough to run [Shor's algorithm](#shors-algorithm) against real RSA and elliptic-curve keys. None exists today. "Q-day" is the informal name for when one does.

## Crypto agility

Designing systems so the algorithm can be changed without rewriting them, for example by putting an algorithm or key identifier in every stored message. See [Planning a migration](migration.md#3-build-in-agility).

## Diffie-Hellman and ECDH

The classic [key exchange](#key-exchange) methods. Two parties combine their own private value with the other's public value and arrive at the same shared secret. ECDH is the elliptic-curve version, and [X25519](#x25519) is the most common form today. Broken by Shor's algorithm. See [KX-01](../patterns/kx-01-hybrid-tls.md).

## Digital signature

A value made with a private key that anyone holding the matching public key can check. It proves who produced a message and that it was not changed. RSA, ECDSA and Ed25519 signatures can be forged with a quantum computer; ML-DSA and SLH-DSA cannot. See [SIG-01](../patterns/sig-01-mldsa-api-signing.md) and [SIG-02](../patterns/sig-02-artifact-signing.md).

## ECC

Elliptic-curve cryptography: public-key algorithms built on elliptic curves, including ECDH, ECDSA, Ed25519 and X25519. It gives small keys and fast operations, which is why it replaced RSA in most new protocols. Broken by Shor's algorithm.

## ECDSA

The elliptic-curve digital signature algorithm, used in many TLS certificates and in JWTs as ES256. Quantum-vulnerable. Replace with [ML-DSA](#ml-dsa).

## Ed25519

A modern elliptic-curve signature scheme with 32-byte keys and 64-byte signatures. Quantum-vulnerable. Replace with [ML-DSA](#ml-dsa).

## FIPS 203, 204 and 205

The NIST standards, published in August 2024, that define [ML-KEM](#ml-kem), [ML-DSA](#ml-dsa) and [SLH-DSA](#slh-dsa) respectively.

## FN-DSA

A lattice signature scheme, formerly Falcon, being standardised as FIPS 206. Its signatures are smaller than ML-DSA's, but it is much harder to implement safely. Not used in these patterns.

## Forward secrecy

A property of key exchange where each session uses fresh, throwaway keys, so stealing a server's long-term key later does not expose past sessions. It does **not** protect against a quantum computer, which can break each recorded key exchange directly. That is why recorded traffic is at risk even with forward secrecy.

## Grover's algorithm

A quantum algorithm that speeds up brute-force search. Against a symmetric key of n bits it needs about 2<sup>n/2</sup> steps instead of 2<sup>n</sup>, which at best halves the key length. Its steps must also run one after another, which makes it much less useful in practice than the formula suggests. This is why AES-256 and SHA-256 remain safe.

## Harvest now, decrypt later

An attack where encrypted traffic or data is recorded today and stored until a quantum computer can decrypt it. It makes classical key exchange a problem now for any data that must stay secret for years. See [The quantum problem](quantum-threat.md#why-act-before-a-quantum-computer-exists).

## Hash function

A function that turns any input into a short fixed-size fingerprint, such that it is infeasible to find two inputs with the same fingerprint. SHA-256, SHA-384, SHA-512 and SHA-3 are safe against quantum computers. MD5 and SHA-1 are already broken. See [HASH-01](../patterns/hash-01-digests-and-macs.md).

## HKDF

A key derivation function built on HMAC. It turns one shared secret into several independent keys, each tied to a purpose by a label. Quantum-safe with SHA-256 or above. See [HASH-02](../patterns/hash-02-hkdf-key-derivation.md).

## HMAC

A [MAC](#mac) built from a hash function, such as HMAC-SHA-256. Quantum-safe. See [HASH-01](../patterns/hash-01-digests-and-macs.md).

## HPKE

Hybrid Public Key Encryption (RFC 9180), a standard way to encrypt a message to someone's public key. "Hybrid" here means it combines a KEM with symmetric encryption, not classical with post-quantum, although post-quantum KEMs can be plugged in. See [KX-03](../patterns/kx-03-hpke-hybrid-envelope.md).

## Hybrid

In post-quantum work, using a classical and a post-quantum algorithm together, so the result stays secure as long as either one does. The patterns use hybrid ML-KEM-768 + X25519 for key exchange, which is also what TLS calls `X25519MLKEM768`. See [KX-01](../patterns/kx-01-hybrid-tls.md).

## JWS and JWT

JSON Web Signature, and the JSON Web Token format built on it, used for bearer tokens. Most JWTs today are signed with RSA (RS256) or ECDSA (ES256), both quantum-vulnerable. See [SESS-02](../patterns/sess-02-mldsa-signed-tokens.md).

## KEM

Key encapsulation mechanism. A public-key method for setting up a shared secret: the sender uses the recipient's public key to produce a random secret and a ciphertext, and only the recipient's private key can recover the secret from the ciphertext. ML-KEM is a KEM. It does the job that Diffie-Hellman does in key exchange.

## Key exchange

How two parties agree on a shared secret key over a public network, so they can then use fast symmetric encryption. Every TLS, SSH and VPN connection starts with one. Today's methods (Diffie-Hellman, ECDH, X25519, RSA key transport) are broken by Shor's algorithm. See [KX-01](../patterns/kx-01-hybrid-tls.md) and [KX-02](../patterns/kx-02-hybrid-mtls.md).

## Lattice-based cryptography

Cryptography built on hard problems about points in high-dimensional grids (lattices). No efficient quantum or classical attack is known. ML-KEM, ML-DSA and FN-DSA are lattice-based.

## MAC

Message authentication code. A short tag made with a shared secret key that proves a message came from someone holding the key and was not changed. Unlike a signature, anyone who can check it can also create it. Quantum-safe. See [HASH-01](../patterns/hash-01-digests-and-macs.md).

## ML-DSA

Module-Lattice Digital Signature Algorithm (FIPS 204), the main post-quantum replacement for RSA, ECDSA and Ed25519 signatures. It comes in three sizes: ML-DSA-44, ML-DSA-65 (the default here) and ML-DSA-87. Its public keys and signatures are a few kilobytes. See [SIG-01](../patterns/sig-01-mldsa-api-signing.md), [SIG-02](../patterns/sig-02-artifact-signing.md), [SESS-02](../patterns/sess-02-mldsa-signed-tokens.md), [PKI-01](../patterns/pki-01-mldsa-certificates.md) and [KEY-01](../patterns/key-01-pqc-key-storage.md).

## ML-KEM

Module-Lattice Key Encapsulation Mechanism (FIPS 203), formerly Kyber, the post-quantum replacement for Diffie-Hellman and RSA encryption. It comes in three sizes: ML-KEM-512, ML-KEM-768 (the default here) and ML-KEM-1024. See [KX-01](../patterns/kx-01-hybrid-tls.md), [KX-03](../patterns/kx-03-hpke-hybrid-envelope.md) and [KEY-01](../patterns/key-01-pqc-key-storage.md).

## Mosca's inequality

A rule of thumb for deadlines: if data must stay secret for X years and migrating takes Y years, you must start at least X + Y years before a quantum computer arrives. See [Planning a migration](migration.md#2-prioritise).

## mTLS

Mutual TLS, where both the client and the server present certificates, common between internal services. See [KX-02](../patterns/kx-02-hybrid-mtls.md).

## NIST security categories

Five levels NIST uses to rate post-quantum algorithms against the effort of breaking AES or SHA. Category 1 is about as hard as finding an AES-128 key, category 3 as AES-192 and category 5 as AES-256. ML-KEM-768 and ML-DSA-65 are category 3.

## Nonce

A "number used once": a value that must never repeat under the same key. AES-GCM fails badly if a nonce repeats, which is why the patterns limit how many messages one key encrypts. See [SYM-01](../patterns/sym-01-aead-at-rest.md).

## Post-quantum cryptography

Public-key algorithms that run on ordinary computers but are designed to resist attacks by quantum computers too. Often shortened to PQC, and also called quantum-safe or quantum-resistant cryptography. Not the same as [quantum key distribution](#quantum-key-distribution).

## Public-key cryptography

Cryptography that uses a key pair: a public key that can be shared with anyone and a private key that is kept secret. It is used for key exchange, encryption to a recipient, and signatures. RSA and elliptic-curve cryptography are the classical forms, and both are broken by Shor's algorithm.

## Quantum computer

A computer that uses quantum effects (qubits in superposition and entanglement) to solve some specific problems far faster than any ordinary computer. It is not faster at most tasks. Today's machines are too small and error-prone to threaten cryptography.

## Quantum key distribution

QKD: using quantum physics and special hardware, such as fibre links, to share a key. It is a different thing from post-quantum cryptography, needs dedicated equipment, and does not authenticate the parties on its own. It is not covered here, and most security agencies recommend post-quantum cryptography instead.

## Qubit

The basic unit of a quantum computer, the counterpart of a bit. Recent estimates put the machine needed to break RSA-2048 at just under a million error-prone physical qubits running for about a week, far more than any current machine has. The estimates have fallen sharply over the past decade.

## RSA

The oldest widely used public-key algorithm, used for encryption, key transport and signatures. Its security rests on how hard it is to factor large numbers, which Shor's algorithm makes easy. Larger RSA keys do not help. Replace RSA encryption with [KX-03](../patterns/kx-03-hpke-hybrid-envelope.md) and RSA signatures with [ML-DSA](#ml-dsa).

## SHA-2 and SHA-3

The two current families of standard hash functions. SHA-2 includes SHA-256, SHA-384 and SHA-512; SHA-3 includes SHA3-256 and the SHAKE functions. Both are quantum-safe at 256 bits and above. CNSA 2.0 asks for SHA-384 or SHA-512.

## Shor's algorithm

A quantum algorithm that factors large numbers and solves discrete logarithms efficiently. That breaks RSA, Diffie-Hellman and all elliptic-curve cryptography, whatever the key size. It is the reason for the whole migration. See [The quantum problem](quantum-threat.md#shors-algorithm-breaks-public-key-cryptography).

## SLH-DSA

Stateless Hash-Based Digital Signature Algorithm (FIPS 205), formerly SPHINCS+. Its security rests only on hash functions, which makes it a conservative choice for long-lived roots, but its signatures are 7.8 to 49 KB and signing is slow. Not used in these patterns yet.

## Symmetric cryptography

Cryptography where both sides share the same secret key, such as AES, ChaCha20, HMAC and hash functions. Quantum computers weaken it only slightly, so 256-bit keys remain safe.

## TLS

Transport Layer Security, the protocol behind HTTPS and most encrypted connections. A TLS 1.3 handshake uses a key exchange (the "group") to set up keys and a certificate signature to prove the server's identity. Both parts are quantum-vulnerable today. See [KX-01](../patterns/kx-01-hybrid-tls.md) for the key exchange and [PKI-01](../patterns/pki-01-mldsa-certificates.md) for the certificates.

## X25519

The most common key exchange today: ECDH on Curve25519. Fast, small and quantum-vulnerable. The patterns keep it alongside ML-KEM in a [hybrid](#hybrid), so the connection is at least as strong as X25519 alone.
