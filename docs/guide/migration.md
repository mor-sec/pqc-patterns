# Planning a migration

Moving a system to post-quantum cryptography is mostly an inventory and rollout problem. The cryptography itself is a small part of the work.

## 1. Inventory

Find every place your systems use public-key cryptography, and note for each one what it protects and for how long.

- **Code.** Run the [checker](../checker.md) across your repositories. It flags RSA encryption, raw ECDH, classical signing keys, classical-only TLS groups and weak symmetric choices, and links each finding to the pattern that fixes it.
- **Dependencies.** List the TLS and crypto libraries and their versions. Hybrid TLS needs Go 1.24+, rustls 0.23.22+, or Bouncy Castle JSSE 1.86 or JDK 27+ in Java.
- **Traffic.** Log the negotiated TLS key exchange group on your endpoints, as [KX-01](../patterns/kx-01-hybrid-tls.md) shows. It tells you which clients already support hybrid groups.
- **Stored data.** Find data encrypted to public keys (RSA-OAEP, ECIES, PGP) and its retention period.
- **Long-lived keys.** CA roots, firmware and package signing keys, and any signature that must stay verifiable for years.

## 2. Prioritise

Rank each item by how long its protection must last against how long it will take to migrate. If data must stay secret for 10 years and migration takes 3, it needs to be quantum-safe 13 years before a quantum computer arrives (Mosca's inequality).

In practice the order is usually:

1. TLS key exchange on all endpoints. Low effort, and it protects recorded traffic immediately.
2. Public-key encryption of stored data and messages.
3. Long-lived signing keys: roots, firmware and code signing.
4. Everything else that signs: API requests, tokens, service certificates.

## 3. Build in agility

You will change algorithms again, whether for a newer standard, a bigger parameter set or a broken implementation. Every pattern here leaves room for that:

- Wire formats carry a version or algorithm identifier, such as the key ID in [SYM-01](../patterns/sym-01-aead-at-rest.md) and the versioned context string in [SIG-01](../patterns/sig-01-mldsa-api-signing.md), and the parameters stored in every password hash in [HASH-03](../patterns/hash-03-password-hashing.md).
- Verifiers accept a set of keys, so you can rotate without a flag day.
- Keys are stored in standard PKCS#8 and SubjectPublicKeyInfo, which name their algorithm, and are referred to by a key ID derived from the public key ([KEY-01](../patterns/key-01-pqc-key-storage.md)).
- Algorithm choices live in one function per pattern, not spread across call sites.

## 4. Roll out

For anything with two ends you do not upgrade at once:

1. **Compatible mode.** Offer the post-quantum option first while still accepting the classical one, and measure how many peers use each.
2. **Fix stragglers.** Upgrade or replace clients that still negotiate classical algorithms.
3. **Strict mode.** Refuse classical-only peers where you control both ends. Keep public endpoints compatible until the classical share is negligible.

Test through your real network path. Post-quantum handshakes are larger, and some middleboxes and load balancers mishandle a ClientHello over about 1.2 KB or a certificate chain over 10 KB.

## 5. Keep it from regressing

- Run the checker in CI with `--error`, so new classical-only code fails the build.
- Alert on classical TLS connections to endpoints that should be strict.
- Pin crypto library versions and read their changelogs. Defaults change silently, and a configuration flag can turn hybrid groups off.
