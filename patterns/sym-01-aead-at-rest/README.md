# SYM-01: Authenticated encryption at rest (AES-256-GCM)

## Intent

Encrypt records, files or fields at rest so that anyone without the key can neither read nor undetectably modify them, and so a quantum attacker gains nothing useful.

## When to use it

- Encrypting database fields, blobs or files with a symmetric key you control, usually a data key from a KMS.
- Use [KX-03](../kx-03-hpke-hybrid-envelope/) instead when the reader holds a key pair rather than a shared secret key.
- Use [SYM-03](../sym-03-streaming-encryption/) for large streams or files that do not fit in memory.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Algorithm | AES-256-GCM | Grover's algorithm at most halves effective key strength, so a 256-bit key keeps a 128-bit margin. AES-128 does not. |
| Nonce | 96-bit random, fresh per message | Safe for up to 2^32 messages per key (NIST SP 800-38D). Rotate keys well before that. |
| Associated data | 5-byte header plus caller context, length-prefixed | Stops a valid ciphertext being moved to another record or downgraded to another key or version. |
| Key ID | 4 bytes in the header | Lets you rotate keys without re-encrypting everything at once. |

CNSA 2.0 also specifies AES-256, so there is no separate CNSA variant.

Wire format, identical in all three languages:

```
version (0x01) || key ID (4 bytes, big-endian) || nonce (12) || ciphertext || tag (16)
```

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/aead.go](go/aead.go) | Standard library (`crypto/aes`, `crypto/cipher`) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `aws-lc-rs` |
| Java | [java/.../Keyring.java](java/src/main/java/io/github/morsec/pqcpatterns/sym01/Keyring.java) | JDK built-in provider |

```go
k, _ := aead.NewKeyring(1, dataKey)
blob, _ := k.Encrypt(plaintext, []byte("customers/42/payment_method"))
pt, err := k.Decrypt(blob, []byte("customers/42/payment_method"))
```

Each implementation's tests cover a round trip, every single-bit flip, wrong associated data, truncation, key rotation, nonce uniqueness, and decryption of the shared vector in [testdata/vector.json](testdata/vector.json).

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| AES-128 keys | Leaves only about 64 bits of security against a large quantum computer | [`pqc-sym-aes-128`](../../rules/) |
| ECB or CBC without a MAC | No integrity, and ECB leaks patterns | [`pqc-sym-unauthenticated-mode`](../../rules/) |
| Fixed, counter-from-zero or reused nonces | One GCM nonce reuse leaks the authentication key and plaintext XOR | [`pqc-sym-static-nonce`](../../rules/) |
| No associated data | Ciphertexts can be swapped between rows | Review item |
| Returning different errors for "bad tag" and "unknown key" | Gives attackers an oracle | Review item |
| Hardcoded keys in source or config | Keys belong in a KMS or HSM (KEY-02) | `pqc-key-hardcoded` (planned) |

## Threat notes

- Protects confidentiality and integrity of stored data, including against an attacker with a future quantum computer.
- Does not protect against an attacker who obtains the key, so key storage (KEY-02) matters more than the cipher.
- Harvest-now-decrypt-later exposure is low for AES-256 itself. The real exposure is in how the data key was delivered: if it was wrapped with RSA or ECDH, use KX-03 for wrapping instead.

## Migration

1. Add the new 256-bit key to the keyring as a decrypt-only key, then make it active with `Rotate`.
2. Re-encrypt old records in the background. Old key IDs keep decrypting until the job finishes.
3. Remove the old key once no records reference its ID.
4. Moving from AES-128 or an unauthenticated mode: decrypt with the old code path and re-encrypt with this pattern, keyed off the version byte.

## References

- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) (GCM and nonce limits)
- NSA CNSA 2.0 algorithm suite (AES-256 for symmetric encryption)
- Go [`crypto/cipher`](https://pkg.go.dev/crypto/cipher), Rust [`aws-lc-rs`](https://docs.rs/aws-lc-rs), Java [`Cipher`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html)
