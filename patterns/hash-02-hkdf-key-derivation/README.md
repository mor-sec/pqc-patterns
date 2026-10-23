# HASH-02: Deriving purpose-bound keys with HKDF

## Intent

Turn one high-entropy secret into many independent keys, one per purpose and context, so that a key is never reused across algorithms, tenants or features. HKDF is the standard tool for this, and it is already post-quantum safe at 256-bit strength.

## When to use it

- One KMS data key or master secret has to yield separate encryption, MAC and token-signing keys.
- Per-tenant or per-record keys derived from a root key, so you don't have to store each one.
- Turning an ML-KEM or hybrid KEM shared secret into session keys when you are building a protocol yourself. HPKE (KX-03) and TLS (KX-01) already do this internally, so prefer them.
- Do **not** use it for passwords. HKDF is fast by design. Use HASH-03 (password hashing, planned).

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Function | HKDF-SHA-256 (RFC 5869); HKDF-SHA-384 for CNSA 2.0 | Standard, available in every stack, and quantum attacks only halve SHA-256's preimage strength to 128 bits. |
| Input secret | At least 32 random bytes | Derived keys can't be stronger than their input. |
| Salt | Empty when the secret is already uniformly random; otherwise a fixed, non-secret, random value per application | Salt helps extraction from non-uniform secrets such as a Diffie-Hellman output. It doesn't need to be secret. |
| Info | Length-prefixed: version label, purpose, context, output length | Purpose stops one key being used for two algorithms. Context stops two tenants sharing a key. Length stops a 16-byte key being a prefix of the 32-byte key. Length prefixes stop `"ab" + "c"` colliding with `"a" + "bc"`. |
| Purpose string | `<feature>/<algorithm>/<version>`, for example `billing-exports/aes-256-gcm/v1` | Readable, unique, and versioned so you can rotate a derivation. |
| Output | 16 to 8160 bytes; normally 32 | 32 bytes suits AES-256 and HMAC-SHA-256. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/kdf.go](go/kdf.go) | Standard library `crypto/hkdf` (Go 1.24+) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `aws-lc-rs` HKDF |
| Java | [java/.../Kdf.java](java/src/main/java/io/github/morsec/pqcpatterns/hash02/Kdf.java) | Bouncy Castle `HKDFBytesGenerator`. The JDK's `KDF` API (JEP 510) needs Java 25. |

```go
encKey, _ := kdf.Derive(root, nil, "billing-exports/aes-256-gcm/v1", []byte(tenantID), 32)
macKey, _ := kdf.Derive(root, nil, "billing-exports/hmac-sha256/v1", []byte(tenantID), 32)
```

Tests check that changing the purpose, context or salt gives an unrelated key, and that moving a byte across the purpose/context boundary does too. They also check that a 16-byte key is not a prefix of the 32-byte one, and that short secrets, empty purposes and bad lengths are rejected. The Go test checks the HKDF primitive against RFC 5869 test case 1. Rust and Java reproduce the Go-generated [testdata/vector.json](testdata/vector.json), including the exact info bytes.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Using one key for two algorithms (for example AES-GCM and HMAC) | Cross-algorithm interactions; one compromise exposes both | Review item |
| `SHA-256(secret + "enc")` as a KDF | Not a PRF construction; length-extension and ambiguity problems | Review item |
| Empty or constant `info` for every derived key | Every derivation produces the same key | Review item |
| Concatenating info fields without lengths | `"ab" + "c"` equals `"a" + "bc"` | Review item |
| Taking a short key as a prefix of a longer one | Related keys across algorithms | Review item |
| HKDF or SHA-256 on a password | Fast to brute-force; use a password hash (HASH-03) | Review item |
| MD5 or SHA-1 inside the KDF | Weak hashes | [`pqc-hash-weak`](../../rules/) |

## Threat notes

- Derived keys are independent as long as the input secret stays secret. If the input leaks, every derived key leaks, so protect it as you would the strongest key it produces.
- HKDF does not stretch low-entropy input. A 6-digit PIN through HKDF is still a 6-digit PIN.
- Against quantum attackers, Grover's algorithm gives a square-root speedup on brute force. 256-bit inputs and outputs keep a 128-bit margin.

## Migration

1. Inventory places that hash secrets together ad hoc or reuse one key for several jobs.
2. Introduce derived keys under new purpose strings, and keep decrypting old data with the old key until it is re-encrypted (SYM-01's keyring handles this).
3. Bump the purpose version (`/v2`) whenever the derivation or the algorithm changes. Never reuse a purpose string for something new.

## References

- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) (HKDF)
- [NIST SP 800-56C Rev. 2](https://csrc.nist.gov/pubs/sp/800/56/c/r2/final) (key derivation through extraction and expansion)
- [NIST SP 800-108 Rev. 1](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final) (key derivation using pseudorandom functions)
- Go [`crypto/hkdf`](https://pkg.go.dev/crypto/hkdf), [aws-lc-rs](https://docs.rs/aws-lc-rs), [JEP 510](https://openjdk.org/jeps/510)
