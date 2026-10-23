# HASH-03: Storing passwords with Argon2id

## Intent

Store user passwords so that a stolen database cannot be cracked cheaply, using Argon2id with a fresh salt per password. The stored string format lets parameters be raised over time without a forced password reset.

## When to use it

- Any system that checks a password it has stored itself.
- Do **not** use it to derive encryption keys from secrets that are already random. Use HKDF (HASH-02).
- If you can avoid storing passwords at all, through SSO or passkeys, do that instead.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Function | Argon2id, version 1.3 (RFC 9106) | Memory-hard, so GPUs and ASICs gain little. The `id` variant resists both side-channel and trade-off attacks. |
| Cost | 64 MiB, 3 passes, 4 lanes (RFC 9106 second recommended option); never below 19 MiB and 2 passes (OWASP) | Raise passes until one hash takes about 0.5 s on your servers. |
| Salt | 16 random bytes per password | Stops precomputed tables and identical hashes for identical passwords. |
| Output | 32 bytes | Plenty. Longer output adds nothing. |
| Storage | PHC string, for example `$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>` | Self-describing. Each row records its own parameters, so old and new hashes can coexist. |
| Comparison | Constant time | Stops timing leaks of how much of the hash matched. |
| Upgrades | `verify` reports when the stored parameters differ from the current ones; re-hash on successful login | Raises cost over time without a password reset. |
| Parsing | Canonical form only, with parameter bounds (up to 1 GiB, 16 passes, 16 lanes) | A corrupt or hostile row cannot make verification allocate unbounded memory, and there is only one valid encoding. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/password.go](go/password.go) | `golang.org/x/crypto/argon2` |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | RustCrypto `argon2` 0.6, `subtle`, `base64ct` |
| Java | [java/.../PasswordHasher.java](java/src/main/java/io/github/morsec/pqcpatterns/hash03/PasswordHasher.java) | Bouncy Castle `Argon2BytesGenerator` |

```go
stored, _ := password.Hash([]byte(pw), password.Default)

needsRehash, err := password.Verify([]byte(pw), stored, password.Default)
if err == nil && needsRehash {
	stored, _ = password.Hash([]byte(pw), password.Default) // save it
}
```

Tests in all three languages cover:
- round trips and wrong passwords
- a fresh salt on every hash
- re-hash signalling when parameters change
- rejecting malformed stored strings: argon2i, version 16, a leading zero or `+` sign, reordered parameters, oversized memory, zero lanes, a short salt, padding, a short hash, bcrypt strings, an empty string and extra fields

Each language also checks Argon2id against the reference implementation's published output for `password` and `somesalt`. Rust and Java verify the Go-generated [testdata/vector.json](testdata/vector.json).

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| SHA-256 or any plain hash of a password, salted or not | Billions of guesses per second on a GPU | Review item |
| MD5 or SHA-1 password hashes | Weak and fast | [`pqc-hash-weak`](../../rules/) |
| PBKDF2 with low iteration counts, or bcrypt at cost 10 or below | Too cheap today. bcrypt also truncates passwords at 72 bytes. | Review item |
| One salt for every user, or no salt | Identical passwords produce identical hashes, and tables work | Review item |
| Comparing hashes with `==` or `equals` | Timing leak | Review item |
| Encrypting passwords instead of hashing them | Whoever holds the key can recover every password | Review item |
| Hashing on the client and storing that value as-is | The client-side hash becomes the password | Review item |

## Threat notes

- Protects stored passwords against offline guessing after a database leak. It cannot protect weak passwords: rate-limit logins and check new passwords against breach lists.
- Quantum computers do not change this pattern much. Grover's algorithm gives at most a square-root speedup on guessing, and memory-hard functions are a poor fit for quantum hardware. The cost parameters matter far more.
- Optional hardening: a pepper, meaning an HMAC of the password under a key held in a KMS or HSM, applied before Argon2id. A database leak alone is then not enough to crack anything. Plan how you will rotate the pepper.

## Migration

1. Deploy `verify` with support for both the old hash format and Argon2id PHC strings.
2. On each successful login, re-hash with Argon2id and replace the old hash.
3. For accounts that never log in, wrap the old hash, for example `argon2id(sha256crypt_hash)`, and mark the row so verification applies both steps. Alternatively, expire those accounts and force a reset.
4. Raise the parameters as hardware improves. The re-hash signal upgrades users as they log in.

## References

- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2)
- [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) (memorised secret verifiers)
