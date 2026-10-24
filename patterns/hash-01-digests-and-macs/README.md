# HASH-01: Content digests and MACs (SHA-384, HMAC)

## Intent

Record and check content digests in a self-describing format, and authenticate messages with full-length HMAC tags compared in constant time.

## When to use it

- Integrity of files, artifacts, cache entries and downloads, where the digest is published or stored next to the data.
- Authenticating messages between parties that share a secret key, such as webhooks and internal queues.
- Use SIG-01 instead when the verifier must not be able to create tags, or when you cannot share a key. Use HASH-02 to derive keys, and HASH-03 for passwords. A plain hash is never right for either.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Digest | SHA-384 | Meets CNSA 2.0 and is not open to length extension, because it is a truncated SHA-512. It runs at SHA-512 speed on 64-bit hardware. Grover's algorithm leaves it with ample margin. |
| Digest format | `sha384-<base64>`, the [Subresource Integrity](https://www.w3.org/TR/SRI/) syntax | The algorithm travels with the value, so you can raise the minimum later and never have to guess what a stored digest is. Browsers and package managers already use this format. |
| Verification policy | Accept SHA-384 and SHA-512; accept SHA-256 only for data written by older systems | SHA-256 is not broken, but it is below the CNSA 2.0 bar. MD5 and SHA-1 are never accepted. |
| Canonical form | Standard base64 with padding, one spelling per digest | Two spellings of the same digest would let a cache or allow-list miss a match. |
| MAC | HMAC-SHA-384, 48-byte tag | HMAC stays secure even where the hash has collision weaknesses. Never `hash(key ‖ message)`: with SHA-256 or SHA-512 an attacker can extend the message. |
| MAC key | At least 32 bytes, one per purpose (derive with HASH-02) | A key shared across purposes lets a tag from one place be replayed in another. |
| MAC comparison | Constant time, and refuse any tag that is not full length | A comparison that stops at the first wrong byte leaks timing. Accepting a truncated tag lets an attacker guess a short prefix. |

**SHA-3:** SHA3-384 is a sound alternative if you want a design unrelated to SHA-2. The pattern does not use it by default because SRI does not define it and hardware support is less common.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/digest.go](go/digest.go) | Standard library `crypto/sha512`, `crypto/hmac` |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `aws-lc-rs` `digest` and `hmac` |
| Java | [java/.../Digests.java](java/src/main/java/io/github/morsec/pqcpatterns/hash01/Digests.java) | JDK `MessageDigest` and `Mac` |

```go
integrity := digest.Sum(artifact)                      // "sha384-..."
err := digest.Check(integrity, downloaded, digest.Strong)

tag, _ := digest.Tag(webhookKey, body)                 // 48 bytes
err = digest.Verify(webhookKey, body, receivedTag)     // constant time, full length only
```

For files, use `SumReader` (Go and Rust) or `sum(InputStream)` (Java), which stream the input.

Tests check that:

- SHA-384 of `"abc"` matches the FIPS 180-4 example, and HMAC-SHA-384 matches RFC 4231 test case 6.
- MD5 and SHA-1 digests, SHA-256 under the strong policy, a missing separator, a truncated value, the URL-safe alphabet, extra padding and non-canonical base64 are all refused.
- A tampered message, a flipped tag bit, a truncated tag and a short key are all refused.
- Rust and Java check every digest in the Go-generated [testdata/vector.json](testdata/vector.json), reject its bad examples and verify its HMAC tag.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| MD5 or SHA-1 for anything security-relevant | Practical collisions exist | [`pqc-hash-weak`](../../rules/) |
| Comparing MACs with `bytes.Equal`, `Arrays.equals` or `==` | Leaks how many bytes matched, so a tag can be forged byte by byte | [`pqc-mac-compare`](../../rules/) (Go, Java) |
| `sha256(key ‖ message)` as a MAC | Length extension lets an attacker append data and compute a valid tag | Review item |
| Truncating tags to save space | Each removed byte makes guessing 256 times easier | Review item |
| Bare hex digests with no algorithm | You cannot tell, or change, what produced them | Review item |
| A plain hash for passwords or key derivation | Use HASH-03 and HASH-02 | Review item |

## Threat notes

- Digests protect integrity only if the digest itself comes from a trusted place, such as a signed manifest or a separate channel. A digest stored next to the file it protects stops accidents, not attackers. Sign the manifest with SIG-01 or SIG-02.
- Quantum computers give at most a square-root speed-up on hash preimages (Grover) and less on collisions, so SHA-384 and HMAC-SHA-384 keep a wide margin. There is no harvest-now-decrypt-later risk here; hashes are on this list because MD5 and SHA-1 still turn up in every crypto inventory.
- Anyone who holds an HMAC key can create tags. If verifiers should not be able to sign, use signatures.

## Migration

1. Write new digests as `sha384-...` and verify with the compatible policy, so existing SHA-256 digests keep working.
2. Rewrite stored digests as data is next touched, or in a background job.
3. Switch verifiers to the strong policy once no SHA-256 digests remain.
4. For MACs, run old and new keys side by side: accept tags from either, issue tags with the new one, then retire the old key.

## References

- [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) (SHA-2), [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) (SHA-3)
- [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) (HMAC), [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231) (HMAC-SHA-2 test vectors)
- [W3C Subresource Integrity](https://www.w3.org/TR/SRI/)
- Go [`crypto/sha512`](https://pkg.go.dev/crypto/sha512), [`crypto/hmac`](https://pkg.go.dev/crypto/hmac), [aws-lc-rs](https://docs.rs/aws-lc-rs), Java [`MessageDigest`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/java/security/MessageDigest.html)
