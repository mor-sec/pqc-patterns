# SYM-03: Streaming and large-file encryption (segmented AES-256-GCM)

## Intent

Encrypt files, backups and uploads of any size with constant memory, so that nobody without the key can read them and nobody can modify, reorder, truncate or extend them without detection.

## When to use it

- Encrypting data that does not fit comfortably in memory: backups, exports, media, log archives, object storage uploads.
- Encrypting data you produce or consume as a stream, such as an HTTP upload you pipe straight to storage.
- Use [SYM-01](../sym-01-aead-at-rest/) instead for records and fields that fit in memory. It is simpler and its output is smaller.
- Use [KX-03](../kx-03-hpke-hybrid-envelope/) to wrap the master key for a recipient who holds a key pair rather than a shared key.

## Recommended construction

A single AES-GCM call cannot safely encrypt an unbounded stream. GCM is limited to about 64 GiB per nonce, and its decrypt step only authenticates after it has seen everything, so you would have to buffer the whole file. The fix is the "online AEAD" or STREAM construction used by Google Tink and age: split the plaintext into fixed segments and seal each one with its own nonce.

| Choice | Value | Why |
| --- | --- | --- |
| Algorithm | AES-256-GCM per segment | Keeps a 128-bit margin against Grover's algorithm, as in SYM-01. |
| Per-stream key | HKDF-SHA-256 from the master key, a random 32-byte salt and the associated data | Each stream gets a fresh key, so nonce reuse across streams is not a concern and one key never approaches the GCM limits. HMAC-SHA-256 keeps 128-bit quantum security as a key derivation function ([HASH-02](../hash-02-hkdf-key-derivation/)). |
| Segment size | 64 KiB of plaintext | Large enough that the 16-byte tag per segment costs 0.02%, small enough for constant memory. |
| Nonce | 7-byte random prefix, 4-byte segment counter, 1-byte last-segment flag | The counter stops reordering. The flag stops truncation at a segment boundary and appending. |
| Associated data | Bound into the per-stream key | A stream cannot be moved to another object name, bucket or tenant. |
| Maximum size | 2^32 segments (256 TiB) per stream | Encryption fails rather than wrapping the counter. |

CNSA 2.0 also specifies AES-256, so there is no separate CNSA variant.

Wire format, identical in all three languages:

```
header:   version (0x01) || salt (32) || nonce prefix (7)
segments: ciphertext || tag (16), repeated

stream key = HKDF-SHA-256(ikm = master key, salt = salt, info = "pqc-patterns/sym-03/v1" || associated data)
nonce(i)   = nonce prefix (7) || i (4 bytes, big-endian) || last (1 byte: 0x01 on the final segment, else 0x00)
```

Every segment carries exactly 64 KiB of plaintext except the last, which carries 0 to 64 KiB. Empty input is a single empty final segment. Ciphertext size is plaintext size plus 40 bytes plus 16 bytes per segment.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/stream.go](go/stream.go) | Standard library (`crypto/cipher`, `crypto/hkdf`) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `aws-lc-rs` |
| Java | [java/.../StreamingAead.java](java/src/main/java/io/github/morsec/pqcpatterns/sym03/StreamingAead.java) | JDK AES-GCM, Bouncy Castle HKDF |

```go
ad := []byte("backups/2026-10-23.tar")
err := stream.Encrypt(dst, src, dataKey, ad)

// Decrypt to a temporary file and only publish it once Decrypt succeeds.
tmp, _ := os.CreateTemp(dir, "restore-*")
if err := stream.Decrypt(tmp, src, dataKey, ad); err != nil {
	tmp.Close()
	os.Remove(tmp.Name())
	return err
}
tmp.Close()
os.Rename(tmp.Name(), finalPath)
```

```rust
sym_03_streaming_encryption::encrypt(File::open(path)?, BufWriter::new(out), &data_key, ad)?;
```

```java
try (InputStream in = Files.newInputStream(path); OutputStream out = Files.newOutputStream(dst)) {
  StreamingAead.encrypt(in, out, dataKey, ad);
}
```

Each implementation's tests cover:

- round trips at 0, 1 and 64 KiB ± 1 bytes and several multi-segment sizes, including readers that return one byte at a time;
- rejection of a dropped final segment (including when the plaintext is an exact multiple of 64 KiB), mid-segment truncation, appended bytes, two streams joined together, swapped segments, every single-bit flip in a stream, wrong associated data, a wrong key and empty input;
- read and write errors being reported as I/O errors rather than decryption failures;
- the shared vector in [testdata/vector.json](testdata/vector.json), which every language must reproduce byte for byte (a short stream in full, and a three-segment stream by SHA-256).

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| CTR, CFB or OFB stream modes, or CBC, without a MAC | No integrity: an attacker can flip plaintext bits at will | [`pqc-sym-unauthenticated-mode`](../../rules/) |
| AES-128 keys | Leaves only about 64 bits of security against a large quantum computer | [`pqc-sym-aes-128`](../../rules/) |
| One GCM call over a whole large file | Hits the 64 GiB per-nonce limit, and forces you to buffer everything before you can trust any of it | Review item |
| Segments with independent random nonces and no counter or last flag | Segments can be reordered, dropped or duplicated without detection | Review item |
| Encrypt-then-MAC over the whole file, verified at the end | Plaintext is released before it is checked, and memory or a second pass is needed | Review item |
| Acting on decrypted output before `Decrypt` returns success | A truncated stream is only detected at the end | Review item |
| Fixed or counter-from-zero nonces under a long-lived key | One GCM nonce reuse leaks the authentication key | [`pqc-sym-static-nonce`](../../rules/) |

## Threat notes

- Protects confidentiality and integrity of whole streams, including their length and segment order, against an attacker with a future quantum computer.
- Decryption is online: each segment is authenticated before it is written, but whether the stream is complete is only known at the end. Write to a temporary location and rename on success, or make the consumer roll back on error.
- A stream reveals the exact plaintext length and nothing else about it. Pad before encrypting if size matters.
- The header salt and prefix are random, so encrypting the same file twice gives unrelated ciphertexts.
- As with SYM-01, the real risk is the master key. If it was delivered with RSA or ECDH, wrap it with KX-03 instead.

## Migration

1. If you encrypt files with AES-CBC, AES-CTR or a home-grown chunking scheme, write new files with this pattern and keep the old reader for existing files, keyed off a file extension, object metadata or the version byte.
2. If you use one GCM call per file today, the format differs: keep the old reader for old objects and re-encrypt them in the background.
3. Google Tink's `AES256_GCM_HKDF_4KB` / `1MB` streaming AEAD key templates and age use the same design. They are good choices too if you already depend on them, but their wire formats differ from this one.

## References

- Hoang, Reyhanitabar, Rogaway and Vizár, [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance](https://eprint.iacr.org/2015/189) (the STREAM construction)
- Google Tink [streaming AEAD](https://developers.google.com/tink/streaming-aead)
- [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) (GCM limits), [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) (HKDF)
- Go [`crypto/cipher`](https://pkg.go.dev/crypto/cipher), Rust [`aws-lc-rs`](https://docs.rs/aws-lc-rs), Java [`Cipher`](https://docs.oracle.com/en/java/javase/21/docs/api/java.base/javax/crypto/Cipher.html)
