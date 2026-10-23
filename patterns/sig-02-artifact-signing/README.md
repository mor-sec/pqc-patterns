# SIG-02: Signing release artifacts with ML-DSA

## Intent

Let anyone who downloads a release, firmware image or build output check that it came from you and was not changed, with a signature a quantum computer cannot forge, and without trusting anything the download itself claims.

## When to use it

- Release binaries, archives, packages, firmware images, SBOMs and other files you publish.
- Build outputs passed between CI stages or into deployment, where the next stage must know which pipeline produced them.
- Use [SIG-01](../sig-01-mldsa-api-signing/) for HTTP requests and [SESS-02](../sess-02-mldsa-signed-tokens/) for tokens.
- For firmware that must meet CNSA 2.0, the NSA prefers the stateful hash-based schemes LMS and XMSS. SIG-03 (planned) covers them.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Algorithm | ML-DSA-87, hedged (randomised) signing | Release keys live for years and protect everything signed with them, so this pattern uses the highest parameter set. The 4.6 KB signature is irrelevant next to an artifact. It is also the CNSA 2.0 level. |
| Context string | `pqc-patterns/sig-02/artifact/v1` | FIPS 204 domain separation. A signature made for an API request or token with the same key can never be passed off as an artifact signature. |
| What is signed | A seven-line text statement: format version, algorithm, key ID, artifact name, size and SHA-512, signing time | Signing a statement rather than the raw file lets verifiers check the signature before reading a large file. The name stops a valid signature for one release being shown next to another, and the size stops length games. |
| Digest | SHA-512, streamed | Constant memory for any artifact size. Collision resistance stays far above the signature's security level, even against quantum search. |
| Key ID | Hex SHA-256 of the signer's `SubjectPublicKeyInfo`, as in pattern KEY-01 | Verifiers look keys up in their own trusted set, which is how rotation and revocation work. The signature file never carries a public key. |
| Verification order | Parse strictly, then check the key, then the signature, then the name the caller expects, then size and digest | Nothing from an unauthenticated file is acted on. The name comes from the caller, never from the file. |
| Encoding | One canonical spelling per field: lower-case hex, no leading zeros, UTC with whole seconds, standard base64, LF line endings | One statement, one encoding, so there is no room for parser differences between languages. |

The signature file, for example `myapp-1.4.2-linux-amd64.tar.gz.sig`:

```
pqc-patterns-signature-v1
algorithm: ML-DSA-87
key: 07e57c4f14dbad1267f621ec3777b4e2e6c4fbc4c22fbb87510ff8e0b3c6a642
name: myapp-1.4.2-linux-amd64.tar.gz
size: 1000
sha512: 5096498d96f50f9a137c4db5b8b0cd38…
signed: 2026-10-23T12:00:00Z
signature: YYxNu9zzVrsCXq1MAuITisslFcj1k3SA…
```

The signature covers the first seven lines exactly as written, including their line feeds.

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/artifacts.go](go/artifacts.go) | Standard library `crypto/mldsa` |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | RustCrypto `ml-dsa` 0.1 (not independently audited, see SIG-01), `aws-lc-rs` for SHA-2 |
| Java | [java/.../ArtifactSigner.java](java/src/main/java/io/github/morsec/pqcpatterns/sig02/ArtifactSigner.java) | Bouncy Castle 1.86 |

```go
// In the release pipeline, with the key from KEY-01 or an HSM.
signer, _ := artifacts.NewSigner(seed)
f, _ := os.Open("dist/myapp-1.4.2-linux-amd64.tar.gz")
sig, _ := signer.Sign("myapp-1.4.2-linux-amd64.tar.gz", f)
os.WriteFile("dist/myapp-1.4.2-linux-amd64.tar.gz.sig", sig, 0o644)

// In the installer, with the release keys pinned in the installer itself.
v := artifacts.NewVerifier(releaseKey2026, releaseKey2027)
st, err := v.Verify(sig, "myapp-1.4.2-linux-amd64.tar.gz", download)
if err != nil {
	return fmt.Errorf("refusing to install: %w", err)
}
```

Each implementation's tests cover:

- sign and verify at several sizes, including empty artifacts, and verification with two trusted keys during rotation;
- rejection of a flipped bit, a truncated or extended artifact, a signature for another release name, an untrusted key, the same key signing under another context string, and edited statement fields;
- the shared vector in [testdata/vector.json](testdata/vector.json): every language must derive the same public key and key ID from the seed, build a byte-identical statement for the same artifact and time, verify the Go signature, and reject 16 malformed or non-canonical variants of it.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Release signing with RSA, ECDSA or Ed25519 only (GPG, minisign, cosign keys today) | A quantum attacker can forge releases, and old signatures stay forgeable forever | [`pqc-sig-classical-keygen`](../../rules/) flags new classical keys |
| Publishing only a checksum file next to the download | Anyone who can change the download can change the checksum | Review item |
| Verifying a signature without checking the artifact name | A valid signature for an old, vulnerable release can be served next to it | Review item |
| Taking the public key from the signature file or the download page | The attacker supplies their own key | Review item |
| Hashing the whole artifact before checking the signature, or reading past the signed size | Wasted work and a denial-of-service lever on untrusted input | Review item |
| Signing keys on build machines or in CI secrets with broad access | One compromised job can sign anything | Review item |
| Treating the `signed` time as trusted | It is the signer's claim. Use a timestamping service or transparency log if you need proof of time | Review item |

## Threat notes

- Protects against tampered or substituted downloads, mirrors serving old releases under new names, and forgery by a quantum attacker.
- Does not protect against a stolen signing key. Keep it offline or in an HSM (KEY-02, planned), sign from a dedicated, minimal job, and publish key IDs so users can notice a key they did not expect.
- Revocation is by removing a key from verifiers' trusted sets, so ship the set with your installer or updater and update it like any other code.
- A signature proves who signed, not what the build contained. Pair it with reproducible builds and provenance (SLSA, in-toto) for the supply-chain side.

## Migration

1. **Dual-sign during the transition.** Keep publishing your existing GPG, minisign or Sigstore signature and add the ML-DSA `.sig` file next to it. Old clients keep working, and new clients verify both or only the ML-DSA one.
2. **Ship the new public keys in a release signed the old way,** so existing installs learn them through a channel they already trust.
3. **Make updaters require the ML-DSA signature** once most installs have the new keys, then stop producing classical signatures.
4. **Re-sign long-lived artifacts** that are still downloaded, such as old firmware or installers, so their authenticity outlives the classical keys.
5. Sigstore, GPG and other ecosystems are adding post-quantum algorithms. When yours supports ML-DSA, prefer it, and keep this pattern's checks (name, size, context) in mind when you configure it.

## References

- [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA, including context strings in section 5.2)
- [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) (SLH-DSA, a conservative hash-based alternative for offline root keys)
- NSA CNSA 2.0 algorithm suite (ML-DSA-87; LMS and XMSS for software and firmware signing)
- [SLSA](https://slsa.dev/) and [in-toto](https://in-toto.io/) for build provenance
- Go [`crypto/mldsa`](https://pkg.go.dev/crypto/mldsa), RustCrypto [`ml-dsa`](https://docs.rs/ml-dsa), [Bouncy Castle](https://www.bouncycastle.org/)
