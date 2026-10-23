# PQC checker (Semgrep rules)

These rules find cryptography in Go, Java and Rust code that is not quantum-safe or is otherwise weak. Each finding points to the pattern in this repo that fixes it.

## Run it

```sh
pip install semgrep
semgrep scan --config path/to/pqc-patterns/rules/ your/code/
```

Add `--error` to fail a CI job on findings, or `--sarif -o pqc.sarif` to upload results to GitHub code scanning. Rule files are plain YAML, so you can also copy individual rules into your own Semgrep configuration.

## Rules

| Rule | Severity | Go | Java | Rust | Fix |
| --- | --- | --- | --- | --- | --- |
| `pqc-kx-rsa-encrypt` | Error | ✓ | ✓ | ✓ | [KX-03](../patterns/kx-03-hpke-hybrid-envelope/) |
| `pqc-kx-classical-ecdh` | Warning | ✓ | ✓ | ✓ | [KX-03](../patterns/kx-03-hpke-hybrid-envelope/) |
| `pqc-sig-classical-keygen` | Warning | ✓ | ✓ | ✓ | [SIG-01](../patterns/sig-01-mldsa-api-signing/) |
| `pqc-sig-mldsa-no-context` | Warning | ✓ | | ✓ | [SIG-01](../patterns/sig-01-mldsa-api-signing/) |
| `pqc-sym-unauthenticated-mode` | Error | ✓ | ✓ | ✓ | [SYM-01](../patterns/sym-01-aead-at-rest/) |
| `pqc-sym-aes-128` | Warning | ✓ | ✓ | ✓ | [SYM-01](../patterns/sym-01-aead-at-rest/) |
| `pqc-sym-static-nonce` | Error | ✓ | ✓ | ✓ | [SYM-01](../patterns/sym-01-aead-at-rest/) |
| `pqc-tls-classical-groups` | Error | ✓ | ✓ | ✓ | [KX-01](../patterns/kx-01-hybrid-tls/) |
| `pqc-tls-min-version` | Warning | ✓ | ✓ | ✓ | [KX-01](../patterns/kx-01-hybrid-tls/) |
| `pqc-tls-no-verify` | Error | ✓ | ✓ | ✓ | [KX-01](../patterns/kx-01-hybrid-tls/) |
| `pqc-tls-godebug-downgrade` | Error | Any file: Dockerfiles, manifests, env files | | | [KX-01](../patterns/kx-01-hybrid-tls/) |
| `pqc-hash-weak` | Error | ✓ | ✓ | ✓ | HASH-01 (planned) |

**Errors** mean a finding is very likely wrong in new code. **Warnings** need a human decision. For example, X25519 is fine as the classical half of a hybrid exchange, and ECDSA is fine for TLS certificates until post-quantum certificates are deployable (PKI-01).

To silence a finding you have reviewed, add `// nosemgrep: <rule-id>` on that line along with a comment explaining why.

## Limits

- **Pattern-based, not data-flow analysis.** The rules catch common shapes, such as a nonce allocated and never filled, but not every way a value can flow.
- **Test code is skipped.** Semgrep skips `test/`, `tests/` and `*_test.go` by default, and the key generation rules also skip `src/test`. Test code legitimately builds classical clients and certificates.
- **No ML-DSA context check for Java.** Bouncy Castle sets the context through a separate `setParameter` call, which a pattern cannot reliably pair with the `Signature` object.
- **Rust coverage depends on paths.** The rules match the common crates (`rsa`, `aws-lc-rs`, `rustls`, RustCrypto). Matching works best on fully written paths, so aliased imports can hide a finding.

## Develop

Each `<lang>/pqc.yaml` has a matching fixture file. Lines marked `ruleid:` must be flagged and lines marked `ok:` must not be.

```sh
semgrep --test rules/                                       # rule unit tests
semgrep scan --config rules/ --error --metrics=off patterns/   # the patterns must stay clean
```
