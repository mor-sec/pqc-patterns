# pqc-patterns

Copy-ready patterns for writing production code with post-quantum safe cryptography in **Go, Rust and Java**.

Each pattern solves one common job, such as encrypting data at rest, signing API requests or configuring TLS. It gives a recommended construction, runnable and tested code in all three languages, the anti-patterns to look for in review, and a migration path from the classical version.

Read it as a website, with a migration guide, at **[mor-sec.github.io/pqc-patterns](https://mor-sec.github.io/pqc-patterns/)**.

## Defaults

| Job | Default | CNSA 2.0 |
| --- | --- | --- |
| Key exchange and public-key encryption | Hybrid ML-KEM-768 + X25519 | ML-KEM-1024 |
| Signatures | ML-DSA-65 | ML-DSA-87 |
| Symmetric encryption | AES-256-GCM | AES-256-GCM |
| Hashing and KDFs | SHA-256 or above, HKDF | SHA-384 or above |

## Patterns

| ID | Pattern | Go | Rust | Java |
| --- | --- | --- | --- | --- |
| [HASH-01](patterns/hash-01-digests-and-macs/) | Content digests and MACs | stdlib | aws-lc-rs | JDK |
| [HASH-02](patterns/hash-02-hkdf-key-derivation/) | Deriving purpose-bound keys with HKDF | stdlib | aws-lc-rs | Bouncy Castle |
| [HASH-03](patterns/hash-03-password-hashing/) | Storing passwords with Argon2id | x/crypto | RustCrypto argon2 | Bouncy Castle |
| [KX-01](patterns/kx-01-hybrid-tls/) | Hybrid post-quantum TLS 1.3 | stdlib | rustls + aws-lc-rs | Bouncy Castle JSSE |
| [KX-02](patterns/kx-02-hybrid-mtls/) | Mutual TLS between services | stdlib | rustls + aws-lc-rs | Bouncy Castle JSSE |
| [KX-03](patterns/kx-03-hpke-hybrid-envelope/) | Hybrid envelope encryption with HPKE | stdlib | hpke-rs + libcrux | Bouncy Castle |
| [PKI-01](patterns/pki-01-mldsa-certificates/) | ML-DSA certificates and fully post-quantum TLS | not yet (no ML-DSA in `crypto/x509`) | rustls + rcgen | Bouncy Castle JSSE |
| [SESS-02](patterns/sess-02-mldsa-signed-tokens/) | Signed bearer tokens (JWS) with ML-DSA | stdlib | RustCrypto ml-dsa | Bouncy Castle + Jackson |
| [SIG-01](patterns/sig-01-mldsa-api-signing/) | Signing API requests with ML-DSA | stdlib | RustCrypto ml-dsa | Bouncy Castle |
| [SYM-01](patterns/sym-01-aead-at-rest/) | Authenticated encryption at rest | stdlib | aws-lc-rs | JDK |

The full planned catalog of 24 patterns is tracked in the project plan.

## Checker

[`rules/`](rules/) holds Semgrep rules for Go, Java and Rust. They flag quantum-vulnerable or weak cryptography, such as RSA encryption, classical-only TLS groups, AES-128, static nonces and disabled certificate checks, and link each finding to the pattern that fixes it:

```sh
semgrep scan --config rules/ path/to/your/code
```

## Cross-language test vectors

Each pattern has a `testdata/vector.json` written by the Go implementation. The Rust and Java tests decrypt or verify it, which shows the wire formats really are the same in all three languages. To regenerate a vector:

```sh
cd patterns/<pattern>/go && PQC_WRITE_VECTORS=1 go test ./...
```

## Running the tests

| Language | Requirement | Command |
| --- | --- | --- |
| Go | Go 1.27+ | `cd patterns/<pattern>/go && go test ./...` |
| Rust | Rust 1.85+, a C compiler and CMake (for aws-lc-sys) | `cargo test` from the repo root |
| Java | Java 21+ and Maven | `mvn test` from the repo root |

## Building the docs site

The site is built with MkDocs from [`docs/`](docs/) and from the README of every pattern and of the checker, so there is one copy of each page:

```sh
pip install -r tools/docs-requirements.txt
mkdocs serve        # or: mkdocs build --strict
```

## Library maturity

- Go's standard library and Bouncy Castle are the most mature options here.
- In Rust, `ml-dsa` (RustCrypto) and `libcrux` have not been independently audited. Each pattern page says which crate it uses and why.
- Treat this repo as reference code. Review it against your own threat model before you ship it.

## License

[MIT](LICENSE)
