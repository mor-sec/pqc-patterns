# pqc-patterns

Copy-ready patterns for writing production code with post-quantum safe cryptography in **Go, Rust and Java**.

Each pattern solves one common job, such as encrypting data at rest, signing API requests or configuring TLS. It gives a recommended construction, runnable and tested code in all three languages, the anti-patterns to look for in review, and a migration path from the classical version.

<div class="grid cards" markdown>

- **New to post-quantum cryptography?** Read [The quantum problem](guide/quantum-threat.md) for a plain-language explanation, and keep the [glossary](guide/glossary.md) handy.
- **Ready to plan the work?** Read [Start here](guide/index.md), then [Planning a migration](guide/migration.md).
- **Need code for one job?** Go to the [pattern list](patterns/index.md).
- **Auditing a codebase?** Run the [checker](checker.md) to find quantum-vulnerable and weak cryptography.

</div>

## Defaults

| Job | Default | CNSA 2.0 |
| --- | --- | --- |
| Key exchange and public-key encryption | Hybrid ML-KEM-768 + X25519 | ML-KEM-1024 |
| Signatures | ML-DSA-65 | ML-DSA-87 |
| Symmetric encryption | AES-256-GCM | AES-256-GCM |
| Hashing and KDFs | SHA-256 or above, HKDF | SHA-384 or above |

[Choosing algorithms](guide/algorithms.md) explains each choice.

## How the code is tested

- Every pattern has tests in all three languages, run in CI on each change.
- Most patterns have a cross-language test vector: Go writes it, and Rust and Java must decrypt or verify it. That shows the wire formats really match.
- The pattern code must pass the repo's own checker.

Treat this as reference code. Review it against your own threat model before you ship it, and check the library notes on each pattern page for maturity.
