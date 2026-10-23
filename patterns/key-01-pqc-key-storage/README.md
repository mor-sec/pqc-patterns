# KEY-01: Generating, encoding and storing post-quantum keys

## Intent

Generate ML-DSA and ML-KEM key pairs, write them in the standard formats every library is converging on, read them back without accepting anything ambiguous, and keep private keys out of reach on disk.

## When to use it

- Any service that holds its own ML-DSA signing key (SIG-01, SESS-02, PKI-01) or ML-KEM decryption key (KX-03).
- Exchanging public keys with other teams, tools or languages.
- Moving keys between Go, Rust, Java, OpenSSL and Bouncy Castle.
- Use a KMS or HSM instead (KEY-02, planned) when the platform supports ML-DSA or ML-KEM and you can avoid holding the private key at all. This pattern still applies to the public keys.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Algorithms | ML-DSA-65 and ML-KEM-768; ML-DSA-87 and ML-KEM-1024 for CNSA 2.0 | NIST category 3 and 5 parameter sets, as used across this catalog. |
| What to store | The seed only: 32 bytes for ML-DSA (FIPS 204 ξ), 64 for ML-KEM (FIPS 203 d‖z) | The expanded private key is 2.4 to 4.9 KB and can be recomputed from the seed. Storing only the seed means one canonical form and no risk of an expanded key that does not match its seed. |
| Private key format | PKCS#8 `PrivateKeyInfo` with the seed choice `[0] IMPLICIT OCTET STRING`, PEM label `PRIVATE KEY` | The form RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM) define, and the only one Go's `crypto/x509` accepts. |
| Public key format | `SubjectPublicKeyInfo` with the raw key in the BIT STRING and no parameters, PEM label `PUBLIC KEY` | Same RFCs, and the same form as in certificates. |
| Parsing | Re-encode and compare. Reject the expanded and "both" private key forms, parameters, trailing data, extra PEM blocks, PEM headers, and public keys that fail the FIPS 203 modulus check | One key, one encoding, one key ID. A lenient parser is how two components end up disagreeing about which key is in use. |
| Key ID | Lowercase hex SHA-256 of the `SubjectPublicKeyInfo` DER | Stable across languages, and binds the algorithm as well as the key bytes. |
| Files | Created with mode 0600 and `O_EXCL`; readers refuse files that group or others can access | The OpenSSH rule. Never overwrite a key in place. Write a new one and rotate. |
| Randomness | The OS CSPRNG only | The seed is the whole secret. |

Wire format, for ML-DSA-65 (ML-KEM is the same with its OID and a 64-byte seed):

```
30 34                               PrivateKeyInfo
   02 01 00                         version 0
   30 0b 06 09 60 86 48 01 65 03 04 03 12    id-ml-dsa-65 (2.16.840.1.101.3.4.3.18)
   04 22 80 20 <32-byte seed>       OCTET STRING { [0] seed }
```

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/keys.go](go/keys.go) | Standard library (`crypto/mldsa`, `crypto/mlkem`, `encoding/asn1`, `encoding/pem`) |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | RustCrypto `ml-dsa` 0.1 and `ml-kem` 0.3 with `pkcs8` (not independently audited, see SIG-01), `zeroize` |
| Java | [java/.../PqcKeys.java](java/src/main/java/io/github/morsec/pqcpatterns/key01/PqcKeys.java) | Bouncy Castle 1.86 |

```go
k, _ := keys.Generate(keys.MLDSA65)
keys.WritePrivateKeyFile("/etc/myapp/signing.pem", k) // 0600, never overwrites
os.WriteFile("signing.pub.pem", k.PublicKeyPEM(), 0o644)
log.Printf("new signing key %s", k.KeyID())

k, err := keys.ReadPrivateKeyFile("/etc/myapp/signing.pem")
sk, _ := k.PrivateKey() // *mldsa.PrivateKey, ready for SIG-01
```

Each implementation's tests cover:

- round trips for all four algorithms, and using the loaded key to sign;
- key IDs, rejection of wrong-length seeds, and owner-only files that are never overwritten and are refused when world-readable;
- the shared vector in [testdata/vector.json](testdata/vector.json): for each algorithm, the PEM private key, public key and key ID derived from the seed `00 01 02 …`, which every language must reproduce character for character, plus ten malformed private keys and five or six malformed public keys that every language must reject.

The Go tests also check that the ML-DSA encodings match Go's own `crypto/x509`, an independent implementation of RFC 9881.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Storing the expanded private key, or both forms | Larger, not canonical, and a mismatched seed and expanded key can sign with one key while reporting another | Review item |
| Raw key bytes in files or environment variables, with no algorithm identifier | Nothing records which parameter set the bytes belong to | Review item |
| Private key files readable by other users, or overwritten in place | Key theft, and a crash mid-write loses the only copy | Review item |
| Private keys in source code, container images or CI logs | Anyone with read access has the key | Review item |
| Key IDs from a counter or a hash of the private key | A counter is not unique across systems. Hashing the private key risks leaking it | Review item |
| Generating keys from `math/rand` or a fixed seed | Predictable keys | [`pqc-token-weak-random`](../../rules/) (with SESS-01) for the common cases |
| Legacy encrypted PEM (`Proc-Type: 4,ENCRYPTED`) or PBES1 PKCS#8 | Weak, obsolete key wrapping | Review item |

## Threat notes

- Protects against key confusion between components, parsers that accept more than one encoding, and keys left readable on shared machines.
- Does not encrypt the key at rest. File permissions only stop other local users. For protection against disk or backup theft, wrap the PEM with [SYM-01](../sym-01-aead-at-rest/) under a key held in a KMS, or use the KMS or HSM directly (KEY-02, planned).
- Memory: Rust wipes seeds on drop with `zeroize`, and Java's `KeyPair.destroy()` overwrites its seed array. Go cannot reliably wipe memory. In all three, the underlying library keeps its own expanded copy while a key is in use.
- The key ID is public. It identifies a key and reveals nothing about the private half.

## Migration

1. **Keys from OpenSSL 3.5.** By default, OpenSSL writes ML-DSA and ML-KEM private keys in the "both" form, which this pattern (and Go's `crypto/x509`) rejects. Convert them once with `openssl pkey -in old.pem -out new.pem -provparam ml-dsa.output_formats=seed-only`, or `ml-kem.output_formats=seed-only` for ML-KEM keys.
2. **Keys from draft-era tools** may use pre-standard OIDs or encodings. Regenerate them, or re-encode from the seed if the tool exposes it.
3. **Raw seed files.** Wrap each in PKCS#8 with `FromSeed` and `PrivateKeyPEM`. The key ID does not depend on the file format, so existing references survive if you were already hashing the SPKI.
4. **Rotation.** Generate a new key into a new file, publish its public key and key ID, switch signers or decrypters over, then retire the old file. Never rewrite a key file in place.

## References

- [RFC 9881](https://www.rfc-editor.org/rfc/rfc9881) (ML-DSA in X.509 and PKCS#8), [RFC 9935](https://www.rfc-editor.org/rfc/rfc9935) (ML-KEM in X.509 and PKCS#8)
- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) (ML-KEM, including the encapsulation key check in section 7.2), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) (ML-DSA)
- [RFC 5958](https://www.rfc-editor.org/rfc/rfc5958) (PKCS#8), [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) (PEM labels)
- Go [`crypto/x509.ParsePKCS8PrivateKey`](https://pkg.go.dev/crypto/x509#ParsePKCS8PrivateKey), RustCrypto [`ml-dsa`](https://docs.rs/ml-dsa) and [`ml-kem`](https://docs.rs/ml-kem), [Bouncy Castle](https://www.bouncycastle.org/)
