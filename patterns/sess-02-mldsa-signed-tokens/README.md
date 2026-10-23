# SESS-02: Signed bearer tokens with ML-DSA (JWS, RFC 9964)

## Intent

Issue and verify short-lived bearer tokens, such as access tokens between services, as JWTs signed with ML-DSA. Use the JOSE algorithm registered in RFC 9964, so other standard libraries can verify them as they add support. Close the verification mistakes that have caused most JWT vulnerabilities.

## When to use it

- Access tokens issued by an authorisation service and checked by many resource servers.
- Service-to-service tokens that must pass through proxies, where mTLS (KX-02) alone does not carry the caller's identity far enough.
- Do **not** use it for browser sessions. An ML-DSA-65 token is about 4.6 KB, which is over the 4 KB cookie limit. Use an opaque random session ID stored server-side ([SESS-01](../sess-01-opaque-session-tokens/)).
- Use SIG-01 when you need to sign a whole request (method, path, body) rather than carry claims.

## Recommended construction

| Choice | Value | Why |
| --- | --- | --- |
| Format | JWS compact serialisation | Standard JWT wire format. |
| Algorithm | `ML-DSA-65` (RFC 9964); `ML-DSA-87` for CNSA 2.0 | Post-quantum signature registered for JOSE. Pure ML-DSA, not HashML-DSA. |
| Context string | Empty | RFC 9964 section 5 requires it. Domain separation comes from `typ`. |
| Header | Exactly `alg`, `typ` and `kid`; anything else is rejected | Refusing `jku`, `x5u`, `jwk` and `crit` removes the key-injection and unknown-extension classes of bugs. Duplicate members are rejected too. |
| Algorithm check | The verifier accepts one fixed algorithm | Stops `alg: none` and algorithm-confusion attacks. The token never chooses how it is verified. |
| Type | `typ` checked against one value per token kind (`at+jwt` for access tokens, RFC 9068) | Explicit typing (RFC 8725 section 3.11) stops an ID token or a refresh token being replayed as an access token. |
| Key selection | `kid` looked up in the verifier's own key set | Supports rotation. Keys never come from the token. |
| Order | Header, then signature, then claims | No claim is parsed or trusted before the signature is checked. |
| Claims | `iss` and `aud` must equal the verifier's configured values; `iat` and `exp` required | `aud` stops a token for one service being used at another. |
| Lifetime | At most 1 hour (`exp - iat`), 30 s clock leeway | Bearer tokens can be stolen. Short lifetimes limit the window. |
| Private key storage | The 32-byte FIPS 204 seed | The RFC 9964 JWK `priv` value is the seed too. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/tokens.go](go/tokens.go) | Standard library `crypto/mldsa` and `encoding/json` |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | RustCrypto `ml-dsa` 0.1 (unaudited, see SIG-01), `serde_json`, `base64` |
| Java | [java/.../MlDsaTokens.java](java/src/main/java/io/github/morsec/pqcpatterns/sess02/MlDsaTokens.java) | Bouncy Castle 1.86, Jackson |

```go
signer := &tokens.Signer{KeyID: "auth-2026-10", Key: sk}
tok, _ := signer.Sign(tokens.Claims{Issuer: "https://auth.internal", Subject: "svc-billing",
	Audience: "https://payments.internal", IssuedAt: now.Unix(), ExpiresAt: now.Add(15 * time.Minute).Unix()})

v := &tokens.Verifier{Issuer: "https://auth.internal", Audience: "https://payments.internal", Keys: trusted}
claims, err := v.Verify(tok)
```

Publish verification keys as RFC 9964 JWKs, for example in a JWKS document:

```json
{"kty": "AKP", "alg": "ML-DSA-65", "kid": "auth-2026-10", "pub": "<base64url of the 1952-byte public key>"}
```

Tests in all three languages cover:
- round trips
- tampered claims
- `alg: none` and other algorithms
- a wrong or missing `typ`
- `jku` and `crit` headers
- duplicate header members
- unknown `kid`
- a signature made with a non-empty context
- a signature from another key
- wrong issuer or audience
- expired, future-dated, missing or extreme timestamps
- an over-long lifetime
- malformed tokens

Rust and Java also verify the Go-generated token in [testdata/vector.json](testdata/vector.json).

**Library notes**

- **Go:** `encoding/json` silently keeps the last of two duplicate members, so the header is parsed token by token to reject duplicates and unknown members.
- **Checker:** `pqc-sig-mldsa-no-context` flags ML-DSA with an empty context. JOSE and COSE are the exception, because RFC 9964 requires the empty context. This pattern keeps the empty context in one named constant.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Taking the algorithm from the token's `alg` header | `alg: none` and algorithm confusion | Review item |
| Fetching keys from `jku`, `x5u` or an embedded `jwk` | The attacker supplies the key that verifies their token | Review item |
| Decoding claims before checking the signature, or using a "decode" API in auth code | Unverified claims end up trusted | Review item |
| No `aud` check, or accepting any audience from a list | Tokens for one service work at another | Review item |
| No `typ` check | Other token kinds from the same issuer are accepted | Review item |
| Long-lived bearer tokens, or no `exp` | A stolen token works for days | Review item |
| RS256, ES256 or EdDSA for new token keys | Forgeable once a quantum computer exists | [`pqc-sig-classical-keygen`](../../rules/) |
| Putting ML-DSA JWTs in cookies | Over the 4 KB cookie limit; browsers drop them | Review item |

## Threat notes

- Protects token integrity and issuer authenticity against classical and quantum forgery.
- Does not protect confidentiality. Claims are only base64url-encoded, so keep secrets and personal data out of them.
- Bearer tokens can be replayed by whoever holds them until they expire. Use short lifetimes, and sender-constrained tokens (DPoP or mTLS-bound) where theft is a concern.
- Revocation is not covered. Rely on short lifetimes, or have resource servers check a deny-list of `jti` values.

## Migration

1. Add ML-DSA keys to the issuer's JWKS beside the current RS256 or ES256 keys, and roll out verifiers that accept both algorithms. Each `kid` should map to exactly one algorithm.
2. Start issuing ML-DSA tokens for one audience at a time and watch header sizes. Some proxies and load balancers cap request headers at 8 KB.
3. Once every audience accepts ML-DSA, stop issuing classical tokens. When the last of them has expired, remove the classical keys from the JWKS.

## References

- [RFC 9964](https://www.rfc-editor.org/rfc/rfc9964) (ML-DSA for JOSE and COSE)
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) (JWS), [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) (JWT), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) (JWT best current practice), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) (JWT access tokens)
- [FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf) (ML-DSA)
