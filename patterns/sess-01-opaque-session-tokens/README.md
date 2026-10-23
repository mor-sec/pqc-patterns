# SESS-01: Opaque session tokens

## Intent

Keep users signed in with random, server-side session tokens that a quantum computer cannot forge, a database leak cannot replay, and the server can revoke at any time.

## When to use it

- Browser sessions after login, carried in a cookie.
- API keys and long-lived tokens for first-party clients, where every request reaches a service that can look the token up.
- Use [SESS-02](../sess-02-mldsa-signed-tokens/) instead when many independent services must check a token without a shared session store. Signed tokens cannot be revoked before they expire, and ML-DSA tokens are too large for cookies.

## Recommended construction

Opaque tokens are already post-quantum. They carry no signature or public-key operation for Shor's algorithm to break, and Grover's algorithm only halves the effective strength of the random value. JWT sessions signed with RS256, ES256 or EdDSA, by contrast, become forgeable once a large quantum computer exists. Moving browser sessions to opaque tokens removes that exposure without waiting for post-quantum signature support.

| Choice | Value | Why |
| --- | --- | --- |
| Token | `sess_` + 32 bytes from the OS CSPRNG in unpadded base64url (48 characters) | 256 bits keeps a 128-bit margin against Grover's algorithm. The prefix lets secret scanners spot leaked tokens. Pick one unique to your application. |
| Server-side key | SHA-256 of the 32 random bytes, in hex | A leaked session table cannot be turned back into working cookies. Looking up by hash means no token is ever compared byte by byte, so there is no timing side channel. A plain hash is enough because the input is already 256 bits of randomness, unlike a password ([HASH-03](../hash-03-password-hashing/)). |
| Parsing | Exact prefix, exact length, strict base64url (no padding, no non-zero trailing bits) | Each token has exactly one valid spelling. |
| Idle timeout | 30 minutes | The top of OWASP's range for low-risk apps. Use 2 to 5 minutes for high-value apps. |
| Absolute timeout | 12 hours from login, not reset by activity or rotation | Bounds how long a stolen token is useful. Shorten it for sensitive apps. |
| Rotation | New token on every login and on every privilege change (password change, step-up authentication) | Stops session fixation. The old token is revoked straight away. |
| Errors | One error for malformed, unknown, expired and revoked | Gives an attacker nothing to probe. |
| Cookie | `__Host-session=…; Path=/; HttpOnly; Secure; SameSite=Lax`, no `Max-Age` | `__Host-` makes the browser refuse the cookie over HTTP, from a subdomain or with a wider path. `HttpOnly` keeps it from JavaScript, and `SameSite=Lax` blocks most cross-site request forgery. |

## Code

| Language | Source | Library |
| --- | --- | --- |
| Go | [go/sessions.go](go/sessions.go) | Standard library |
| Rust | [rust/src/lib.rs](rust/src/lib.rs) | `aws-lc-rs` (random and SHA-256), `base64` |
| Java | [java/.../Sessions.java](java/src/main/java/io/github/morsec/pqcpatterns/sess01/Sessions.java) | JDK only |

Each implementation has a `Store` interface with three methods (get, put, delete by session ID) and an in-memory store for tests. In production, back it with a database table or Redis, with an expiry equal to the absolute timeout.

```go
m := sessions.NewManager(store)

// Login: always a fresh token.
tok, _ := m.Create(user.ID)
http.SetCookie(w, sessions.Cookie(tok))

// Every request.
s, err := m.Validate(sessions.FromRequest(r))
if err != nil {
	http.Redirect(w, r, "/login", http.StatusSeeOther)
	return
}

// Password change or step-up authentication.
tok, _ = m.Rotate(sessions.FromRequest(r))
http.SetCookie(w, sessions.Cookie(tok))

// Logout.
m.Revoke(sessions.FromRequest(r))
http.SetCookie(w, sessions.ClearCookie())
```

Each implementation's tests cover:

- the token format and uniqueness, and that the store holds only the hash;
- the idle timeout, including activity extending it, and the absolute timeout, including through rotation;
- rotation and revocation;
- rejection of tokens from another store;
- reading the cookie back from a request;
- the shared vector in [testdata/vector.json](testdata/vector.json): a token and its session ID, ten malformed tokens that must be rejected (wrong prefix, padding, standard base64 characters, wrong length, a non-canonical last character), and the exact `Set-Cookie` strings.

## Anti-patterns

| Anti-pattern | Why it is wrong | Checker rule |
| --- | --- | --- |
| Tokens from `math/rand`, `java.util.Random`, `Math.random`, `ThreadLocalRandom` or `RandomStringUtils.random*` | Predictable: an attacker who sees a few tokens can compute the next ones | [`pqc-token-weak-random`](../../rules/) |
| JWT browser sessions signed with RSA, ECDSA or EdDSA | Forgeable by a quantum attacker, and cannot be revoked early | [`pqc-sig-classical-keygen`](../../rules/) flags the keys |
| Storing raw tokens in the session table | A database leak or backup leak logs everyone in as everyone | Review item |
| Comparing tokens with `==` or `equals` | Timing differences can leak the token byte by byte. Look up by hash instead | Review item |
| Keeping the same token across login | Session fixation: an attacker plants a token before the victim signs in | Review item |
| Sessions with no absolute timeout, or an idle timeout reset on rotation | A stolen token lives forever | Review item |
| Cookies without `Secure`, `HttpOnly` or `SameSite`, or with a `Domain` attribute | Token theft over HTTP, through XSS, or from a sibling subdomain | Review item |
| Tokens in URLs | They end up in logs, browser history and `Referer` headers | Review item |

## Threat notes

- Protects against forged sessions (including by a quantum attacker), replay of a leaked session table, session fixation, and long-lived stolen tokens.
- Does not protect against a token stolen from a live browser (malware, XSS without `HttpOnly`). Short timeouts and re-authentication for sensitive actions limit the damage.
- `SameSite=Lax` stops most cross-site request forgery but not all of it. Add CSRF tokens for state-changing requests if your app accepts top-level cross-site POSTs or must support old browsers.
- Two concurrent `Rotate` calls with the same token can both succeed. If that matters, use a store with an atomic get-and-delete (Redis `GETDEL`, `DELETE … RETURNING`).
- `Validate` writes to the store on every request to record activity. At high request rates, only write when `LastSeen` is more than a minute old.

## Migration

1. **From signed JWT sessions:** issue opaque tokens at the next login and keep accepting existing JWTs until they expire. Do not extend JWT lifetimes while you migrate.
2. **From raw tokens in the database:** add a hashed-ID column, then hash each existing token in place (or look up by raw token once, rewrite the row, and continue). Drop the raw column when the old sessions have expired.
3. **From weak random tokens:** switch generation now. Existing tokens expire within the absolute timeout.
4. **Changing the prefix** is safe at any time if you accept both prefixes for one absolute-timeout period.

## References

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 6265bis](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/) (cookie prefixes and `SameSite`)
- [NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html) (session management)
- [GitHub's token format](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) (prefixed tokens for secret scanning)
