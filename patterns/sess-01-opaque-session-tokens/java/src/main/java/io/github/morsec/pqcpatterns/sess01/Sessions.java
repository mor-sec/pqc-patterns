package io.github.morsec.pqcpatterns.sess01;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Pattern SESS-01: opaque, random session tokens with server-side state, idle and absolute
 * timeouts, rotation and revocation.
 *
 * <p>A token is {@link #PREFIX} followed by 32 random bytes in unpadded base64url. The server
 * stores only SHA-256 of those bytes (the session ID), so a leaked session table cannot be
 * replayed as cookies, and looking a session up by its hash leaks nothing useful through timing.
 *
 * <p>Random tokens have no signature for a quantum computer to forge, which is why they are the
 * recommended default for browser sessions.
 */
public final class Sessions {
  /** Marks tokens so secret scanners can find leaked ones. Change it for your application. */
  public static final String PREFIX = "sess_";

  /** 256 bits keeps a 128-bit margin against Grover's algorithm. */
  public static final int TOKEN_BYTES = 32;

  /**
   * The {@code __Host-} prefix makes browsers accept the cookie only over HTTPS, for this exact
   * host, with {@code Path=/}.
   */
  public static final String COOKIE_NAME = "__Host-session";

  public static final Duration DEFAULT_IDLE_TIMEOUT = Duration.ofMinutes(30);
  public static final Duration DEFAULT_ABSOLUTE_TIMEOUT = Duration.ofHours(12);
  private static final int ENCODED_LEN = 43;
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

  private Sessions() {}

  /** Server-side state for one login. */
  public record Session(String userId, Instant created, Instant lastSeen) {}

  /**
   * Thrown for malformed, unknown, expired and revoked tokens alike, so callers cannot tell them
   * apart.
   */
  public static final class InvalidSessionException extends Exception {
    private static final long serialVersionUID = 1L;

    InvalidSessionException() {
      super("invalid session");
    }
  }

  /**
   * Persists sessions by session ID (lowercase hex SHA-256 of the token). Use a database table or
   * a cache such as Redis with a TTL of the absolute timeout. Must be safe for concurrent use.
   */
  public interface Store {
    Optional<Session> get(String id);

    void put(String id, Session session);

    void delete(String id);
  }

  /** Issues and checks session tokens. */
  public static final class Manager {
    private final Store store;
    private final Duration idleTimeout;
    private final Duration absoluteTimeout;
    private final Clock clock;
    private final SecureRandom random = new SecureRandom();

    /** A manager with the default timeouts and the system clock. */
    public Manager(Store store) {
      this(store, DEFAULT_IDLE_TIMEOUT, DEFAULT_ABSOLUTE_TIMEOUT, Clock.systemUTC());
    }

    public Manager(Store store, Duration idleTimeout, Duration absoluteTimeout, Clock clock) {
      this.store = store;
      this.idleTimeout = idleTimeout;
      this.absoluteTimeout = absoluteTimeout;
      this.clock = clock;
    }

    /**
     * Starts a new session for {@code userId} and returns its token. Call it on every successful
     * login, never reusing a token from before the login.
     */
    public String create(String userId) {
      Instant now = clock.instant();
      return issue(new Session(userId, now, now));
    }

    private String issue(Session session) {
      byte[] raw = new byte[TOKEN_BYTES];
      random.nextBytes(raw);
      store.put(idOf(raw), session);
      return PREFIX + ENCODER.encodeToString(raw);
    }

    /** Returns the session for {@code token} and records the activity. Expired sessions are deleted. */
    public Session validate(String token) throws InvalidSessionException {
      String id = sessionId(token);
      Session s = store.get(id).orElseThrow(InvalidSessionException::new);
      Instant now = clock.instant();
      if (!now.isBefore(s.lastSeen().plus(idleTimeout))
          || !now.isBefore(s.created().plus(absoluteTimeout))) {
        store.delete(id);
        throw new InvalidSessionException();
      }
      Session touched = new Session(s.userId(), s.created(), now);
      store.put(id, touched);
      return touched;
    }

    /**
     * Replaces a valid token with a new one for the same session and revokes the old one. Call it
     * when the session's privileges change. The absolute timeout still counts from the original
     * login.
     */
    public String rotate(String token) throws InvalidSessionException {
      Session s = validate(token);
      revoke(token);
      return issue(s);
    }

    /**
     * Ends the session for {@code token}, for example on logout. Revoking an unknown or malformed
     * token is not an error.
     */
    public void revoke(String token) {
      try {
        store.delete(sessionId(token));
      } catch (InvalidSessionException e) {
        // Nothing to revoke.
      }
    }
  }

  /** Checks the token's format and returns the ID it is stored under. */
  public static String sessionId(String token) throws InvalidSessionException {
    if (token == null || !token.startsWith(PREFIX) || token.length() != PREFIX.length() + ENCODED_LEN) {
      throw new InvalidSessionException();
    }
    String enc = token.substring(PREFIX.length());
    byte[] raw;
    try {
      raw = DECODER.decode(enc);
    } catch (IllegalArgumentException e) {
      throw new InvalidSessionException();
    }
    // The JDK decoder ignores non-zero trailing bits; insist on the one canonical spelling.
    if (raw.length != TOKEN_BYTES || !ENCODER.encodeToString(raw).equals(enc)) {
      throw new InvalidSessionException();
    }
    return idOf(raw);
  }

  private static String idOf(byte[] raw) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * The {@code Set-Cookie} value for {@code token}: host-only, HTTPS-only, not readable by
   * JavaScript and not sent on cross-site subresource requests. It has no {@code Max-Age}, so the
   * browser drops it on exit, and the server's timeouts apply either way.
   */
  public static String setCookie(String token) {
    return COOKIE_NAME + "=" + token + "; Path=/; HttpOnly; Secure; SameSite=Lax";
  }

  /** The {@code Set-Cookie} value that deletes the session cookie. */
  public static String clearCookie() {
    return COOKIE_NAME + "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax";
  }

  /** Returns the session token from a {@code Cookie} request header, if present. */
  public static Optional<String> fromCookieHeader(String header) {
    for (String pair : header.split(";")) {
      String[] kv = pair.trim().split("=", 2);
      if (kv.length == 2 && kv[0].equals(COOKIE_NAME)) {
        return Optional.of(kv[1]);
      }
    }
    return Optional.empty();
  }

  /** An in-process {@link Store} for tests and single-instance services. */
  public static final class MemoryStore implements Store {
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();

    @Override
    public Optional<Session> get(String id) {
      return Optional.ofNullable(sessions.get(id));
    }

    @Override
    public void put(String id, Session session) {
      sessions.put(id, session);
    }

    @Override
    public void delete(String id) {
      sessions.remove(id);
    }

    public Set<String> ids() {
      return Map.copyOf(sessions).keySet();
    }
  }
}
