package io.github.morsec.pqcpatterns.hash03;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

/**
 * Pattern HASH-03: storing passwords with Argon2id (RFC 9106) in the PHC string format {@code
 * $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>}, with a fresh 16-byte salt per
 * password, a constant-time comparison, and a signal to re-hash when the stored parameters are
 * older than the current ones.
 *
 * <p>Takes the password as UTF-8 bytes; callers should clear the array after use.
 */
public final class PasswordHasher {
  /** Argon2id cost parameters. */
  public record Params(int memoryKib, int time, int threads) {
    boolean valid() {
      return threads >= 1 && threads <= MAX_THREADS
          && time >= 1 && time <= MAX_TIME
          && memoryKib >= 8 * threads && memoryKib <= MAX_MEMORY_KIB;
    }
  }

  /**
   * RFC 9106's second recommended option: 64 MiB, 3 passes, 4 lanes. Tune time upwards until
   * hashing takes about 0.5 s on your servers, but never go below OWASP's floor of 19 MiB and 2
   * passes.
   */
  public static final Params DEFAULT = new Params(64 * 1024, 3, 4);

  public enum Result {
    OK,
    OK_NEEDS_REHASH,
    MISMATCH
  }

  private static final int SALT_LEN = 16;
  private static final int HASH_LEN = 32;
  // Bounds for stored parameters, so a corrupt or hostile database row cannot make verify
  // allocate gigabytes.
  private static final int MAX_MEMORY_KIB = 1 << 20;
  private static final int MAX_TIME = 16;
  private static final int MAX_THREADS = 16;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Base64.Encoder B64 = Base64.getEncoder().withoutPadding();

  private PasswordHasher() {}

  /** Returns a PHC string for password under p. */
  public static String hash(byte[] password, Params p) {
    if (!p.valid()) {
      throw new IllegalArgumentException("Argon2 parameters out of range");
    }
    byte[] salt = new byte[SALT_LEN];
    RANDOM.nextBytes(salt);
    return "$argon2id$v=19$m=" + p.memoryKib() + ",t=" + p.time() + ",p=" + p.threads() + "$"
        + B64.encodeToString(salt) + "$" + B64.encodeToString(argon2(password, salt, p));
  }

  /**
   * Checks password against a stored PHC string. {@link Result#OK_NEEDS_REHASH} means it matched
   * but was made with parameters other than {@code current}: re-hash and store the new value while
   * you have the plaintext.
   *
   * @throws IllegalArgumentException if stored is not a supported argon2id PHC string
   */
  public static Result verify(byte[] password, String stored, Params current) {
    String[] f = stored.split("\\$", -1);
    if (f.length != 6 || !f[0].isEmpty() || !f[1].equals("argon2id") || !f[2].equals("v=19")) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
    String[] kv = f[3].split(",", -1);
    if (kv.length != 3) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
    Params p = new Params(num(kv[0], "m="), num(kv[1], "t="), num(kv[2], "p="));
    byte[] salt = decode(f[4]);
    byte[] want = decode(f[5]);
    if (!p.valid() || salt.length < SALT_LEN || want.length != HASH_LEN) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
    if (!MessageDigest.isEqual(argon2(password, salt, p), want)) {
      return Result.MISMATCH;
    }
    return p.equals(current) ? Result.OK : Result.OK_NEEDS_REHASH;
  }

  static byte[] argon2(byte[] password, byte[] salt, Params p) {
    Argon2BytesGenerator gen = new Argon2BytesGenerator();
    gen.init(new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
        .withVersion(Argon2Parameters.ARGON2_VERSION_13)
        .withMemoryAsKB(p.memoryKib())
        .withIterations(p.time())
        .withParallelism(p.threads())
        .withSalt(salt)
        .build());
    byte[] out = new byte[HASH_LEN];
    gen.generateBytes(password, out);
    return out;
  }

  /** A decimal field with the given prefix and no sign or leading zeros. */
  private static int num(String field, String prefix) {
    if (!field.startsWith(prefix)) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
    String n = field.substring(prefix.length());
    try {
      int v = Integer.parseInt(n);
      if (!Integer.toString(v).equals(n)) {
        throw new IllegalArgumentException("not a supported argon2id PHC string");
      }
      return v;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
  }

  /** Strict unpadded base64: only the canonical encoding of the bytes. */
  private static byte[] decode(String s) {
    byte[] b = Base64.getDecoder().decode(s);
    if (!B64.encodeToString(b).equals(s)) {
      throw new IllegalArgumentException("not a supported argon2id PHC string");
    }
    return b;
  }
}
