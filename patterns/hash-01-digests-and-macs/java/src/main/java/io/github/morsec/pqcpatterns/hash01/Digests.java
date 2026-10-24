package io.github.morsec.pqcpatterns.hash01;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.EnumSet;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pattern HASH-01: self-describing content digests and full-length HMAC tags.
 *
 * <p>Digests use the Subresource Integrity format, {@code <alg>-<base64>}, such as {@code
 * sha384-ywB1P0Wj...}. The algorithm travels with the value, so a verifier can raise its minimum
 * later without changing the format. The default is SHA-384: it meets CNSA 2.0, is not open to
 * length extension, and runs at SHA-512 speed on 64-bit hardware.
 *
 * <p>MACs are HMAC-SHA-384 with a key of at least 32 bytes, compared in constant time and never
 * truncated. Derive one MAC key per purpose with pattern HASH-02 rather than reusing a key across
 * purposes.
 *
 * <p>Uses only the JDK.
 */
public final class Digests {
  public enum Alg {
    SHA256("sha256", "SHA-256", 32),
    SHA384("sha384", "SHA-384", 48),
    SHA512("sha512", "SHA-512", 64);

    final String name;
    final String jca;
    final int length;

    Alg(String name, String jca, int length) {
      this.name = name;
      this.jca = jca;
      this.length = length;
    }

    MessageDigest newDigest() {
      try {
        return MessageDigest.getInstance(jca);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(jca + " is required by every JDK", e);
      }
    }

    static Alg fromName(String name) {
      for (Alg a : values()) {
        if (a.name.equals(name)) {
          return a;
        }
      }
      return null;
    }
  }

  /** The algorithm {@link #sum} uses. */
  public static final Alg DEFAULT = Alg.SHA384;

  /** Accepts SHA-384 and SHA-512 only. Use it for new data. */
  public static final Set<Alg> STRONG = EnumSet.of(Alg.SHA384, Alg.SHA512);

  /**
   * Also accepts SHA-256, for digests written by older systems. SHA-256 is not broken; it is below
   * the CNSA 2.0 bar.
   */
  public static final Set<Alg> COMPATIBLE = EnumSet.allOf(Alg.class);

  /** The shortest HMAC key accepted. */
  public static final int MIN_KEY_LEN = 32;

  /** The length of an HMAC-SHA-384 tag. Shorter tags are refused. */
  public static final int TAG_LEN = 48;

  /** Why a digest or tag was refused. */
  public enum Result {
    OK,
    MALFORMED,
    ALGORITHM_NOT_ALLOWED,
    MISMATCH
  }

  private Digests() {}

  private static String format(Alg alg, byte[] sum) {
    return alg.name + "-" + Base64.getEncoder().encodeToString(sum);
  }

  /** The digest of {@code data} under {@code alg}. Use {@link #sum} unless you need another. */
  public static String sumWith(Alg alg, byte[] data) {
    return format(alg, alg.newDigest().digest(data));
  }

  /** The SHA-384 digest of {@code data} in {@code sha384-<base64>} form. */
  public static String sum(byte[] data) {
    return sumWith(DEFAULT, data);
  }

  /** {@link #sum} for data that does not fit in memory, such as a file. */
  public static String sum(InputStream in) throws IOException {
    MessageDigest md = DEFAULT.newDigest();
    byte[] buf = new byte[64 * 1024];
    for (int n; (n = in.read(buf)) != -1; ) {
      md.update(buf, 0, n);
    }
    return format(DEFAULT, md.digest());
  }

  /**
   * Checks that {@code integrity} is a well-formed digest of {@code data} under an algorithm {@code
   * policy} allows. MD5 and SHA-1 are never accepted.
   */
  public static Result check(String integrity, byte[] data, Set<Alg> policy) {
    int dash = integrity.indexOf('-');
    if (dash < 0) {
      return Result.MALFORMED;
    }
    Alg alg = Alg.fromName(integrity.substring(0, dash));
    if (alg == null || !policy.contains(alg)) {
      return Result.ALGORITHM_NOT_ALLOWED;
    }
    String b64 = integrity.substring(dash + 1);
    byte[] want;
    try {
      want = Base64.getDecoder().decode(b64);
    } catch (IllegalArgumentException e) {
      return Result.MALFORMED;
    }
    // Re-encoding catches non-canonical forms, so each digest has one spelling.
    if (want.length != alg.length || !Base64.getEncoder().encodeToString(want).equals(b64)) {
      return Result.MALFORMED;
    }
    return MessageDigest.isEqual(alg.newDigest().digest(data), want) ? Result.OK : Result.MISMATCH;
  }

  private static Mac mac(byte[] key) {
    if (key.length < MIN_KEY_LEN) {
      throw new IllegalArgumentException("HMAC key shorter than " + MIN_KEY_LEN + " bytes");
    }
    try {
      Mac m = Mac.getInstance("HmacSHA384");
      m.init(new SecretKeySpec(key, "HmacSHA384"));
      return m;
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("HmacSHA384 is required by every JDK", e);
    }
  }

  /** The HMAC-SHA-384 of {@code msg} under {@code key}. */
  public static byte[] tag(byte[] key, byte[] msg) {
    return mac(key).doFinal(msg);
  }

  /**
   * Checks {@code tag} against {@code msg} in constant time. A tag of any length other than {@link
   * #TAG_LEN} is refused, so a truncated tag cannot be accepted.
   */
  public static boolean verify(byte[] key, byte[] msg, byte[] tag) {
    byte[] want = tag(key, msg);
    return tag.length == TAG_LEN && MessageDigest.isEqual(want, tag);
  }
}
