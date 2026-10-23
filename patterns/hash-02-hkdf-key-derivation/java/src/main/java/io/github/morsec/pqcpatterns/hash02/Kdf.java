package io.github.morsec.pqcpatterns.hash02;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Pattern HASH-02: deriving separate, purpose-bound keys from one secret with HKDF-SHA-256 (RFC
 * 5869).
 *
 * <p>The HKDF info input is a length-prefixed encoding of {@code "pqc-patterns/hash-02/v1"},
 * purpose, context and the output length (u16), so two purposes, two contexts or two output lengths
 * never share key material. Without the length, a 16-byte key would be the first half of the
 * 32-byte key for the same purpose.
 *
 * <p>Uses the Bouncy Castle lightweight API because the JDK's own KDF API (JEP 510) needs Java 25.
 */
public final class Kdf {
  private static final byte[] LABEL = "pqc-patterns/hash-02/v1".getBytes(UTF_8);
  /** The smallest input secret accepted: 256 bits. */
  public static final int MIN_SECRET_LEN = 32;
  /** HKDF-SHA-256's output limit, 255 * 32 bytes. */
  public static final int MAX_KEY_LEN = 255 * 32;

  private Kdf() {}

  /** The exact HKDF info bytes for purpose, context and keyLen. */
  public static byte[] info(String purpose, byte[] context, int keyLen) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] f : new byte[][] {LABEL, purpose.getBytes(UTF_8), context}) {
      out.writeBytes(ByteBuffer.allocate(4).putInt(f.length).array());
      out.writeBytes(f);
    }
    out.writeBytes(ByteBuffer.allocate(2).putShort((short) keyLen).array());
    return out.toByteArray();
  }

  /**
   * Returns a keyLen-byte key for purpose, such as {@code "billing-exports/aes-256-gcm/v1"}.
   * context binds the key to an instance, such as a tenant ID, and may be empty. salt may be empty
   * when secret is already uniformly random (a KMS data key or an ML-KEM shared secret); otherwise
   * use a fixed, non-secret, random value per application.
   */
  public static byte[] derive(byte[] secret, byte[] salt, String purpose, byte[] context, int keyLen) {
    if (secret.length < MIN_SECRET_LEN || purpose.isEmpty() || keyLen < 16 || keyLen > MAX_KEY_LEN) {
      throw new IllegalArgumentException("secret shorter than 32 bytes, empty purpose, or bad key length");
    }
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(SHA256Digest.newInstance());
    hkdf.init(new HKDFParameters(secret, salt, info(purpose, context, keyLen)));
    byte[] out = new byte[keyLen];
    hkdf.generateBytes(out, 0, keyLen);
    return out;
  }
}
