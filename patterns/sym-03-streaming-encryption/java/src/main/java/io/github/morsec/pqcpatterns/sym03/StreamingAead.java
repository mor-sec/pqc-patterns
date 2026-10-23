package io.github.morsec.pqcpatterns.sym03;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * Pattern SYM-03: encrypting files and streams of any size with AES-256-GCM in fixed-size
 * authenticated segments, so memory use stays constant and truncation, reordering and appending
 * are detected.
 *
 * <p>Wire format, shared by every language in this repo:
 *
 * <pre>
 * header:   version (1 byte, 0x01) || salt (32 bytes) || nonce prefix (7 bytes)
 * segments: ciphertext || tag (16 bytes), repeated
 * </pre>
 *
 * <p>Each stream gets its own AES-256 key: {@code HKDF-SHA-256(ikm = master key, salt = salt,
 * info = "pqc-patterns/sym-03/v1" || associated data)}. Segment {@code i} uses the nonce {@code
 * prefix || i (u32, big-endian) || last (0x01 on the final segment, else 0x00)}. Every segment
 * holds exactly {@link #SEGMENT_SIZE} bytes of plaintext except the last, which holds 0 to {@link
 * #SEGMENT_SIZE} bytes.
 */
public final class StreamingAead {
  public static final byte VERSION = 0x01;
  /** AES-256 keeps 128-bit security even against Grover's algorithm. */
  public static final int KEY_SIZE = 32;

  public static final int SEGMENT_SIZE = 64 * 1024;
  public static final int SALT_SIZE = 32;
  public static final int PREFIX_SIZE = 7;
  public static final int HEADER_SIZE = 1 + SALT_SIZE + PREFIX_SIZE;
  public static final int TAG_SIZE = 16;
  private static final int SEG_LEN = SEGMENT_SIZE + TAG_SIZE;
  private static final long MAX_SEGMENTS = 1L << 32;
  private static final byte[] LABEL = "pqc-patterns/sym-03/v1".getBytes(StandardCharsets.US_ASCII);
  private static final SecureRandom RANDOM = new SecureRandom();

  private StreamingAead() {}

  /**
   * Thrown for every authentication or format failure, so callers cannot learn why a stream was
   * rejected. Read and write failures surface as plain {@link IOException}s.
   */
  public static final class DecryptException extends Exception {
    private static final long serialVersionUID = 1L;

    DecryptException() {
      super("decryption failed");
    }
  }

  /**
   * Returns a fresh random 256-bit master key. In production, generate and hold keys in a KMS or
   * HSM instead (see pattern KEY-02).
   */
  public static byte[] newKey() {
    byte[] key = new byte[KEY_SIZE];
    RANDOM.nextBytes(key);
    return key;
  }

  /**
   * Reads {@code in} to the end and writes the encrypted stream to {@code out}, holding at most one
   * segment in memory. {@code associatedData} binds the stream to its context (for example a
   * bucket and object name).
   */
  public static void encrypt(InputStream in, OutputStream out, byte[] key, byte[] associatedData)
      throws IOException {
    byte[] salt = new byte[SALT_SIZE];
    byte[] prefix = new byte[PREFIX_SIZE];
    RANDOM.nextBytes(salt);
    RANDOM.nextBytes(prefix);
    encrypt(in, out, key, associatedData, salt, prefix);
  }

  static void encrypt(
      InputStream in, OutputStream out, byte[] key, byte[] associatedData, byte[] salt, byte[] prefix)
      throws IOException {
    SecretKeySpec streamKey = streamKey(key, salt, associatedData);
    out.write(VERSION);
    out.write(salt);
    out.write(prefix);

    // Reading one byte past a full segment tells us whether more follow.
    byte[] buf = new byte[SEGMENT_SIZE + 1];
    byte[] sealed = new byte[SEG_LEN];
    int n = 0;
    for (long i = 0; ; i++) {
      n += in.readNBytes(buf, n, buf.length - n);
      boolean last = n <= SEGMENT_SIZE;
      if (!last && i == MAX_SEGMENTS - 1) {
        throw new IOException("stream: input exceeds 2^32 segments");
      }
      int size = last ? n : SEGMENT_SIZE;
      int len;
      try {
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.ENCRYPT_MODE, streamKey, nonce(prefix, i, last));
        len = gcm.doFinal(buf, 0, size, sealed, 0);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("AES-GCM unavailable", e);
      }
      out.write(sealed, 0, len);
      if (last) {
        return;
      }
      buf[0] = buf[SEGMENT_SIZE];
      n = 1;
    }
  }

  /**
   * Reads an encrypted stream from {@code in} and writes the plaintext to {@code out}.
   *
   * <p>Each segment is authenticated before it is written, but a truncated stream is only detected
   * at the end. Until this returns normally, treat everything written to {@code out} as untrusted:
   * write to a temporary file and move it into place only on success.
   */
  public static void decrypt(InputStream in, OutputStream out, byte[] key, byte[] associatedData)
      throws IOException, DecryptException {
    byte[] header = in.readNBytes(HEADER_SIZE);
    if (header.length < HEADER_SIZE || header[0] != VERSION) {
      throw new DecryptException();
    }
    byte[] salt = Arrays.copyOfRange(header, 1, 1 + SALT_SIZE);
    byte[] prefix = Arrays.copyOfRange(header, 1 + SALT_SIZE, HEADER_SIZE);
    SecretKeySpec streamKey = streamKey(key, salt, associatedData);

    byte[] buf = new byte[SEG_LEN + 1];
    byte[] opened = new byte[SEGMENT_SIZE];
    int n = 0;
    for (long i = 0; ; i++) {
      n += in.readNBytes(buf, n, buf.length - n);
      boolean last = n <= SEG_LEN;
      int size = last ? n : SEG_LEN;
      if (i >= MAX_SEGMENTS || size < TAG_SIZE) {
        throw new DecryptException();
      }
      int len;
      try {
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        gcm.init(Cipher.DECRYPT_MODE, streamKey, nonce(prefix, i, last));
        len = gcm.doFinal(buf, 0, size, opened, 0);
      } catch (AEADBadTagException e) {
        throw new DecryptException();
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("AES-GCM unavailable", e);
      }
      out.write(opened, 0, len);
      if (last) {
        return;
      }
      buf[0] = buf[SEG_LEN];
      n = 1;
    }
  }

  private static SecretKeySpec streamKey(byte[] key, byte[] salt, byte[] associatedData) {
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException(
          "key must be " + KEY_SIZE + " bytes, got " + key.length);
    }
    byte[] info = new byte[LABEL.length + associatedData.length];
    System.arraycopy(LABEL, 0, info, 0, LABEL.length);
    System.arraycopy(associatedData, 0, info, LABEL.length, associatedData.length);
    HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
    hkdf.init(new HKDFParameters(key, salt, info));
    byte[] okm = new byte[KEY_SIZE];
    hkdf.generateBytes(okm, 0, KEY_SIZE);
    return new SecretKeySpec(okm, "AES");
  }

  private static GCMParameterSpec nonce(byte[] prefix, long i, boolean last) {
    ByteBuffer n = ByteBuffer.allocate(12);
    n.put(prefix).putInt((int) i).put((byte) (last ? 1 : 0));
    return new GCMParameterSpec(TAG_SIZE * 8, n.array());
  }
}
