package io.github.morsec.pqcpatterns.sym01;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Pattern SYM-01: authenticated encryption at rest with AES-256-GCM, versioned key IDs for
 * rotation, and caller-bound associated data.
 *
 * <p>Wire format, shared by every language in this repo:
 *
 * <pre>
 * version (1 byte, 0x01) || key ID (4 bytes, big-endian) || nonce (12 bytes) || ciphertext || tag (16 bytes)
 * </pre>
 *
 * <p>The 5-byte header and the caller's associated data are both authenticated. Uses only the
 * JDK's built-in provider. Safe for concurrent use, so keys can be added and rotated while
 * serving traffic.
 */
public final class Keyring {
  public static final byte VERSION = 0x01;
  /** AES-256 keeps 128-bit security even against Grover's algorithm. */
  public static final int KEY_SIZE = 32;

  private static final int HEADER_LEN = 5;
  private static final int NONCE_LEN = 12;
  private static final int TAG_BITS = 128;
  private static final int OVERHEAD = HEADER_LEN + NONCE_LEN + TAG_BITS / 8;
  private static final SecureRandom RANDOM = new SecureRandom();

  private final Map<Integer, SecretKey> keys = new ConcurrentHashMap<>();
  private volatile int activeId;

  /** Thrown for every authentication or format failure, so callers cannot learn why. */
  public static final class DecryptException extends Exception {
    private static final long serialVersionUID = 1L;

    DecryptException() {
      super("decryption failed");
    }
  }

  public Keyring(int id, byte[] key) {
    add(id, key);
    activeId = id;
  }

  /** Registers a decrypt-only key. Call {@link #rotate} to make it the active key. */
  public void add(int id, byte[] key) {
    if (key.length != KEY_SIZE) {
      throw new IllegalArgumentException("key must be " + KEY_SIZE + " bytes, got " + key.length);
    }
    if (keys.putIfAbsent(id, new SecretKeySpec(key, "AES")) != null) {
      throw new IllegalArgumentException("key ID " + id + " already present");
    }
  }

  /** Makes an already-added key the active key for new encryptions. */
  public void rotate(int id) {
    if (!keys.containsKey(id)) {
      throw new IllegalArgumentException("unknown key ID " + id);
    }
    activeId = id;
  }

  /** A fresh random 256-bit key. In production, hold keys in a KMS or HSM (pattern KEY-02). */
  public static byte[] newKey() {
    byte[] key = new byte[KEY_SIZE];
    RANDOM.nextBytes(key);
    return key;
  }

  /**
   * Seals plaintext under the active key. associatedData binds the ciphertext to its context
   * (for example a table name and row ID). Nonces are random, so one key must not encrypt more
   * than 2^32 messages; rotate well before that.
   */
  public byte[] encrypt(byte[] plaintext, byte[] associatedData) throws GeneralSecurityException {
    byte[] nonce = new byte[NONCE_LEN];
    RANDOM.nextBytes(nonce);
    int id = activeId;
    byte[] header = ByteBuffer.allocate(HEADER_LEN).put(VERSION).putInt(id).array();

    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, keys.get(id), new GCMParameterSpec(TAG_BITS, nonce));
    c.updateAAD(aad(header, associatedData));
    byte[] body = c.doFinal(plaintext);

    return ByteBuffer.allocate(HEADER_LEN + NONCE_LEN + body.length)
        .put(header)
        .put(nonce)
        .put(body)
        .array();
  }

  /** Verifies and opens a blob produced by encrypt in any language. */
  public byte[] decrypt(byte[] blob, byte[] associatedData) throws DecryptException {
    if (blob.length < OVERHEAD || blob[0] != VERSION) {
      throw new DecryptException();
    }
    SecretKey key = keys.get(ByteBuffer.wrap(blob, 1, 4).getInt());
    if (key == null) {
      throw new DecryptException();
    }
    try {
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, blob, HEADER_LEN, NONCE_LEN));
      c.updateAAD(aad(Arrays.copyOf(blob, HEADER_LEN), associatedData));
      return c.doFinal(blob, HEADER_LEN + NONCE_LEN, blob.length - HEADER_LEN - NONCE_LEN);
    } catch (GeneralSecurityException e) {
      throw new DecryptException();
    }
  }

  /** Header plus length-prefixed caller data, so different splits cannot collide. */
  private static byte[] aad(byte[] header, byte[] associatedData) {
    return ByteBuffer.allocate(header.length + 4 + associatedData.length)
        .put(header)
        .putInt(associatedData.length)
        .put(associatedData)
        .array();
  }
}
