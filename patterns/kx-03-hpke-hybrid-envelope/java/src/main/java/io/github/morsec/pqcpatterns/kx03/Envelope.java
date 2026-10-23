package io.github.morsec.pqcpatterns.kx03;

import java.nio.ByteBuffer;
import java.util.Arrays;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/**
 * Pattern KX-03: encrypting a message or data key to a recipient's public key with HPKE (RFC
 * 9180) using the hybrid post-quantum KEM ML-KEM-768 + X25519 (X-Wing, draft-ietf-hpke-pq).
 *
 * <p>Ciphersuite: KEM 0x647a (MLKEM768-X25519), KDF 0x0001 (HKDF-SHA256), AEAD 0x0002
 * (AES-256-GCM). Wire format, shared by every language in this repo:
 *
 * <pre>
 * suite (6 bytes: KEM ID || KDF ID || AEAD ID, big-endian) || enc (1120 bytes) || ciphertext || tag
 * </pre>
 */
public final class Envelope {
  public static final short KEM_ID = HPKE.kem_X_WING; // 0x647a
  public static final short KDF_ID = HPKE.kdf_HKDF_SHA256;
  public static final short AEAD_ID = HPKE.aead_AES_GCM256;
  /** ML-KEM-768 ciphertext (1088 bytes) followed by the X25519 share (32 bytes). */
  public static final int ENC_LEN = 1120;

  private static final int SUITE_LEN = 6;
  private static final byte[] SUITE =
      ByteBuffer.allocate(SUITE_LEN).putShort(KEM_ID).putShort(KDF_ID).putShort(AEAD_ID).array();

  private Envelope() {}

  public static final class OpenException extends Exception {
    private static final long serialVersionUID = 1L;

    OpenException() {
      super("decryption failed");
    }
  }

  /** A recipient key pair as bytes: a 32-byte private seed and a 1216-byte public key. */
  public record KeyPair(byte[] privateKey, byte[] publicKey) {}

  private static HPKE hpke() {
    return new HPKE(HPKE.mode_base, KEM_ID, KDF_ID, AEAD_ID);
  }

  /** Keep privateKey in a secret store; publish publicKey. */
  public static KeyPair generateKey() {
    HPKE h = hpke();
    AsymmetricCipherKeyPair kp = h.generatePrivateKey();
    return new KeyPair(h.serializePrivateKey(kp.getPrivate()), h.serializePublicKey(kp.getPublic()));
  }

  /**
   * Encrypts plaintext to the recipient. info names the application and purpose (for example
   * "billing-exports/v1") and must match on open. aad is authenticated but not encrypted.
   */
  public static byte[] seal(byte[] recipientPublicKey, byte[] info, byte[] aad, byte[] plaintext)
      throws InvalidCipherTextException {
    HPKE h = hpke();
    AsymmetricKeyParameter pk = h.deserializePublicKey(recipientPublicKey);
    byte[][] out = h.seal(pk, info, aad, plaintext, null, null, null); // {ciphertext, enc}
    return ByteBuffer.allocate(SUITE_LEN + out[1].length + out[0].length)
        .put(SUITE)
        .put(out[1])
        .put(out[0])
        .array();
  }

  /** Decrypts a message produced by seal in any language in this repo. */
  public static byte[] open(KeyPair recipient, byte[] info, byte[] aad, byte[] msg) throws OpenException {
    if (msg.length < SUITE_LEN + ENC_LEN || !Arrays.equals(msg, 0, SUITE_LEN, SUITE, 0, SUITE_LEN)) {
      throw new OpenException();
    }
    try {
      HPKE h = hpke();
      AsymmetricCipherKeyPair kp = h.deserializePrivateKey(recipient.privateKey(), recipient.publicKey());
      byte[] enc = Arrays.copyOfRange(msg, SUITE_LEN, SUITE_LEN + ENC_LEN);
      byte[] ct = Arrays.copyOfRange(msg, SUITE_LEN + ENC_LEN, msg.length);
      return h.open(enc, kp, info, aad, ct, null, null, null);
    } catch (InvalidCipherTextException | RuntimeException e) {
      throw new OpenException();
    }
  }
}
