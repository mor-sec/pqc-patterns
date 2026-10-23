package io.github.morsec.pqcpatterns.sig01;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Pattern SIG-01: signing API requests with ML-DSA-65 (FIPS 204) so a receiver can prove who
 * sent a request and that it was not altered or replayed.
 *
 * <p>The signed message is a length-prefixed encoding of key ID, timestamp (Unix seconds,
 * decimal), HTTP method, path and body, signed under the ML-DSA context string {@link #CONTEXT}.
 *
 * <p>Uses Bouncy Castle rather than the JDK 24+ built-in ML-DSA because the JDK does not support
 * context strings, and because Bouncy Castle runs on Java 21 LTS.
 */
public final class ApiSigner {
  /** Domain-separates API request signatures (FIPS 204, section 5.2). */
  public static final byte[] CONTEXT = "pqc-patterns/sig-01/api-request/v1".getBytes(UTF_8);

  public static final Duration DEFAULT_MAX_SKEW = Duration.ofMinutes(5);
  /** Use {@code ml_dsa_87} where CNSA 2.0 applies. */
  public static final MLDSAParameterSpec PARAMS = MLDSAParameterSpec.ml_dsa_65;

  private static final Provider BC = new BouncyCastleProvider();

  private ApiSigner() {}

  /** The part of an HTTP request covered by the signature. Path includes the query string. */
  public record Request(String keyId, Instant timestamp, String method, String path, byte[] body) {
    /** The exact bytes that are signed. */
    public byte[] message() {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      for (byte[] f :
          new byte[][] {
            keyId.getBytes(UTF_8),
            Long.toString(timestamp.getEpochSecond()).getBytes(UTF_8),
            method.getBytes(UTF_8),
            path.getBytes(UTF_8),
            body
          }) {
        out.writeBytes(ByteBuffer.allocate(4).putInt(f.length).array());
        out.writeBytes(f);
      }
      return out.toByteArray();
    }
  }

  public enum Failure {
    UNKNOWN_KEY,
    STALE,
    SIGNATURE
  }

  public static final class VerifyException extends Exception {
    private static final long serialVersionUID = 1L;
    public final Failure failure;

    VerifyException(Failure failure) {
      super("request verification failed: " + failure);
      this.failure = failure;
    }
  }

  /** Creates a new key. Store only {@code key.getSeed()}, the 32-byte FIPS 204 seed. */
  public static MLDSAPrivateKey generateKey() throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA", BC);
    g.initialize(PARAMS);
    return (MLDSAPrivateKey) g.generateKeyPair().getPrivate();
  }

  /** Restores a key from its 32-byte seed. */
  public static MLDSAPrivateKey loadPrivateKey(byte[] seed) throws GeneralSecurityException {
    return (MLDSAPrivateKey)
        KeyFactory.getInstance("ML-DSA", BC).generatePrivate(new MLDSAPrivateKeySpec(PARAMS, seed));
  }

  /** Decodes a 1952-byte ML-DSA-65 public key. */
  public static MLDSAPublicKey loadPublicKey(byte[] encoded) throws GeneralSecurityException {
    return (MLDSAPublicKey)
        KeyFactory.getInstance("ML-DSA", BC).generatePublic(new MLDSAPublicKeySpec(PARAMS, encoded));
  }

  /** Signs r. Signing is hedged (randomised), so two signatures over one request differ. */
  public static byte[] sign(MLDSAPrivateKey key, Request r) throws GeneralSecurityException {
    Signature s = Signature.getInstance("ML-DSA", BC);
    s.initSign(key);
    s.setParameter(new ContextParameterSpec(CONTEXT));
    s.update(r.message());
    return s.sign();
  }

  /**
   * Checks the timestamp window, then the signature. Does not detect a replay inside the window;
   * pair it with a nonce or idempotency-key cache if requests are not idempotent.
   */
  public static void verify(
      Map<String, MLDSAPublicKey> keys, Request r, byte[] sig, Instant now, Duration maxSkew)
      throws VerifyException {
    MLDSAPublicKey pk = keys.get(r.keyId());
    if (pk == null) {
      throw new VerifyException(Failure.UNKNOWN_KEY);
    }
    if (Duration.between(r.timestamp(), now).abs().compareTo(maxSkew) > 0) {
      throw new VerifyException(Failure.STALE);
    }
    try {
      Signature s = Signature.getInstance("ML-DSA", BC);
      s.initVerify(pk);
      s.setParameter(new ContextParameterSpec(CONTEXT));
      s.update(r.message());
      if (!s.verify(sig)) {
        throw new VerifyException(Failure.SIGNATURE);
      }
    } catch (GeneralSecurityException e) {
      throw new VerifyException(Failure.SIGNATURE);
    }
  }
}
