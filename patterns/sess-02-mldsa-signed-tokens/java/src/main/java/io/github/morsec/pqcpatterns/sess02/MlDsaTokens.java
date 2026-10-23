package io.github.morsec.pqcpatterns.sess02;

import static java.nio.charset.StandardCharsets.US_ASCII;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLDSAPublicKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Pattern SESS-02: signed bearer tokens (JWTs) with ML-DSA-65, as specified for JOSE in RFC 9964.
 *
 * <p>A token is a JWS in compact form: {@code BASE64URL(header) "." BASE64URL(claims) "."
 * BASE64URL(signature)}. The verifier accepts exactly one algorithm and one token type, looks the
 * key up by {@code kid}, checks the signature before reading any claims, and then requires the
 * issuer, audience and lifetime it was configured with.
 *
 * <p>RFC 9964 requires the empty ML-DSA context string, which is what Bouncy Castle uses when no
 * {@code ContextParameterSpec} is set. JWS gets its domain separation from the {@code typ} header.
 */
public final class MlDsaTokens {
  /** The RFC 9964 JOSE algorithm name. Use ML-DSA-87 where CNSA 2.0 applies. */
  public static final String ALG = "ML-DSA-65";
  /** Explicit type (RFC 8725 section 3.11) for access tokens (RFC 9068). One type per token kind. */
  public static final String TYPE = "at+jwt";

  public static final Duration DEFAULT_LEEWAY = Duration.ofSeconds(30);
  public static final Duration DEFAULT_MAX_LIFETIME = Duration.ofHours(1);
  public static final MLDSAParameterSpec PARAMS = MLDSAParameterSpec.ml_dsa_65;

  private static final Provider BC = new BouncyCastleProvider();
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder B64D = Base64.getUrlDecoder();

  /** Only alg, typ and kid: crit, jku, x5u and embedded keys are refused, as are duplicates. */
  private static final ObjectMapper STRICT = JsonMapper.builder()
      .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .enable(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES)
      .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
      .build();
  /** Claims may carry application-specific fields, which this pattern ignores. */
  private static final ObjectMapper CLAIMS = JsonMapper.builder()
      .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
      .enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
      .build();

  private MlDsaTokens() {}

  record Header(String alg, String typ, String kid) {}

  /** The registered claims this pattern sets and checks. {@code aud} is always a single string. */
  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Claims(String iss, String sub, String aud, long iat, long exp, String jti) {}

  public enum Failure {
    MALFORMED,
    HEADER,
    UNKNOWN_KEY,
    SIGNATURE,
    CLAIMS,
    EXPIRED
  }

  public static final class VerifyException extends Exception {
    private static final long serialVersionUID = 1L;
    public final Failure failure;

    VerifyException(Failure failure) {
      super("token verification failed: " + failure);
      this.failure = failure;
    }
  }

  /** Creates a new key. Store only {@code key.getSeed()}, the 32-byte FIPS 204 seed. */
  public static MLDSAPrivateKey generateKey() throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA", BC);
    g.initialize(PARAMS);
    return (MLDSAPrivateKey) g.generateKeyPair().getPrivate();
  }

  public static MLDSAPrivateKey loadPrivateKey(byte[] seed) throws GeneralSecurityException {
    return (MLDSAPrivateKey)
        KeyFactory.getInstance("ML-DSA", BC).generatePrivate(new MLDSAPrivateKeySpec(PARAMS, seed));
  }

  public static MLDSAPublicKey loadPublicKey(byte[] encoded) throws GeneralSecurityException {
    return (MLDSAPublicKey)
        KeyFactory.getInstance("ML-DSA", BC).generatePublic(new MLDSAPublicKeySpec(PARAMS, encoded));
  }

  /** Returns a compact JWS over {@code claims}. Signing is hedged (randomised). */
  public static String sign(MLDSAPrivateKey key, String kid, Claims claims) throws GeneralSecurityException {
    try {
      String input = B64.encodeToString(STRICT.writeValueAsBytes(new Header(ALG, TYPE, kid))) + "."
          + B64.encodeToString(CLAIMS.writeValueAsBytes(claims));
      Signature s = Signature.getInstance("ML-DSA", BC);
      s.initSign(key);
      s.update(input.getBytes(US_ASCII));
      return input + "." + B64.encodeToString(s.sign());
    } catch (JsonProcessingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Checks tokens against a set of trusted public keys. */
  public record Verifier(String issuer, String audience, Map<String, MLDSAPublicKey> keys, Duration leeway,
      Duration maxLifetime) {
    public Verifier(String issuer, String audience, Map<String, MLDSAPublicKey> keys) {
      this(issuer, audience, keys, DEFAULT_LEEWAY, DEFAULT_MAX_LIFETIME);
    }

    public Verifier {
      if (issuer == null || issuer.isEmpty() || audience == null || audience.isEmpty()) {
        throw new IllegalArgumentException("issuer and audience are required");
      }
      keys = Map.copyOf(keys);
    }

    public Claims verify(String token) throws VerifyException {
      return verify(token, Instant.now());
    }

    public Claims verify(String token, Instant now) throws VerifyException {
      String[] parts = token.split("\\.", -1);
      if (parts.length != 3) {
        throw new VerifyException(Failure.MALFORMED);
      }
      byte[] hb = decode(parts[0]);
      byte[] pb = decode(parts[1]);
      byte[] sig = decode(parts[2]);

      Header h;
      try {
        h = STRICT.readValue(hb, Header.class);
      } catch (IOException e) {
        throw new VerifyException(Failure.MALFORMED);
      }
      if (!ALG.equals(h.alg()) || !TYPE.equals(h.typ())) {
        throw new VerifyException(Failure.HEADER);
      }
      MLDSAPublicKey pk = h.kid() == null ? null : keys.get(h.kid());
      if (pk == null) {
        throw new VerifyException(Failure.UNKNOWN_KEY);
      }
      try {
        Signature s = Signature.getInstance("ML-DSA", BC);
        s.initVerify(pk);
        s.update((parts[0] + "." + parts[1]).getBytes(US_ASCII));
        if (!s.verify(sig)) {
          throw new VerifyException(Failure.SIGNATURE);
        }
      } catch (GeneralSecurityException e) {
        throw new VerifyException(Failure.SIGNATURE);
      }

      Claims c;
      try {
        c = CLAIMS.readValue(pb, Claims.class);
      } catch (IOException e) {
        throw new VerifyException(Failure.MALFORMED);
      }
      if (!issuer.equals(c.iss()) || !audience.equals(c.aud())) {
        throw new VerifyException(Failure.CLAIMS);
      }
      long t = now.getEpochSecond();
      long slack = leeway.toSeconds();
      if (c.iat() == 0
          || c.exp() == 0
          || t >= saturatingAdd(c.exp(), slack)
          || saturatingAdd(t, slack) < c.iat()
          || lifetimeTooLong(c.iat(), c.exp(), maxLifetime.toSeconds())) {
        throw new VerifyException(Failure.EXPIRED);
      }
      return c;
    }
  }

  /** Strict base64url: no padding, and only the canonical encoding of the bytes. */
  private static byte[] decode(String s) throws VerifyException {
    try {
      byte[] b = B64D.decode(s);
      if (!B64.encodeToString(b).equals(s)) {
        throw new VerifyException(Failure.MALFORMED);
      }
      return b;
    } catch (IllegalArgumentException e) {
      throw new VerifyException(Failure.MALFORMED);
    }
  }

  /** exp - iat > max, without overflow; a wrapped difference counts as too long. */
  private static boolean lifetimeTooLong(long iat, long exp, long max) {
    long d = exp - iat;
    return exp > iat && (d < 0 || d > max);
  }

  private static long saturatingAdd(long a, long b) {
    long r = a + b;
    return ((a ^ r) & (b ^ r)) < 0 ? Long.MAX_VALUE : r;
  }
}
