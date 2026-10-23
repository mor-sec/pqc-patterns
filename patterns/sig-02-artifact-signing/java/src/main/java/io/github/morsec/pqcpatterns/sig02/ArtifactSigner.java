package io.github.morsec.pqcpatterns.sig02;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Pattern SIG-02: signing release artifacts, such as binaries, archives and firmware images, with
 * detached ML-DSA-87 signatures.
 *
 * <p>A signature file is text with exactly these lines, in this order:
 *
 * <pre>
 * pqc-patterns-signature-v1
 * algorithm: ML-DSA-87
 * key: &lt;hex SHA-256 of the signer's SubjectPublicKeyInfo DER&gt;
 * name: &lt;artifact name, printable ASCII without spaces&gt;
 * size: &lt;artifact length in bytes&gt;
 * sha512: &lt;hex SHA-512 of the artifact&gt;
 * signed: &lt;RFC 3339 UTC time, whole seconds&gt;
 * signature: &lt;base64 ML-DSA-87 signature&gt;
 * </pre>
 *
 * <p>The signature covers the first seven lines exactly as written, including their line feeds,
 * under the ML-DSA context string {@link #CONTEXT}. Verifiers check the signature before they read
 * the artifact, and check the name they expected rather than trusting the file's.
 */
public final class ArtifactSigner {
  /** Domain-separates artifact signatures from every other use of the same key (FIPS 204, 5.2). */
  public static final byte[] CONTEXT = "pqc-patterns/sig-02/artifact/v1".getBytes(UTF_8);

  public static final String ALGORITHM = "ML-DSA-87";

  /**
   * Artifact signing keys live for years and signature size rarely matters, so this pattern uses
   * the CNSA 2.0 level.
   */
  public static final MLDSAParameterSpec PARAMS = MLDSAParameterSpec.ml_dsa_87;

  /** Bounds what {@link Verifier#verify} will parse. */
  public static final int MAX_SIGNATURE_FILE = 16 * 1024;

  private static final String MAGIC = "pqc-patterns-signature-v1";
  private static final int MAX_NAME_LEN = 255;
  private static final int SIGNATURE_SIZE = 4627;
  private static final List<String> FIELDS =
      List.of("algorithm", "key", "name", "size", "sha512", "signed", "signature");
  private static final Provider BC = new BouncyCastleProvider();
  private static final HexFormat HEX = HexFormat.of();

  private ArtifactSigner() {}

  /** What a signature file asserts. */
  public record Statement(String keyId, String name, long size, byte[] sha512, Instant signed) {
    String encode() {
      return MAGIC
          + "\nalgorithm: " + ALGORITHM
          + "\nkey: " + keyId
          + "\nname: " + name
          + "\nsize: " + size
          + "\nsha512: " + HEX.formatHex(sha512)
          + "\nsigned: " + DateTimeFormatter.ISO_INSTANT.format(signed)
          + "\n";
    }
  }

  /** Why a signature file was rejected. */
  public static final class VerifyException extends Exception {
    private static final long serialVersionUID = 1L;

    public enum Reason {
      MALFORMED,
      UNKNOWN_KEY,
      SIGNATURE,
      WRONG_ARTIFACT
    }

    public final Reason reason;

    VerifyException(Reason reason) {
      super(reason.name());
      this.reason = reason;
    }
  }

  /** Hex SHA-256 of the key's SubjectPublicKeyInfo DER, the same key ID as pattern KEY-01. */
  public static String keyId(MLDSAPublicKey pk) {
    try {
      return HEX.formatHex(MessageDigest.getInstance("SHA-256").digest(pk.getEncoded()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Loads a signing key from its 32-byte seed (see KEY-01 for storing it). */
  public static MLDSAPrivateKey loadPrivateKey(byte[] seed) throws GeneralSecurityException {
    return (MLDSAPrivateKey)
        KeyFactory.getInstance("ML-DSA", BC).generatePrivate(new MLDSAPrivateKeySpec(PARAMS, seed));
  }

  static boolean validName(String name) {
    if (name.isEmpty() || name.length() > MAX_NAME_LEN) {
      return false;
    }
    return name.chars().allMatch(c -> c >= 0x21 && c <= 0x7e);
  }

  /** Signs artifacts with one key. */
  public static final class Signer {
    private final MLDSAPrivateKey key;
    private final Clock clock;

    public Signer(MLDSAPrivateKey key) {
      this(key, Clock.systemUTC());
    }

    public Signer(MLDSAPrivateKey key, Clock clock) {
      this.key = key;
      this.clock = clock;
    }

    /**
     * Reads the artifact to the end and returns the signature file. {@code name} is how verifiers
     * will refer to the artifact.
     */
    public String sign(String name, InputStream artifact) throws IOException, GeneralSecurityException {
      if (!validName(name)) {
        throw new IllegalArgumentException("invalid artifact name");
      }
      Digest d = digest(artifact, Long.MAX_VALUE);
      Statement st =
          new Statement(
              keyId(key.getPublicKey()),
              name,
              d.size,
              d.sha512,
              clock.instant().truncatedTo(ChronoUnit.SECONDS));
      String msg = st.encode();
      Signature s = Signature.getInstance("ML-DSA", BC);
      s.initSign(key);
      s.setParameter(new ContextParameterSpec(CONTEXT));
      s.update(msg.getBytes(UTF_8));
      return msg + "signature: " + Base64.getEncoder().encodeToString(s.sign()) + "\n";
    }
  }

  /** Checks signature files against a set of trusted keys. */
  public static final class Verifier {
    private final Map<String, MLDSAPublicKey> keys = new HashMap<>();

    /** Trusts {@code pk}, keyed by its key ID. */
    public Verifier add(MLDSAPublicKey pk) {
      keys.put(keyId(pk), pk);
      return this;
    }

    /**
     * Checks {@code sigFile} and then that {@code artifact} is the one it signs, under the name
     * the caller expects.
     */
    public Statement verify(String sigFile, String name, InputStream artifact)
        throws VerifyException, IOException {
      Parsed p = parse(sigFile);
      MLDSAPublicKey pk = keys.get(p.st.keyId());
      if (pk == null) {
        throw new VerifyException(VerifyException.Reason.UNKNOWN_KEY);
      }
      boolean ok;
      try {
        Signature s = Signature.getInstance("ML-DSA", BC);
        s.initVerify(pk);
        s.setParameter(new ContextParameterSpec(CONTEXT));
        s.update(p.msg.getBytes(UTF_8));
        ok = s.verify(p.sig);
      } catch (GeneralSecurityException e) {
        ok = false;
      }
      if (!ok) {
        throw new VerifyException(VerifyException.Reason.SIGNATURE);
      }
      if (!p.st.name().equals(name)) {
        throw new VerifyException(VerifyException.Reason.WRONG_ARTIFACT);
      }
      // Read at most one byte more than the signed size.
      Digest d = digest(artifact, p.st.size() == Long.MAX_VALUE ? Long.MAX_VALUE : p.st.size() + 1);
      if (d.size != p.st.size() || !Arrays.equals(d.sha512, p.st.sha512())) {
        throw new VerifyException(VerifyException.Reason.WRONG_ARTIFACT);
      }
      return p.st;
    }
  }

  private record Digest(long size, byte[] sha512) {}

  private static Digest digest(InputStream in, long limit) throws IOException {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA-512");
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
    byte[] buf = new byte[64 * 1024];
    long size = 0;
    while (size < limit) {
      int n = in.read(buf, 0, (int) Math.min(buf.length, limit - size));
      if (n < 0) {
        break;
      }
      md.update(buf, 0, n);
      size += n;
    }
    return new Digest(size, md.digest());
  }

  private record Parsed(Statement st, String msg, byte[] sig) {}

  /**
   * Splits a signature file strictly. Every field must be in its one canonical spelling, so the
   * signed bytes are exactly what {@code sign} writes.
   */
  static Parsed parse(String file) throws VerifyException {
    VerifyException malformed = new VerifyException(VerifyException.Reason.MALFORMED);
    if (file.length() > MAX_SIGNATURE_FILE || !file.endsWith("\n")) {
      throw malformed;
    }
    String[] lines = file.substring(0, file.length() - 1).split("\n", -1);
    if (lines.length != 8 || !lines[0].equals(MAGIC)) {
      throw malformed;
    }
    String[] f = new String[7];
    for (int i = 0; i < 7; i++) {
      String prefix = FIELDS.get(i) + ": ";
      if (!lines[i + 1].startsWith(prefix)) {
        throw malformed;
      }
      f[i] = lines[i + 1].substring(prefix.length());
    }
    try {
      byte[] keyId = HEX.parseHex(f[1]);
      byte[] sha512 = HEX.parseHex(f[4]);
      byte[] sig = Base64.getDecoder().decode(f[6]);
      Statement st =
          new Statement(
              HEX.formatHex(keyId), f[2], Long.parseLong(f[3]), sha512, Instant.parse(f[5]));
      if (!f[0].equals(ALGORITHM)
          || keyId.length != 32
          || sha512.length != 64
          || st.size() < 0
          || !validName(st.name())
          || sig.length != SIGNATURE_SIZE) {
        throw malformed;
      }
      String msg = file.substring(0, file.length() - lines[7].length() - 1);
      // Reject any field whose spelling is not canonical (leading zeros, upper-case hex, other
      // time zones, base64 variants), so one statement has one encoding.
      if (!st.encode().equals(msg)
          || !Base64.getEncoder().encodeToString(sig).equals(f[6])) {
        throw malformed;
      }
      return new Parsed(st, msg, sig);
    } catch (IllegalArgumentException | DateTimeParseException e) {
      throw malformed;
    }
  }
}
