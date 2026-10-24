package io.github.morsec.pqcpatterns.key01;

import static java.nio.charset.StandardCharsets.US_ASCII;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Set;
import javax.security.auth.Destroyable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLKEMPrivateKey;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jcajce.spec.MLDSAPrivateKeySpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.jcajce.spec.MLKEMPrivateKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * Pattern KEY-01: generating, encoding and storing ML-DSA and ML-KEM keys.
 *
 * <p>Private keys are stored as their seed (32 bytes for ML-DSA, 64 for ML-KEM) in the seed-only
 * PKCS#8 form of RFC 9881 and RFC 9935, PEM-encoded as {@code PRIVATE KEY}. Public keys use
 * SubjectPublicKeyInfo, PEM-encoded as {@code PUBLIC KEY}. Parsing is strict: only the exact DER
 * this class writes is accepted, so every key has one encoding and one key ID.
 */
public final class PqcKeys {
  private static final Provider BC = new BouncyCastleProvider();
  private static final SecureRandom RANDOM = new SecureRandom();

  private PqcKeys() {}

  public enum Algorithm {
    ML_DSA_65("ML-DSA-65", 32, NISTObjectIdentifiers.id_ml_dsa_65),
    /** CNSA 2.0. */
    ML_DSA_87("ML-DSA-87", 32, NISTObjectIdentifiers.id_ml_dsa_87),
    ML_KEM_768("ML-KEM-768", 64, NISTObjectIdentifiers.id_alg_ml_kem_768),
    /** CNSA 2.0. */
    ML_KEM_1024("ML-KEM-1024", 64, NISTObjectIdentifiers.id_alg_ml_kem_1024);

    /** The FIPS name, such as {@code ML-DSA-65}. */
    public final String fipsName;

    /** 32 bytes for ML-DSA (FIPS 204 xi), 64 bytes for ML-KEM (FIPS 203 d || z). */
    public final int seedSize;

    private final ASN1ObjectIdentifier oid;

    Algorithm(String fipsName, int seedSize, ASN1ObjectIdentifier oid) {
      this.fipsName = fipsName;
      this.seedSize = seedSize;
      this.oid = oid;
    }

    boolean isMlDsa() {
      return this == ML_DSA_65 || this == ML_DSA_87;
    }

    KeySpec privateKeySpec(byte[] seed) {
      return switch (this) {
        case ML_DSA_65 -> new MLDSAPrivateKeySpec(MLDSAParameterSpec.ml_dsa_65, seed);
        case ML_DSA_87 -> new MLDSAPrivateKeySpec(MLDSAParameterSpec.ml_dsa_87, seed);
        case ML_KEM_768 -> new MLKEMPrivateKeySpec(MLKEMParameterSpec.ml_kem_768, seed);
        case ML_KEM_1024 -> new MLKEMPrivateKeySpec(MLKEMParameterSpec.ml_kem_1024, seed);
      };
    }

    KeyFactory keyFactory() throws GeneralSecurityException {
      return KeyFactory.getInstance(isMlDsa() ? "ML-DSA" : "ML-KEM", BC);
    }

    static Algorithm of(ASN1ObjectIdentifier oid) throws InvalidKeyEncodingException {
      for (Algorithm a : values()) {
        if (a.oid.equals(oid)) {
          return a;
        }
      }
      throw new InvalidKeyEncodingException();
    }
  }

  /** Thrown for any malformed, non-canonical or unsupported key encoding. */
  public static final class InvalidKeyEncodingException extends GeneralSecurityException {
    private static final long serialVersionUID = 1L;

    InvalidKeyEncodingException() {
      super("invalid key encoding");
    }
  }

  /** A public key read from a {@code PUBLIC KEY} PEM block. */
  public record PublicKeyInfo(Algorithm algorithm, byte[] publicKey) {}

  /** A private seed and the public key derived from it. Call {@link #destroy} when done. */
  public static final class KeyPair implements Destroyable {
    private final Algorithm algorithm;
    private final byte[] seed;
    private final byte[] publicKey;
    private boolean destroyed;

    private KeyPair(Algorithm algorithm, byte[] seed, byte[] publicKey) {
      this.algorithm = algorithm;
      this.seed = seed;
      this.publicKey = publicKey;
    }

    public Algorithm algorithm() {
      return algorithm;
    }

    public byte[] seed() {
      return seed.clone();
    }

    public byte[] publicKey() {
      return publicKey.clone();
    }

    /** The usable JCA key: a Bouncy Castle {@link MLDSAPrivateKey} or {@link MLKEMPrivateKey}. */
    public PrivateKey privateKey() throws GeneralSecurityException {
      return algorithm.keyFactory().generatePrivate(algorithm.privateKeySpec(seed));
    }

    /** Seed-only PKCS#8 in a {@code PRIVATE KEY} PEM block. */
    public String privateKeyPem() {
      return pem("PRIVATE KEY", privateKeyDer(algorithm, seed));
    }

    /** SubjectPublicKeyInfo in a {@code PUBLIC KEY} PEM block. */
    public String publicKeyPem() {
      return pem("PUBLIC KEY", publicKeyDer(algorithm, publicKey));
    }

    /**
     * Lowercase hex SHA-256 of the SubjectPublicKeyInfo DER: a stable name for the key in logs, key
     * sets and rotation records.
     */
    public String keyId() {
      try {
        byte[] hash =
            MessageDigest.getInstance("SHA-256").digest(publicKeyDer(algorithm, publicKey));
        return HexFormat.of().formatHex(hash);
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException(e);
      }
    }

    /** Overwrites the seed in memory. Copies returned by {@link #seed} are the caller's to wipe. */
    @Override
    public void destroy() {
      Arrays.fill(seed, (byte) 0);
      destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
      return destroyed;
    }
  }

  /** Creates a new key pair from the system CSPRNG. */
  public static KeyPair generate(Algorithm algorithm) throws GeneralSecurityException {
    byte[] seed = new byte[algorithm.seedSize];
    RANDOM.nextBytes(seed);
    try {
      return fromSeed(algorithm, seed);
    } finally {
      Arrays.fill(seed, (byte) 0);
    }
  }

  /** Rebuilds a key pair from its seed. */
  public static KeyPair fromSeed(Algorithm algorithm, byte[] seed) throws GeneralSecurityException {
    if (seed.length != algorithm.seedSize) {
      throw new IllegalArgumentException(
          algorithm.fipsName + " seed must be " + algorithm.seedSize + " bytes, got " + seed.length);
    }
    PrivateKey key = algorithm.keyFactory().generatePrivate(algorithm.privateKeySpec(seed));
    byte[] pub =
        key instanceof MLDSAPrivateKey dsa
            ? dsa.getPublicKey().getPublicData()
            : ((MLKEMPrivateKey) key).getPublicKey().getPublicData();
    return new KeyPair(algorithm, seed.clone(), pub);
  }

  /**
   * Reads a key written by {@link KeyPair#privateKeyPem}. Expanded and "both" private key forms,
   * encrypted PEM and trailing data are rejected.
   */
  public static KeyPair parsePrivateKeyPem(String pem) throws GeneralSecurityException {
    byte[] der = unpem(pem, "PRIVATE KEY");
    Algorithm algorithm;
    byte[] seed;
    try {
      PrivateKeyInfo info = PrivateKeyInfo.getInstance(der);
      algorithm = Algorithm.of(info.getPrivateKeyAlgorithm().getAlgorithm());
      ASN1TaggedObject choice = ASN1TaggedObject.getInstance(info.parsePrivateKey());
      if (!choice.hasContextTag(0)) {
        throw new InvalidKeyEncodingException();
      }
      seed = ASN1OctetString.getInstance(choice, false).getOctets();
    } catch (IllegalArgumentException | IllegalStateException | ClassCastException | IOException e) {
      throw new InvalidKeyEncodingException();
    }
    try {
      if (seed.length != algorithm.seedSize || !Arrays.equals(privateKeyDer(algorithm, seed), der)) {
        throw new InvalidKeyEncodingException();
      }
      return fromSeed(algorithm, seed);
    } finally {
      Arrays.fill(seed, (byte) 0);
      Arrays.fill(der, (byte) 0);
    }
  }

  /**
   * Reads a key written by {@link KeyPair#publicKeyPem} and checks that it is a valid key for its
   * algorithm.
   */
  public static PublicKeyInfo parsePublicKeyPem(String pem) throws GeneralSecurityException {
    byte[] der = unpem(pem, "PUBLIC KEY");
    Algorithm algorithm;
    byte[] pub;
    try {
      SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(der);
      algorithm = Algorithm.of(info.getAlgorithm().getAlgorithm());
      pub = info.getPublicKeyData().getOctets();
    } catch (IllegalArgumentException | IllegalStateException | ClassCastException e) {
      throw new InvalidKeyEncodingException();
    }
    if (!Arrays.equals(publicKeyDer(algorithm, pub), der) || !validPublicKey(algorithm, pub)) {
      throw new InvalidKeyEncodingException();
    }
    return new PublicKeyInfo(algorithm, pub);
  }

  /** Bouncy Castle checks the length and, for ML-KEM, the FIPS 203 section 7.2 modulus check. */
  private static boolean validPublicKey(Algorithm algorithm, byte[] pub) {
    try {
      algorithm.keyFactory().generatePublic(new X509EncodedKeySpec(publicKeyDer(algorithm, pub)));
      return true;
    } catch (GeneralSecurityException | RuntimeException e) {
      return false;
    }
  }

  /** Writes the private key PEM to a new file readable only by its owner. Never overwrites. */
  public static void writePrivateKeyFile(Path path, KeyPair key) throws IOException {
    boolean posix = path.toAbsolutePath().getFileSystem().supportedFileAttributeViews().contains("posix");
    FileAttribute<?>[] attrs =
        posix
            ? new FileAttribute<?>[] {
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))
            }
            : new FileAttribute<?>[0];
    Files.createFile(path, attrs);
    Files.writeString(path, key.privateKeyPem(), US_ASCII, StandardOpenOption.WRITE, StandardOpenOption.SYNC);
  }

  /** Reads a private key file, refusing files that other users can read or write. */
  public static KeyPair readPrivateKeyFile(Path path) throws IOException, GeneralSecurityException {
    if (path.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
      for (PosixFilePermission p : perms) {
        if (p.name().startsWith("GROUP") || p.name().startsWith("OTHERS")) {
          throw new IOException(path + ": private key is accessible by other users");
        }
      }
    }
    return parsePrivateKeyPem(Files.readString(path, US_ASCII));
  }

  static byte[] privateKeyDer(Algorithm algorithm, byte[] seed) {
    try {
      // The seed choice of ML-DSA-PrivateKey and ML-KEM-PrivateKey: [0] IMPLICIT OCTET STRING.
      return new PrivateKeyInfo(
              new AlgorithmIdentifier(algorithm.oid),
              new DERTaggedObject(false, BERTags.CONTEXT_SPECIFIC, 0, new DEROctetString(seed)))
          .getEncoded(ASN1Encoding.DER);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  static byte[] publicKeyDer(Algorithm algorithm, byte[] pub) {
    try {
      return new SubjectPublicKeyInfo(new AlgorithmIdentifier(algorithm.oid), pub)
          .getEncoded(ASN1Encoding.DER);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }

  private static String pem(String label, byte[] der) {
    String body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(der);
    return "-----BEGIN " + label + "-----\n" + body + "\n-----END " + label + "-----\n";
  }

  /** Strict PEM: one block with the given label, no headers, nothing after it. */
  private static byte[] unpem(String pem, String label) throws InvalidKeyEncodingException {
    String begin = "-----BEGIN " + label + "-----";
    String end = "-----END " + label + "-----";
    String s = pem.strip();
    if (!s.startsWith(begin) || !s.endsWith(end) || s.length() < begin.length() + end.length()) {
      throw new InvalidKeyEncodingException();
    }
    String body = s.substring(begin.length(), s.length() - end.length()).replaceAll("[\\r\\n]", "");
    try {
      return Base64.getDecoder().decode(body);
    } catch (IllegalArgumentException e) {
      throw new InvalidKeyEncodingException();
    }
  }
}
