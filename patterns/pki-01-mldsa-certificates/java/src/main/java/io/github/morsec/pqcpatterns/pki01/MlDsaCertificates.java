package io.github.morsec.pqcpatterns.pki01;

import java.io.IOException;
import java.security.AlgorithmConstraints;
import java.security.AlgorithmParameters;
import java.security.CryptoPrimitive;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

/**
 * Pattern PKI-01: ML-DSA certificates (RFC 9881) and fully post-quantum TLS 1.3, where both the
 * key exchange (hybrid ML-KEM) and the authentication (ML-DSA signatures on the handshake and on
 * every certificate in the chain) resist quantum attacks.
 *
 * <ul>
 *   <li>{@link #generateKeyPair} and {@link #csr} create an ML-DSA-65 key and a PKCS#10 request
 *       for your CA.
 *   <li>{@link #serverParameters} and {@link #clientParameters} allow only TLS 1.3, hybrid groups
 *       and ML-DSA signatures. Use them between services whose certificates have already moved to
 *       ML-DSA.
 * </ul>
 *
 * <p>The TLS signature schemes for ML-DSA (0x0904 to 0x0906) are specified in draft-ietf-tls-mldsa.
 * Bouncy Castle JSSE calls them {@code mldsa44}, {@code mldsa65} and {@code mldsa87}.
 */
public final class MlDsaCertificates {
  /** TLS signature schemes, ML-DSA-65 first. ML-DSA-87 is accepted for CNSA 2.0 peers. */
  public static final List<String> SIGNATURE_SCHEMES = List.of("mldsa65", "mldsa87");

  /** Hybrid key exchange groups, as in pattern KX-01's strict mode. */
  public static final List<String> GROUPS =
      List.of("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024");

  /** The signature algorithm a CA should use to sign ML-DSA-65 certificates. */
  public static final String SIGNATURE_ALGORITHM = "ML-DSA-65";

  private static final Provider BC = new BouncyCastleProvider();
  private static final Provider BCJSSE = new BouncyCastleJsseProvider(BC);

  private MlDsaCertificates() {}

  /** The JSSE provider used by {@link #context}. */
  public static Provider provider() {
    return BCJSSE;
  }

  /** A new ML-DSA-65 key pair. */
  public static KeyPair generateKeyPair() throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("ML-DSA", BC);
    g.initialize(MLDSAParameterSpec.ml_dsa_65, new SecureRandom());
    return g.generateKeyPair();
  }

  /**
   * A PKCS#10 request for {@code dnsNames}, signed with {@code key}. The names travel as a
   * subjectAltName extension request; the CA decides whether to honour them.
   */
  public static PKCS10CertificationRequest csr(KeyPair key, X500Name subject, List<String> dnsNames)
      throws IOException, OperatorCreationException {
    GeneralName[] names =
        dnsNames.stream().map(n -> new GeneralName(GeneralName.dNSName, n)).toArray(GeneralName[]::new);
    ExtensionsGenerator ext = new ExtensionsGenerator();
    ext.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(names));
    return new JcaPKCS10CertificationRequestBuilder(subject, key.getPublic())
        .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, ext.generate())
        .build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC).build(key.getPrivate()));
  }

  /**
   * Key managers for an ML-DSA key and its chain. They use Bouncy Castle's key store, because the
   * JDK's needs a JDK ML-DSA implementation (JDK 24+) to read the keys back.
   */
  public static KeyManager[] keyManagers(PrivateKey key, X509Certificate... chain)
      throws GeneralSecurityException, IOException {
    KeyStore ks = KeyStore.getInstance("PKCS12", BC);
    ks.load(null, null);
    ks.setKeyEntry("key", key, new char[0], chain);
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", BCJSSE);
    kmf.init(ks, new char[0]);
    return kmf.getKeyManagers();
  }

  /** Trust managers that accept chains ending at one of {@code roots}. */
  public static TrustManager[] trustManagers(X509Certificate... roots)
      throws GeneralSecurityException, IOException {
    KeyStore ts = KeyStore.getInstance("PKCS12", BC);
    ts.load(null, null);
    for (int i = 0; i < roots.length; i++) {
      ts.setCertificateEntry("root-" + i, roots[i]);
    }
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", BCJSSE);
    tmf.init(ts);
    return tmf.getTrustManagers();
  }

  /**
   * A context backed by Bouncy Castle JSSE. On its own it allows classical signatures and TLS 1.2:
   * apply {@link #serverParameters} or {@link #clientParameters} to every socket and engine.
   */
  public static SSLContext context(KeyManager[] keyManagers, TrustManager[] trustManagers)
      throws GeneralSecurityException {
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", BCJSSE);
    ctx.init(keyManagers, trustManagers, null);
    return ctx;
  }

  /** Server parameters: TLS 1.3, hybrid groups, ML-DSA signatures only. */
  public static SSLParameters serverParameters() {
    SSLParameters p = new SSLParameters();
    p.setProtocols(new String[] {"TLSv1.3"});
    p.setNamedGroups(GROUPS.toArray(String[]::new));
    p.setSignatureSchemes(SIGNATURE_SCHEMES.toArray(String[]::new));
    p.setAlgorithmConstraints(ML_DSA_ONLY);
    return p;
  }

  /** Client parameters: as {@link #serverParameters}, plus hostname verification. */
  public static SSLParameters clientParameters() {
    SSLParameters p = serverParameters();
    p.setEndpointIdentificationAlgorithm("HTTPS");
    return p;
  }

  /**
   * Signature schemes cover the handshake signature only. These constraints also refuse any
   * certificate in the peer's chain that is signed with anything but ML-DSA-65 or ML-DSA-87, so
   * an ML-DSA leaf issued by a classical CA is rejected too. Other primitives are left to the
   * protocol and group settings above.
   */
  static final AlgorithmConstraints ML_DSA_ONLY =
      new AlgorithmConstraints() {
        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, String algorithm, AlgorithmParameters params) {
          return !primitives.contains(CryptoPrimitive.SIGNATURE) || isMlDsa(algorithm);
        }

        @Override
        public boolean permits(Set<CryptoPrimitive> primitives, Key key) {
          return !primitives.contains(CryptoPrimitive.SIGNATURE) || isMlDsa(key.getAlgorithm());
        }

        @Override
        public boolean permits(
            Set<CryptoPrimitive> primitives, String algorithm, Key key, AlgorithmParameters params) {
          return permits(primitives, algorithm, params) && permits(primitives, key);
        }
      };

  /** Accepts the JCA, TLS and OID spellings of ML-DSA-65 and ML-DSA-87. */
  static boolean isMlDsa(String algorithm) {
    String a = algorithm.toUpperCase(Locale.ROOT).replace("-", "").replace("_", "");
    return switch (a) {
      case "MLDSA65", "MLDSA87", "2.16.840.1.101.3.4.3.18", "2.16.840.1.101.3.4.3.19" -> true;
      default -> false;
    };
  }
}
