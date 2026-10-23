package io.github.morsec.pqcpatterns.pki01;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509ExtendedKeyManager;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.BCSSLParameters;
import org.bouncycastle.jsse.BCSSLSocket;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

class MlDsaCertificatesTest {
  static final BouncyCastleProvider BC = new BouncyCastleProvider();
  static final AtomicLong SERIAL = new AtomicLong(1);
  static final String HOST = "localhost";

  /** A test CA that signs with {@code alg}: ML-DSA-65, or ECDSA for the negative tests. */
  record Ca(String name, KeyPair key, String alg, X509Certificate cert) {
    static Ca create(String name, KeyPair key, String alg) throws Exception {
      var b = builder(new X500Name("CN=" + name), new X500Name("CN=" + name), key.getPublic());
      b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      return new Ca(name, key, alg, sign(b, alg, key));
    }

    static Ca mlDsa(String name) throws Exception {
      return create(name, MlDsaCertificates.generateKeyPair(), MlDsaCertificates.SIGNATURE_ALGORITHM);
    }

    static Ca ecdsa(String name) throws Exception {
      return create(name, ecKey(), "SHA256withECDSA");
    }

    /** Issues a server certificate from a CSR, copying its requested subjectAltName. */
    X509Certificate issue(PKCS10CertificationRequest csr) throws Exception {
      JcaPKCS10CertificationRequest req = new JcaPKCS10CertificationRequest(csr).setProvider(BC);
      // A CA must check proof of possession before it issues anything.
      assertTrue(req.isSignatureValid(
          new JcaContentVerifierProviderBuilder().setProvider(BC).build(req.getPublicKey())));
      Extensions requested =
          Extensions.getInstance(req.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0]
              .getAttrValues().getObjectAt(0));
      var b = builder(req.getSubject(), new X500Name("CN=" + name), req.getPublicKey());
      b.addExtension(requested.getExtension(Extension.subjectAlternativeName));
      return sign(b, alg, key);
    }

    /** Key managers for a fresh ML-DSA leaf, issued from its CSR. */
    KeyManager[] server(KeyPair leafKey) throws Exception {
      X509Certificate leaf = issue(MlDsaCertificates.csr(leafKey, new X500Name("CN=" + HOST), List.of(HOST)));
      return MlDsaCertificates.keyManagers(leafKey.getPrivate(), leaf, cert);
    }

    /** A leaf for any key type, issued without a CSR. */
    X509Certificate leaf(PublicKey leafKey) throws Exception {
      var b = builder(new X500Name("CN=" + HOST), new X500Name("CN=" + name), leafKey);
      b.addExtension(Extension.subjectAlternativeName, false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, HOST)));
      return sign(b, alg, key);
    }
  }

  static X509v3CertificateBuilder builder(X500Name subject, X500Name issuer, PublicKey key) {
    Instant now = Instant.now();
    return new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(SERIAL.getAndIncrement()),
        Date.from(now.minusSeconds(3600)), Date.from(now.plusSeconds(3600)), subject, key);
  }

  static X509Certificate sign(X509v3CertificateBuilder b, String alg, KeyPair signer) throws Exception {
    return new JcaX509CertificateConverter().setProvider(BC)
        .getCertificate(b.build(new JcaContentSignerBuilder(alg).setProvider(BC).build(signer.getPrivate())));
  }

  /**
   * A key manager that presents its chain whatever the client asked for, like a misconfigured or
   * hostile server. Bouncy Castle's own key manager will not pick a chain that the client's
   * signature_algorithms_cert rules out, which would hide whether the client checks it too.
   */
  static KeyManager[] stubborn(PrivateKey key, X509Certificate... chain) {
    return new KeyManager[] {
      new X509ExtendedKeyManager() {
        @Override public String[] getClientAliases(String type, Principal[] issuers) { return null; }
        @Override public String chooseClientAlias(String[] type, Principal[] issuers, Socket s) { return null; }
        @Override public String[] getServerAliases(String type, Principal[] issuers) { return new String[] {"leaf"}; }
        @Override public String chooseServerAlias(String type, Principal[] issuers, Socket s) { return "leaf"; }
        @Override public String chooseEngineServerAlias(String type, Principal[] issuers, SSLEngine e) {
          return "leaf";
        }
        @Override public X509Certificate[] getCertificateChain(String alias) { return chain; }
        @Override public PrivateKey getPrivateKey(String alias) { return key; }
      }
    };
  }

  /** Every message in the cause chain, for asserting why a handshake failed. */
  static String causes(Throwable t) {
    StringBuilder b = new StringBuilder();
    for (; t != null; t = t.getCause()) {
      b.append(t).append('\n');
    }
    return b.toString();
  }

  static KeyPair ecKey() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  /** Handshakes over loopback; returns the server certificate the client saw, or throws. */
  static X509Certificate handshake(KeyManager[] server, SSLParameters serverParams, Ca trusted)
      throws Exception {
    return handshake(server, serverParams, trusted, c -> {});
  }

  static X509Certificate handshake(
      KeyManager[] server, SSLParameters serverParams, Ca trusted, Consumer<BCSSLSocket> clientTweak)
      throws Exception {
    SSLContext serverCtx = MlDsaCertificates.context(server, null);
    SSLContext clientCtx = MlDsaCertificates.context(null, MlDsaCertificates.trustManagers(trusted.cert()));
    try (SSLServerSocket ss = (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
      ss.setSSLParameters(serverParams);
      CompletableFuture<Void> accepted = CompletableFuture.runAsync(() -> {
        try (SSLSocket s = (SSLSocket) ss.accept()) {
          s.startHandshake();
          s.getOutputStream().write(1);
        } catch (Exception ignored) {
          // The client's view is what the tests assert on.
        }
      });
      try (SSLSocket c = (SSLSocket) clientCtx.getSocketFactory().createSocket(HOST, ss.getLocalPort())) {
        c.setSSLParameters(MlDsaCertificates.clientParameters());
        clientTweak.accept((BCSSLSocket) c);
        c.startHandshake();
        assertEquals("TLSv1.3", c.getSession().getProtocol());
        assertEquals(1, c.getInputStream().read());
        return (X509Certificate) c.getSession().getPeerCertificates()[0];
      } finally {
        accepted.get(10, TimeUnit.SECONDS);
      }
    }
  }

  /** A server that allows classical signatures too, to show the client is the one refusing. */
  static SSLParameters permissiveServer() {
    SSLParameters p = new SSLParameters();
    p.setProtocols(new String[] {"TLSv1.3"});
    p.setNamedGroups(MlDsaCertificates.GROUPS.toArray(String[]::new));
    p.setSignatureSchemes(new String[] {"mldsa65", "mldsa87", "ecdsa_secp256r1_sha256"});
    return p;
  }

  @Test
  void fullyPostQuantumHandshake() throws Exception {
    Ca ca = Ca.mlDsa("Ledger CA");
    X509Certificate seen =
        handshake(ca.server(MlDsaCertificates.generateKeyPair()), MlDsaCertificates.serverParameters(), ca);
    assertEquals("2.16.840.1.101.3.4.3.18", seen.getSigAlgOID());
    assertEquals(List.of(List.of(GeneralName.dNSName, HOST)), List.copyOf(seen.getSubjectAlternativeNames()));
  }

  @Test
  void rejectsClassicalServerCertificate() throws Exception {
    // The client offers only ML-DSA signature schemes, so an ECDSA server cannot sign the handshake.
    Ca ca = Ca.ecdsa("Classical CA");
    KeyPair leafKey = ecKey();
    KeyManager[] km = stubborn(leafKey.getPrivate(), ca.leaf(leafKey.getPublic()), ca.cert());
    Exception e = assertThrows(Exception.class, () -> handshake(km, permissiveServer(), ca));
    assertTrue(causes(e).contains("handshake_failure"), causes(e));
  }

  @Test
  void rejectsMlDsaLeafUnderClassicalCa() throws Exception {
    // The handshake signature is ML-DSA, but the CA signed the leaf with ECDSA. The chain is only
    // as strong as its weakest signature, so the client's algorithm constraints refuse it.
    //
    // Bouncy Castle's server already declines to send a chain outside the client's
    // signature_algorithms_cert, but RFC 8446 section 4.4.2.2 lets a server send one anyway. To
    // test the client's own check, the client here advertises ECDSA for certificates.
    Consumer<BCSSLSocket> advertiseEcdsaCerts = c -> {
      BCSSLParameters p = c.getParameters();
      p.setSignatureSchemesCert(new String[] {"mldsa65", "mldsa87", "ecdsa_secp256r1_sha256"});
      c.setParameters(p);
    };
    Ca ca = Ca.ecdsa("Classical CA");
    KeyPair leafKey = MlDsaCertificates.generateKeyPair();
    KeyManager[] km = stubborn(leafKey.getPrivate(), ca.leaf(leafKey.getPublic()), ca.cert());
    Exception e = assertThrows(Exception.class, () -> handshake(km, permissiveServer(), ca, advertiseEcdsaCerts));
    assertTrue(causes(e).contains("certificate_unknown"), causes(e));

    // Control: the same setup with an ML-DSA CA connects.
    Ca pq = Ca.mlDsa("Ledger CA");
    KeyManager[] pqKm = stubborn(leafKey.getPrivate(), pq.leaf(leafKey.getPublic()), pq.cert());
    assertNotNull(handshake(pqKm, permissiveServer(), pq, advertiseEcdsaCerts));
  }

  @Test
  void rejectsUntrustedCa() throws Exception {
    Ca ca = Ca.mlDsa("Ledger CA");
    Ca other = Ca.mlDsa("Other CA");
    Exception e = assertThrows(Exception.class,
        () -> handshake(ca.server(MlDsaCertificates.generateKeyPair()), MlDsaCertificates.serverParameters(), other));
    assertTrue(causes(e).contains("Unable to construct a valid chain"), causes(e));
  }

  @Test
  void rejectsWrongHostname() throws Exception {
    Ca ca = Ca.mlDsa("Ledger CA");
    KeyPair leafKey = MlDsaCertificates.generateKeyPair();
    X509Certificate leaf =
        ca.issue(MlDsaCertificates.csr(leafKey, new X500Name("CN=elsewhere"), List.of("elsewhere.internal")));
    KeyManager[] km = MlDsaCertificates.keyManagers(leafKey.getPrivate(), leaf, ca.cert());
    Exception e = assertThrows(Exception.class, () -> handshake(km, MlDsaCertificates.serverParameters(), ca));
    assertTrue(causes(e).contains("No subject alternative name"), causes(e));
  }

  @Test
  void csrIsMlDsa() throws Exception {
    KeyPair key = MlDsaCertificates.generateKeyPair();
    PKCS10CertificationRequest csr = MlDsaCertificates.csr(key, new X500Name("CN=ledger"), List.of("ledger.internal"));
    assertEquals("2.16.840.1.101.3.4.3.18", csr.getSignatureAlgorithm().getAlgorithm().getId());
    assertTrue(csr.isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BC).build(key.getPublic())));
    Extensions requested = Extensions.getInstance(
        csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0].getAttrValues().getObjectAt(0));
    assertEquals(new GeneralNames(new GeneralName(GeneralName.dNSName, "ledger.internal")),
        GeneralNames.fromExtensions(requested, Extension.subjectAlternativeName));
  }

  @Test
  void constraintNames() {
    assertTrue(MlDsaCertificates.isMlDsa("ML-DSA-65"));
    assertTrue(MlDsaCertificates.isMlDsa("mldsa87"));
    assertTrue(MlDsaCertificates.isMlDsa("2.16.840.1.101.3.4.3.18"));
    assertFalse(MlDsaCertificates.isMlDsa("ML-DSA-44"));
    assertFalse(MlDsaCertificates.isMlDsa("SHA256withECDSA"));
    assertFalse(MlDsaCertificates.isMlDsa("ed25519"));
  }
}
