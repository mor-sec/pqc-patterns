package io.github.morsec.pqcpatterns.kx02;

import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

class HybridMtlsTest {
  static final String BILLING = "spiffe://example.org/billing";

  record Ca(KeyPair key, X509Certificate cert) {
    static Ca create() throws Exception {
      KeyPair kp = ecKey();
      X500Name name = new X500Name("CN=test internal CA");
      var b = builder(name, name, kp);
      b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      return new Ca(kp, sign(b, kp));
    }

    KeyManager[] server(String dns) throws Exception {
      return leaf(new GeneralName(GeneralName.dNSName, dns), KeyPurposeId.id_kp_serverAuth);
    }

    KeyManager[] client(String uri) throws Exception {
      return leaf(new GeneralName(GeneralName.uniformResourceIdentifier, uri), KeyPurposeId.id_kp_clientAuth);
    }

    KeyManager[] leaf(GeneralName san, KeyPurposeId eku) throws Exception {
      KeyPair kp = ecKey();
      var b = builder(new X500Name("CN=" + san.getName()), new X500Name("CN=test internal CA"), kp);
      b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(san));
      b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
      X509Certificate leaf = sign(b, key);
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(null, null);
      ks.setKeyEntry("leaf", kp.getPrivate(), new char[0], new X509Certificate[] {leaf, cert});
      KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", HybridMtls.provider());
      kmf.init(ks, new char[0]);
      return kmf.getKeyManagers();
    }

    TrustManager[] trust() throws Exception {
      KeyStore ts = KeyStore.getInstance("PKCS12");
      ts.load(null, null);
      ts.setCertificateEntry("ca", cert);
      TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", HybridMtls.provider());
      tmf.init(ts);
      return tmf.getTrustManagers();
    }
  }

  static KeyPair ecKey() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  static JcaX509v3CertificateBuilder builder(X500Name subject, X500Name issuer, KeyPair kp) {
    return new JcaX509v3CertificateBuilder(issuer, BigInteger.valueOf(System.nanoTime()),
        Date.from(Instant.now().minusSeconds(3600)), Date.from(Instant.now().plusSeconds(3600)), subject,
        kp.getPublic());
  }

  static X509Certificate sign(JcaX509v3CertificateBuilder b, KeyPair issuer) throws Exception {
    return new JcaX509CertificateConverter()
        .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuer.getPrivate())));
  }

  /** Result of a loopback handshake: the identity the server saw, and each side's failure. */
  record Outcome(Optional<String> identity, Exception server, Exception client) {}

  static Outcome handshake(Ca ca, KeyManager[] clientKeys, TrustManager[] clientRoots, String host,
      SSLParameters clientParams) throws Exception {
    SSLContext serverCtx = HybridMtls.serverContext(ca.server("localhost"), ca.trust(), Set.of(BILLING));
    SSLContext clientCtx = HybridMtls.clientContext(clientKeys, clientRoots);
    try (SSLServerSocket ss = HybridMtls.serverSocket(serverCtx, 0)) {
      CompletableFuture<Object> accepted = CompletableFuture.supplyAsync(() -> {
        try (SSLSocket s = (SSLSocket) ss.accept()) {
          s.startHandshake();
          s.getOutputStream().write(1);
          return HybridMtls.peerIdentity(s.getSession());
        } catch (Exception e) {
          return e;
        }
      });
      Exception clientErr = null;
      try (SSLSocket c = HybridMtls.clientSocket(clientCtx, host, ss.getLocalPort())) {
        if (clientParams != null) {
          c.setSSLParameters(clientParams);
        }
        c.startHandshake();
        // TLS 1.3 client auth fails after the client's Finished, so read to see the server's verdict.
        if (c.getInputStream().read() != 1) {
          throw new java.io.EOFException("server closed the connection");
        }
      } catch (Exception e) {
        clientErr = e;
      }
      Object server = accepted.get(10, TimeUnit.SECONDS);
      @SuppressWarnings("unchecked")
      Optional<String> id = server instanceof Optional<?> o ? (Optional<String>) o : Optional.empty();
      return new Outcome(id, server instanceof Exception e ? e : null, clientErr);
    }
  }

  @Test
  void mutualHandshake() throws Exception {
    Ca ca = Ca.create();
    Outcome o = handshake(ca, ca.client(BILLING), ca.trust(), "localhost", null);
    assertNull(o.server());
    assertNull(o.client());
    assertEquals(Optional.of(BILLING), o.identity());
  }

  @Test
  void rejectsClientWithoutCertificate() throws Exception {
    Ca ca = Ca.create();
    assertNotNull(handshake(ca, null, ca.trust(), "localhost", null).server());
  }

  @Test
  void rejectsClientFromOtherCa() throws Exception {
    Ca ca = Ca.create();
    assertNotNull(handshake(ca, Ca.create().client(BILLING), ca.trust(), "localhost", null).server());
  }

  @Test
  void rejectsIdentityNotOnAllowList() throws Exception {
    Ca ca = Ca.create();
    Outcome o = handshake(ca, ca.client("spiffe://example.org/reports"), ca.trust(), "localhost", null);
    assertTrue(causedBy(o.server(), "allow-list"), String.valueOf(o.server()));
    assertNotNull(o.client());
  }

  static boolean causedBy(Throwable t, String text) {
    for (; t != null; t = t.getCause()) {
      if (String.valueOf(t.getMessage()).contains(text)) {
        return true;
      }
    }
    return false;
  }

  @Test
  void rejectsClassicalClient() throws Exception {
    Ca ca = Ca.create();
    SSLParameters classical = HybridMtls.clientParameters();
    classical.setNamedGroups(new String[] {"x25519", "secp256r1"});
    assertNotNull(handshake(ca, ca.client(BILLING), ca.trust(), "localhost", classical).server());
  }

  @Test
  void clientRejectsWrongServerName() throws Exception {
    Ca ca = Ca.create();
    // 127.0.0.1 is not the certificate's name (localhost), so hostname verification fails.
    assertNotNull(handshake(ca, ca.client(BILLING), ca.trust(), "127.0.0.1", null).client());
  }
}
