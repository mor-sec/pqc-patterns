package io.github.morsec.pqcpatterns.kx01;

import static io.github.morsec.pqcpatterns.kx01.HybridTls.Mode.*;
import static org.junit.jupiter.api.Assertions.*;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.util.Date;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class HybridTlsTest {
  static SSLContext serverCtx;
  static SSLContext clientCtx;

  @BeforeAll
  static void certs() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair kp = g.generateKeyPair();
    X500Name name = new X500Name("CN=localhost");
    var builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
        Date.from(Instant.now().minusSeconds(3600)), Date.from(Instant.now().plusSeconds(3600)), name, kp.getPublic());
    builder.addExtension(Extension.subjectAlternativeName, false,
        new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")));
    X509Certificate cert = new JcaX509CertificateConverter()
        .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(kp.getPrivate())));

    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    ks.setKeyEntry("server", kp.getPrivate(), new char[0], new X509Certificate[] {cert});
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX", HybridTls.provider());
    kmf.init(ks, new char[0]);
    serverCtx = HybridTls.context(kmf.getKeyManagers(), null);

    KeyStore ts = KeyStore.getInstance("PKCS12");
    ts.load(null, null);
    ts.setCertificateEntry("ca", cert);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX", HybridTls.provider());
    tmf.init(ts);
    clientCtx = HybridTls.context(null, tmf.getTrustManagers());
  }

  /** Handshakes over loopback; returns null on success or the client's exception. */
  static Exception handshake(SSLParameters server, SSLParameters client) throws Exception {
    try (SSLServerSocket ss = (SSLServerSocket) serverCtx.getServerSocketFactory().createServerSocket(0)) {
      ss.setSSLParameters(server);
      CompletableFuture<Void> accepted = CompletableFuture.runAsync(() -> {
        try (SSLSocket s = (SSLSocket) ss.accept()) {
          s.startHandshake();
          s.getOutputStream().write(1);
        } catch (Exception ignored) {
          // The client's view is what the tests assert on.
        }
      });
      try (SSLSocket c = (SSLSocket) clientCtx.getSocketFactory().createSocket("localhost", ss.getLocalPort())) {
        c.setSSLParameters(client);
        c.startHandshake();
        assertEquals("TLSv1.3", c.getSession().getProtocol());
        assertEquals(1, c.getInputStream().read());
        return null;
      } catch (Exception e) {
        return e;
      } finally {
        accepted.get(10, TimeUnit.SECONDS);
      }
    }
  }

  static SSLParameters classicalOnly() {
    SSLParameters p = HybridTls.parameters(COMPATIBLE);
    p.setNamedGroups(new String[] {"x25519", "secp256r1"});
    return p;
  }

  @Test
  void strictHandshakeSucceeds() throws Exception {
    // Both sides offer only hybrid groups, so a completed handshake used one of them.
    assertNull(handshake(HybridTls.parameters(STRICT), HybridTls.parameters(STRICT)));
  }

  @Test
  void strictServerRejectsClassicalClient() throws Exception {
    assertNotNull(handshake(HybridTls.parameters(STRICT), classicalOnly()));
  }

  @Test
  void compatibleServerAcceptsClassicalClient() throws Exception {
    assertNull(handshake(HybridTls.parameters(COMPATIBLE), classicalOnly()));
  }

  @Test
  void rejectsTls12() throws Exception {
    SSLParameters old = HybridTls.parameters(COMPATIBLE);
    old.setProtocols(new String[] {"TLSv1.2"});
    assertNotNull(handshake(HybridTls.parameters(COMPATIBLE), old));
  }
}
