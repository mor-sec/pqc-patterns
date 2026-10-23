package io.github.morsec.pqcpatterns.kx02;

import java.io.IOException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Provider;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Pattern KX-02: mutual TLS 1.3 between services, with a post-quantum hybrid key exchange (RFC
 * 10024) and an allow-list of client identities checked inside the handshake.
 *
 * <p>Each workload has a certificate from an internal CA. Clients are named by a single URI SAN,
 * such as {@code spiffe://example.org/billing}. Trusting the CA proves who a client is; the
 * allow-list decides whether it may connect.
 *
 * <p>In JSSE the TLS version, groups, client-auth requirement and hostname check live in {@link
 * SSLParameters}, not in the {@link SSLContext}. Create sockets and engines through the methods
 * here, which apply them, rather than through the context's own factories.
 *
 * <p>Uses Bouncy Castle JSSE so it runs on Java 21 LTS. Certificates stay classical (ECDSA);
 * track pattern PKI-01 for ML-DSA certificates.
 */
public final class HybridMtls {
  /** Hybrid groups in preference order. There is no classical fallback. */
  public static final List<String> HYBRID = List.of("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024");

  private static final Provider BC = new BouncyCastleProvider();
  private static final Provider BCJSSE = new BouncyCastleJsseProvider(BC);
  private static final int URI_SAN = 6;

  private HybridMtls() {}

  /** The JSSE provider used here; also use it for KeyManagerFactory and TrustManagerFactory. */
  public static Provider provider() {
    return BCJSSE;
  }

  /**
   * A server context that trusts client certificates from {@code clientCas} and accepts only the
   * identities in {@code allowed}.
   */
  public static SSLContext serverContext(KeyManager[] keyManagers, TrustManager[] clientCas, Set<String> allowed)
      throws GeneralSecurityException {
    X509ExtendedTrustManager pkix = null;
    for (TrustManager tm : clientCas) {
      if (tm instanceof X509ExtendedTrustManager x) {
        pkix = x;
      }
    }
    if (pkix == null) {
      throw new GeneralSecurityException("no X509ExtendedTrustManager in clientCas");
    }
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", BCJSSE);
    ctx.init(keyManagers, new TrustManager[] {new AllowList(pkix, Set.copyOf(allowed))}, null);
    return ctx;
  }

  /** A client context that presents the key managers' certificate and trusts {@code roots}. */
  public static SSLContext clientContext(KeyManager[] keyManagers, TrustManager[] roots)
      throws GeneralSecurityException {
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", BCJSSE);
    ctx.init(keyManagers, roots, null);
    return ctx;
  }

  /** TLS 1.3, hybrid groups only, client certificate required. */
  public static SSLParameters serverParameters() {
    SSLParameters p = base();
    p.setNeedClientAuth(true);
    return p;
  }

  /** TLS 1.3, hybrid groups only, server hostname verified. */
  public static SSLParameters clientParameters() {
    SSLParameters p = base();
    p.setEndpointIdentificationAlgorithm("HTTPS");
    return p;
  }

  private static SSLParameters base() {
    SSLParameters p = new SSLParameters();
    p.setProtocols(new String[] {"TLSv1.3"});
    p.setNamedGroups(HYBRID.toArray(String[]::new));
    return p;
  }

  public static SSLServerSocket serverSocket(SSLContext ctx, int port) throws IOException {
    SSLServerSocket s = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(port);
    s.setSSLParameters(serverParameters());
    return s;
  }

  public static SSLSocket clientSocket(SSLContext ctx, String host, int port) throws IOException {
    SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket(host, port);
    s.setSSLParameters(clientParameters());
    return s;
  }

  public static SSLEngine serverEngine(SSLContext ctx) {
    SSLEngine e = ctx.createSSLEngine();
    e.setUseClientMode(false);
    e.setSSLParameters(serverParameters());
    return e;
  }

  public static SSLEngine clientEngine(SSLContext ctx, String host, int port) {
    SSLEngine e = ctx.createSSLEngine(host, port);
    e.setUseClientMode(true);
    e.setSSLParameters(clientParameters());
    return e;
  }

  /** The URI SAN of the peer's verified leaf certificate, for decisions finer than the allow-list. */
  public static Optional<String> peerIdentity(SSLSession session) {
    try {
      return identity((X509Certificate) session.getPeerCertificates()[0]);
    } catch (SSLPeerUnverifiedException e) {
      return Optional.empty();
    }
  }

  /** The single URI SAN of a certificate, or empty if it has none or several. */
  static Optional<String> identity(X509Certificate cert) {
    try {
      Collection<List<?>> sans = cert.getSubjectAlternativeNames();
      if (sans == null) {
        return Optional.empty();
      }
      List<String> uris = sans.stream()
          .filter(san -> Integer.valueOf(URI_SAN).equals(san.get(0)))
          .map(san -> (String) san.get(1))
          .toList();
      return uris.size() == 1 ? Optional.of(uris.get(0)) : Optional.empty();
    } catch (CertificateParsingException e) {
      return Optional.empty();
    }
  }

  /** Runs the PKIX checks first, then requires the client's identity to be allowed. */
  private static final class AllowList extends X509ExtendedTrustManager {
    private final X509ExtendedTrustManager pkix;
    private final Set<String> allowed;

    AllowList(X509ExtendedTrustManager pkix, Set<String> allowed) {
      this.pkix = pkix;
      this.allowed = allowed;
    }

    private void requireAllowed(X509Certificate[] chain) throws CertificateException {
      if (!identity(chain[0]).filter(allowed::contains).isPresent()) {
        throw new CertificateException("client identity is not on the allow-list");
      }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      pkix.checkClientTrusted(chain, authType, socket);
      requireAllowed(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      pkix.checkClientTrusted(chain, authType, engine);
      requireAllowed(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      pkix.checkClientTrusted(chain, authType);
      requireAllowed(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      throw new CertificateException("server context does not verify servers");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      throw new CertificateException("server context does not verify servers");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      throw new CertificateException("server context does not verify servers");
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return pkix.getAcceptedIssuers();
    }
  }
}
