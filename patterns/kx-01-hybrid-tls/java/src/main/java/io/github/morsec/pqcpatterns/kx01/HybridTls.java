package io.github.morsec.pqcpatterns.kx01;

import java.security.GeneralSecurityException;
import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Pattern KX-01: TLS 1.3 configuration that negotiates a hybrid post-quantum key exchange (RFC
 * 10024).
 *
 * <ul>
 *   <li>{@link Mode#STRICT}: only hybrid groups. Peers that cannot do post-quantum key exchange
 *       fail the handshake. Use for service-to-service traffic you control.
 *   <li>{@link Mode#COMPATIBLE}: hybrid groups first, classical x25519 as fallback. Use for public
 *       endpoints until your clients are upgraded.
 * </ul>
 *
 * <p>Uses the Bouncy Castle JSSE provider so it works on Java 21 LTS. On JDK 27+ the built-in
 * SunJSSE supports the same group names through the same {@link SSLParameters#setNamedGroups}
 * call, so only {@link #context} changes. Certificates stay classical; harvest-now,
 * decrypt-later attacks target key exchange, not authentication (see pattern PKI-01).
 */
public final class HybridTls {
  public enum Mode {
    STRICT,
    COMPATIBLE
  }

  /** Hybrid groups in preference order. Put SecP384r1MLKEM1024 first for CNSA 2.0 systems. */
  public static final List<String> HYBRID = List.of("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024");

  private static final Provider BC = new BouncyCastleProvider();
  private static final Provider BCJSSE = new BouncyCastleJsseProvider(BC);

  private HybridTls() {}

  /** The JSSE provider used by {@link #context}; also use it for KeyManagerFactory and friends. */
  public static Provider provider() {
    return BCJSSE;
  }

  /** A TLS 1.3 context backed by Bouncy Castle JSSE. */
  public static SSLContext context(KeyManager[] keyManagers, TrustManager[] trustManagers)
      throws GeneralSecurityException {
    SSLContext ctx = SSLContext.getInstance("TLSv1.3", BCJSSE);
    ctx.init(keyManagers, trustManagers, null);
    return ctx;
  }

  /**
   * Parameters to apply to every client socket, server socket or SSLEngine. Clients should also
   * keep hostname verification on, which this sets.
   */
  public static SSLParameters parameters(Mode mode) {
    List<String> groups = new ArrayList<>(HYBRID);
    if (mode == Mode.COMPATIBLE) {
      groups.add("x25519");
    }
    SSLParameters p = new SSLParameters();
    p.setProtocols(new String[] {"TLSv1.3"});
    p.setNamedGroups(groups.toArray(String[]::new));
    p.setEndpointIdentificationAlgorithm("HTTPS");
    return p;
  }
}
