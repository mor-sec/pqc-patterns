import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.HttpsURLConnection;
import org.apache.commons.lang3.RandomStringUtils;
import org.bouncycastle.crypto.hpke.HPKE;

class Fixtures {
  String newSessionToken() {
    // ruleid: pqc-token-weak-random
    Random r = new Random();
    // ruleid: pqc-token-weak-random
    return Long.toHexString(r.nextLong());
  }

  void randomness() {
    // ruleid: pqc-token-weak-random
    long apiKey = ThreadLocalRandom.current().nextLong();
    // ruleid: pqc-token-weak-random
    String csrfToken = RandomStringUtils.randomAlphanumeric(32);
    // ok: pqc-token-weak-random
    String resetToken = RandomStringUtils.secure().nextAlphanumeric(32);
    SecureRandom sr = new SecureRandom();
    byte[] nonce = new byte[12];
    // ok: pqc-token-weak-random
    sr.nextBytes(nonce);
    // ok: pqc-token-weak-random
    double jitter = Math.random();
    // ok: pqc-token-weak-random
    int delay = new Random().nextInt(100);
  }

  void kx() throws Exception {
    // ruleid: pqc-kx-rsa-encrypt
    Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    // ruleid: pqc-kx-classical-ecdh
    KeyAgreement.getInstance("ECDH");
    // ruleid: pqc-kx-classical-ecdh
    KeyAgreement.getInstance("X25519");
    // ruleid: pqc-kx-classical-ecdh
    new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256);
    // ok: pqc-kx-classical-ecdh
    new HPKE(HPKE.mode_base, HPKE.kem_X_WING, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256);
  }

  void sigs() throws Exception {
    // ruleid: pqc-sig-classical-keygen
    KeyPairGenerator.getInstance("RSA");
    // ruleid: pqc-sig-classical-keygen
    KeyPairGenerator.getInstance("EC");
    // ruleid: pqc-sig-classical-keygen
    KeyPairGenerator.getInstance("Ed25519");
    // ok: pqc-sig-classical-keygen
    KeyPairGenerator.getInstance("ML-DSA", "BC");
  }

  void sym(SecureRandom rng) throws Exception {
    // ruleid: pqc-sym-unauthenticated-mode
    Cipher.getInstance("AES");
    // ruleid: pqc-sym-unauthenticated-mode
    Cipher.getInstance("AES/CBC/PKCS5Padding");
    // ruleid: pqc-sym-unauthenticated-mode
    Cipher.getInstance("AES/ECB/PKCS5Padding");
    // ok: pqc-sym-unauthenticated-mode
    Cipher.getInstance("AES/GCM/NoPadding");

    KeyGenerator g = KeyGenerator.getInstance("AES");
    // ruleid: pqc-sym-aes-128
    g.init(128);
    KeyGenerator g2 = KeyGenerator.getInstance("AES");
    // ok: pqc-sym-aes-128
    g2.init(256);
    // ruleid: pqc-sym-aes-128
    new HPKE(HPKE.mode_base, HPKE.kem_X_WING, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM128);

    // ruleid: pqc-sym-static-nonce
    new GCMParameterSpec(128, new byte[12]);
    byte[] fixed = new byte[12];
    // ruleid: pqc-sym-static-nonce
    new GCMParameterSpec(128, fixed);
    byte[] nonce = new byte[12];
    rng.nextBytes(nonce);
    // ok: pqc-sym-static-nonce
    new GCMParameterSpec(128, nonce);
    // ruleid: pqc-sym-static-nonce
    new GCMParameterSpec(128, "123456789012".getBytes(java.nio.charset.StandardCharsets.UTF_8));
    // ruleid: pqc-sym-static-nonce
    new GCMParameterSpec(128, new byte[16], 0, 12);
    // ruleid: pqc-sym-static-nonce
    new GCMParameterSpec(128, new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12});
  }

  void tls(SSLParameters p) throws Exception {
    // ruleid: pqc-tls-classical-groups
    p.setNamedGroups(new String[] {"x25519", "secp256r1"});
    // ok: pqc-tls-classical-groups
    p.setNamedGroups(new String[] {"X25519MLKEM768", "x25519"});
    // ruleid: pqc-tls-classical-groups
    System.setProperty("jdk.tls.namedGroups", "x25519,secp256r1");
    // ok: pqc-tls-classical-groups
    System.setProperty("jdk.tls.namedGroups", "X25519MLKEM768,x25519");

    // ruleid: pqc-tls-min-version
    SSLContext.getInstance("TLSv1.2");
    // ok: pqc-tls-min-version
    SSLContext.getInstance("TLSv1.3");
    // ruleid: pqc-tls-min-version
    p.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});

    // ruleid: pqc-tls-no-verify
    HttpsURLConnection.setDefaultHostnameVerifier((host, session) -> true);
    // ruleid: pqc-tls-no-verify
    p.setEndpointIdentificationAlgorithm(null);
    // ok: pqc-tls-no-verify
    p.setEndpointIdentificationAlgorithm("HTTPS");
    // ruleid: pqc-tls-no-verify
    Object v = new org.apache.hc.client5.http.ssl.NoopHostnameVerifier();
    // ruleid: pqc-tls-no-verify
    Object t = io.netty.handler.ssl.util.InsecureTrustManagerFactory.INSTANCE;
    HttpsURLConnection.setDefaultHostnameVerifier(new javax.net.ssl.HostnameVerifier() {
      // ruleid: pqc-tls-no-verify
      public boolean verify(String host, javax.net.ssl.SSLSession session) { return true; }
    });
  }

  void hashes() throws Exception {
    // ruleid: pqc-hash-weak
    MessageDigest.getInstance("MD5");
    // ruleid: pqc-hash-weak
    MessageDigest.getInstance("SHA-1");
    // ok: pqc-hash-weak
    MessageDigest.getInstance("SHA-256");
  }
}

class TrustAll implements javax.net.ssl.X509TrustManager {
  public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) { }
  // ruleid: pqc-tls-no-verify
  public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) { }
  public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
}
