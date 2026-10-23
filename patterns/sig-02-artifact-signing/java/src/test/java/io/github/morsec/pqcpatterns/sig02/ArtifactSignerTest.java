package io.github.morsec.pqcpatterns.sig02;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.morsec.pqcpatterns.sig02.ArtifactSigner.Signer;
import io.github.morsec.pqcpatterns.sig02.ArtifactSigner.Verifier;
import io.github.morsec.pqcpatterns.sig02.ArtifactSigner.VerifyException;
import io.github.morsec.pqcpatterns.sig02.ArtifactSigner.VerifyException.Reason;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class ArtifactSignerTest {
  private static final String NAME = "myapp-1.4.2-linux-amd64.tar.gz";

  private static byte[] pattern(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) {
      b[i] = (byte) (i % 251);
    }
    return b;
  }

  private static MLDSAPrivateKey newKey() throws Exception {
    byte[] seed = new byte[32];
    new SecureRandom().nextBytes(seed);
    return ArtifactSigner.loadPrivateKey(seed);
  }

  private static ByteArrayInputStream in(byte[] b) {
    return new ByteArrayInputStream(b);
  }

  private static Reason reason(Verifier v, String sig, String name, byte[] art) {
    VerifyException e = assertThrows(VerifyException.class, () -> v.verify(sig, name, in(art)));
    return e.reason;
  }

  @Test
  void signAndVerify() throws Exception {
    MLDSAPrivateKey k = newKey();
    Signer s = new Signer(k);
    Verifier v = new Verifier().add(k.getPublicKey());
    for (int n : new int[] {0, 1, 100_000}) {
      byte[] art = pattern(n);
      ArtifactSigner.Statement st = v.verify(s.sign(NAME, in(art)), NAME, in(art));
      assertEquals(n, st.size());
      assertEquals(ArtifactSigner.keyId(k.getPublicKey()), st.keyId());
    }
  }

  @Test
  void rejectsModifiedArtifact() throws Exception {
    MLDSAPrivateKey k = newKey();
    Verifier v = new Verifier().add(k.getPublicKey());
    byte[] art = pattern(1000);
    String sig = new Signer(k).sign(NAME, in(art));
    byte[] flipped = art.clone();
    flipped[500] ^= 1;
    for (byte[] bad :
        new byte[][] {flipped, Arrays.copyOf(art, 999), Arrays.copyOf(art, 1001), new byte[0]}) {
      assertEquals(Reason.WRONG_ARTIFACT, reason(v, sig, NAME, bad), bad.length + " bytes");
    }
  }

  @Test
  void rejectsWrongName() throws Exception {
    MLDSAPrivateKey k = newKey();
    Signer s = new Signer(k);
    Verifier v = new Verifier().add(k.getPublicKey());
    byte[] art = pattern(10);
    String sig = s.sign("myapp-1.4.1-linux-amd64.tar.gz", in(art));
    assertEquals(Reason.WRONG_ARTIFACT, reason(v, sig, NAME, art));
    assertThrows(IllegalArgumentException.class, () -> s.sign("has space", in(art)));
    assertThrows(IllegalArgumentException.class, () -> s.sign("", in(art)));
  }

  @Test
  void rejectsUntrustedKey() throws Exception {
    byte[] art = pattern(10);
    String sig = new Signer(newKey()).sign(NAME, in(art));
    assertEquals(Reason.UNKNOWN_KEY, reason(new Verifier().add(newKey().getPublicKey()), sig, NAME, art));
  }

  @Test
  void rotation() throws Exception {
    MLDSAPrivateKey old = newKey();
    MLDSAPrivateKey fresh = newKey();
    Verifier v = new Verifier().add(old.getPublicKey()).add(fresh.getPublicKey());
    byte[] art = pattern(10);
    for (MLDSAPrivateKey k : new MLDSAPrivateKey[] {old, fresh}) {
      v.verify(new Signer(k).sign(NAME, in(art)), NAME, in(art));
    }
  }

  @Test
  void rejectsOtherContext() throws Exception {
    MLDSAPrivateKey k = newKey();
    Verifier v = new Verifier().add(k.getPublicKey());
    byte[] art = pattern(10);
    String sig = new Signer(k).sign(NAME, in(art));
    String msg = sig.substring(0, sig.indexOf("signature: "));
    Signature s = Signature.getInstance("ML-DSA", new BouncyCastleProvider());
    s.initSign(k);
    s.setParameter(new ContextParameterSpec("pqc-patterns/sig-01/api-request/v2".getBytes(UTF_8)));
    s.update(msg.getBytes(UTF_8));
    String forged = msg + "signature: " + Base64.getEncoder().encodeToString(s.sign()) + "\n";
    assertEquals(Reason.SIGNATURE, reason(v, forged, NAME, art));
  }

  @Test
  void rejectsEditedStatement() throws Exception {
    MLDSAPrivateKey k = newKey();
    Verifier v = new Verifier().add(k.getPublicKey());
    byte[] art = pattern(10);
    String sig = new Signer(k).sign(NAME, in(art));
    String[][] edits = {{"size: 10\n", "size: 11\n"}, {NAME, "other.tar.gz"}, {"signed: 2", "signed: 1"}};
    for (String[] e : edits) {
      assertEquals(Reason.SIGNATURE, reason(v, sig.replaceFirst(e[0], e[1]), NAME, art), e[1]);
    }
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    MLDSAPrivateKey k = ArtifactSigner.loadPrivateKey(hex.parseHex(v.get("seed").asText()));
    assertEquals(v.get("public_key").asText(), hex.formatHex(k.getPublicKey().getPublicData()));
    assertEquals(v.get("key_id").asText(), ArtifactSigner.keyId(k.getPublicKey()));
    String name = v.get("name").asText();
    byte[] art = pattern(v.get("artifact_length").asInt());
    Clock fixed = Clock.fixed(Instant.parse(v.get("signed").asText()), ZoneOffset.UTC);
    String mine = new Signer(k, fixed).sign(name, in(art));
    String file = v.get("signature_file").asText();
    int cut = file.indexOf("signature: ");
    assertEquals(file.substring(0, cut), mine.substring(0, cut), "statement encoding differs");
    Verifier verifier = new Verifier().add(k.getPublicKey());
    verifier.verify(file, name, in(art));
    int i = 0;
    for (JsonNode bad : v.get("malformed_signature_files")) {
      assertEquals(Reason.MALFORMED, reason(verifier, bad.asText(), name, art), "malformed " + i++);
    }
  }
}
