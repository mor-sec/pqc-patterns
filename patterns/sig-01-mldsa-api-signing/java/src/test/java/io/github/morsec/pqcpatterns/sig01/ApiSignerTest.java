package io.github.morsec.pqcpatterns.sig01;

import static io.github.morsec.pqcpatterns.sig01.ApiSigner.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.security.Signature;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.interfaces.MLDSAPublicKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class ApiSignerTest {
  static final Instant T0 = Instant.ofEpochSecond(1_790_000_000L);

  static Request req() {
    return new Request("svc-a-2026", T0, "POST", "/v1/payments?dry_run=false", "{\"amount\":1000}".getBytes(UTF_8));
  }

  static Failure failureOf(Map<String, MLDSAPublicKey> keys, Request r, byte[] sig) {
    VerifyException e = assertThrows(VerifyException.class, () -> verify(keys, r, sig, T0, DEFAULT_MAX_SKEW));
    return e.failure;
  }

  @Test
  void roundTrip() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    byte[] sig = sign(sk, req());
    assertEquals(3309, sig.length);
    verify(Map.of("svc-a-2026", sk.getPublicKey()), req(), sig, T0, DEFAULT_MAX_SKEW);
  }

  @Test
  void rejectsTampering() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    var keys = Map.of("svc-a-2026", sk.getPublicKey());
    byte[] sig = sign(sk, req());
    Request r = req();
    for (Request t :
        new Request[] {
          new Request(r.keyId(), r.timestamp(), r.method(), r.path(), "{\"amount\":9000}".getBytes(UTF_8)),
          new Request(r.keyId(), r.timestamp(), r.method(), "/v1/refunds?dry_run=false", r.body()),
          new Request(r.keyId(), r.timestamp(), "PUT", r.path(), r.body()),
          new Request(r.keyId(), T0.plusSeconds(1), r.method(), r.path(), r.body())
        }) {
      assertEquals(Failure.SIGNATURE, failureOf(keys, t, sig));
    }
    byte[] bad = sig.clone();
    bad[100] ^= 1;
    assertEquals(Failure.SIGNATURE, failureOf(keys, r, bad));
  }

  @Test
  void rejectsWrongContext() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Signature s = Signature.getInstance("ML-DSA", new BouncyCastleProvider());
    s.initSign(sk);
    s.setParameter(new ContextParameterSpec("some/other/purpose".getBytes(UTF_8)));
    s.update(req().message());
    assertEquals(Failure.SIGNATURE, failureOf(Map.of("svc-a-2026", sk.getPublicKey()), req(), s.sign()));
  }

  @Test
  void rejectsStaleAndUnknown() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    var keys = Map.of("svc-a-2026", sk.getPublicKey());
    Request r = req();
    Request old = new Request(r.keyId(), T0.minusSeconds(360), r.method(), r.path(), r.body());
    assertEquals(Failure.STALE, failureOf(keys, old, sign(sk, old)));
    Request unknown = new Request("unknown", T0, r.method(), r.path(), r.body());
    assertEquals(Failure.UNKNOWN_KEY, failureOf(keys, unknown, sign(sk, unknown)));
  }

  @Test
  void fieldBoundaries() {
    Request a = new Request("k", T0, "GET", "/ab", "c".getBytes(UTF_8));
    Request b = new Request("k", T0, "GET", "/a", "bc".getBytes(UTF_8));
    assertFalse(java.util.Arrays.equals(a.message(), b.message()));
  }

  @Test
  void seedRoundTrip() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    assertEquals(32, sk.getSeed().length);
    assertArrayEquals(sk.getPublicKey().getPublicData(), loadPrivateKey(sk.getSeed()).getPublicKey().getPublicData());
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    byte[] pk = hex.parseHex(v.get("public_key").asText());
    assertArrayEquals(pk, loadPrivateKey(hex.parseHex(v.get("seed").asText())).getPublicKey().getPublicData());

    Instant ts = Instant.ofEpochSecond(v.get("timestamp").asLong());
    Request r = new Request(v.get("key_id").asText(), ts, v.get("method").asText(), v.get("path").asText(),
        hex.parseHex(v.get("body").asText()));
    verify(Map.of(r.keyId(), loadPublicKey(pk)), r, hex.parseHex(v.get("signature").asText()), ts, DEFAULT_MAX_SKEW);
  }
}
