package io.github.morsec.pqcpatterns.sess02;

import static io.github.morsec.pqcpatterns.sess02.MlDsaTokens.*;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;

class MlDsaTokensTest {
  static final Instant T0 = Instant.ofEpochSecond(1_790_000_000L);
  static final String ISS = "https://auth.internal";
  static final String AUD = "https://payments.internal";
  static final String KID = "auth-2026-10";
  static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  static final ObjectMapper JSON = new ObjectMapper();

  static Claims claims() {
    return new Claims(ISS, "svc-billing", AUD, T0.getEpochSecond(), T0.getEpochSecond() + 900, null);
  }

  static Failure failureOf(Verifier v, String token) {
    return assertThrows(VerifyException.class, () -> v.verify(token, T0)).failure;
  }

  static String forge(MLDSAPrivateKey sk, String header, String claimsJson, byte[] ctx) throws Exception {
    String input = B64.encodeToString(header.getBytes(UTF_8)) + "." + B64.encodeToString(claimsJson.getBytes(UTF_8));
    Signature s = Signature.getInstance("ML-DSA", new BouncyCastleProvider());
    s.initSign(sk);
    if (ctx != null) {
      s.setParameter(new ContextParameterSpec(ctx));
    }
    s.update(input.getBytes(US_ASCII));
    return input + "." + B64.encodeToString(s.sign());
  }

  @Test
  void roundTrip() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    assertEquals(claims(), v.verify(sign(sk, KID, claims()), T0));
  }

  @Test
  void rejectsTampering() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    String[] parts = sign(sk, KID, claims()).split("\\.");
    Claims c = claims();
    String evil = JSON.writeValueAsString(new Claims(c.iss(), "svc-admin", c.aud(), c.iat(), c.exp(), null));
    assertEquals(Failure.SIGNATURE, failureOf(v, parts[0] + "." + B64.encodeToString(evil.getBytes(UTF_8)) + "." + parts[2]));
  }

  @Test
  void rejectsHeaders() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    String body = JSON.writeValueAsString(claims());
    Map<String, Failure> cases = Map.of(
        "{\"alg\":\"none\",\"typ\":\"at+jwt\",\"kid\":\"auth-2026-10\"}", Failure.HEADER,
        "{\"alg\":\"ES256\",\"typ\":\"at+jwt\",\"kid\":\"auth-2026-10\"}", Failure.HEADER,
        "{\"alg\":\"ML-DSA-65\",\"typ\":\"id+jwt\",\"kid\":\"auth-2026-10\"}", Failure.HEADER,
        "{\"alg\":\"ML-DSA-65\",\"kid\":\"auth-2026-10\"}", Failure.HEADER,
        "{\"alg\":\"ML-DSA-65\",\"typ\":\"at+jwt\",\"kid\":\"auth-2026-10\",\"jku\":\"https://evil.example\"}", Failure.MALFORMED,
        "{\"alg\":\"none\",\"alg\":\"ML-DSA-65\",\"typ\":\"at+jwt\",\"kid\":\"auth-2026-10\"}", Failure.MALFORMED,
        "{\"alg\":\"ML-DSA-65\",\"typ\":\"at+jwt\",\"kid\":\"other\"}", Failure.UNKNOWN_KEY);
    for (var e : cases.entrySet()) {
      assertEquals(e.getValue(), failureOf(v, forge(sk, e.getKey(), body, null)), e.getKey());
    }
  }

  @Test
  void rejectsNonEmptyContext() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    String tok = forge(sk, "{\"alg\":\"ML-DSA-65\",\"typ\":\"at+jwt\",\"kid\":\"auth-2026-10\"}",
        JSON.writeValueAsString(claims()), "x".getBytes(UTF_8));
    assertEquals(Failure.SIGNATURE, failureOf(v, tok));
  }

  @Test
  void rejectsOtherKey() throws Exception {
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, generateKey().getPublicKey()));
    assertEquals(Failure.SIGNATURE, failureOf(v, sign(generateKey(), KID, claims())));
  }

  @Test
  void claimChecks() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    long t = T0.getEpochSecond();
    Map<UnaryOperator<Claims>, Failure> cases = Map.of(
        c -> new Claims("https://evil.example", c.sub(), c.aud(), c.iat(), c.exp(), null), Failure.CLAIMS,
        c -> new Claims(c.iss(), c.sub(), "https://ledger.internal", c.iat(), c.exp(), null), Failure.CLAIMS,
        c -> new Claims(c.iss(), c.sub(), c.aud(), c.iat(), t - 60, null), Failure.EXPIRED,
        c -> new Claims(c.iss(), c.sub(), c.aud(), t + 60, c.exp(), null), Failure.EXPIRED,
        c -> new Claims(c.iss(), c.sub(), c.aud(), c.iat(), t + 86_400, null), Failure.EXPIRED,
        c -> new Claims(c.iss(), c.sub(), c.aud(), 0, c.exp(), null), Failure.EXPIRED,
        c -> new Claims(c.iss(), c.sub(), c.aud(), Long.MIN_VALUE, Long.MAX_VALUE, null), Failure.EXPIRED);
    for (var e : cases.entrySet()) {
      assertEquals(e.getValue(), failureOf(v, sign(sk, KID, e.getKey().apply(claims()))));
    }
  }

  @Test
  void malformed() throws Exception {
    MLDSAPrivateKey sk = generateKey();
    Verifier v = new Verifier(ISS, AUD, Map.of(KID, sk.getPublicKey()));
    String tok = sign(sk, KID, claims());
    for (String bad : new String[] {tok.substring(0, tok.lastIndexOf('.')), tok + ".x", tok + "=", ""}) {
      assertEquals(Failure.MALFORMED, failureOf(v, bad));
    }
    assertThrows(IllegalArgumentException.class, () -> new Verifier(ISS, "", Map.of()));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode vec = JSON.readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    byte[] pk = hex.parseHex(vec.get("public_key").asText());
    assertArrayEquals(pk, loadPrivateKey(hex.parseHex(vec.get("seed").asText())).getPublicKey().getPublicData());
    Verifier v = new Verifier(vec.get("iss").asText(), vec.get("aud").asText(),
        Map.of(vec.get("kid").asText(), loadPublicKey(pk)));
    Claims c = v.verify(vec.get("token").asText(), Instant.ofEpochSecond(vec.get("now").asLong()));
    assertEquals(vec.get("expected_sub").asText(), c.sub());
  }
}
