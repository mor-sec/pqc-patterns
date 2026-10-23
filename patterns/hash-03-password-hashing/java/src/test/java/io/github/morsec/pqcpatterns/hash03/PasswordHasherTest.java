package io.github.morsec.pqcpatterns.hash03;

import static io.github.morsec.pqcpatterns.hash03.PasswordHasher.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PasswordHasherTest {
  static final Params FAST = new Params(8 * 1024, 1, 1);
  static final byte[] PW = "correct horse battery staple".getBytes(UTF_8);

  @Test
  void roundTrip() {
    String h = hash(PW, FAST);
    assertTrue(h.startsWith("$argon2id$v=19$m=8192,t=1,p=1$"), h);
    assertEquals(Result.OK, verify(PW, h, FAST));
    assertEquals(Result.MISMATCH, verify("Correct horse battery staple".getBytes(UTF_8), h, FAST));
    assertNotEquals(h, hash(PW, FAST), "salt is not fresh");
  }

  @Test
  void needsRehash() {
    assertEquals(Result.OK_NEEDS_REHASH, verify(PW, hash(PW, FAST), new Params(16 * 1024, 2, 1)));
  }

  @Test
  void rejectsMalformed() {
    String good = hash(PW, FAST);
    String[] f = good.split("\\$");
    String shortSalt = String.join("$", "", f[1], f[2], f[3], Base64.getEncoder().withoutPadding().encodeToString("short".getBytes(UTF_8)), f[5]);
    String shortHash = String.join("$", "", f[1], f[2], f[3], f[4], f[5].substring(0, 20));
    for (String bad : new String[] {
        good.replace("argon2id", "argon2i"),
        good.replace("v=19", "v=16"),
        good.replace("m=8192", "m=08192"),
        good.replace("m=8192", "m=+8192"),
        good.replace("m=8192,t=1,p=1", "t=1,m=8192,p=1"),
        good.replace("m=8192", "m=4194304"),
        good.replace("p=1", "p=0"),
        shortSalt,
        good + "=",
        shortHash,
        "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
        "",
        good + "$x"}) {
      assertThrows(IllegalArgumentException.class, () -> verify(PW, bad, FAST), bad);
    }
  }

  @Test
  void argon2idKnownAnswer() {
    byte[] out = argon2("password".getBytes(UTF_8), "somesalt".getBytes(UTF_8), new Params(64 * 1024, 2, 1));
    assertEquals("CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc", Base64.getEncoder().withoutPadding().encodeToString(out));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    assertEquals(Result.OK, verify(v.get("password").asText().getBytes(UTF_8), v.get("phc").asText(), FAST));
  }
}
