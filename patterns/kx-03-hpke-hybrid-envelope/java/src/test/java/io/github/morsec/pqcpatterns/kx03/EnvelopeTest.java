package io.github.morsec.pqcpatterns.kx03;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class EnvelopeTest {
  static final byte[] INFO = "pqc-patterns/kx-03/test".getBytes(UTF_8);
  static final byte[] EMPTY = new byte[0];

  @Test
  void roundTrip() throws Exception {
    Envelope.KeyPair kp = Envelope.generateKey();
    assertEquals(32, kp.privateKey().length);
    assertEquals(1216, kp.publicKey().length);
    byte[] ad = "export-17".getBytes(UTF_8);
    byte[] msg = Envelope.seal(kp.publicKey(), INFO, ad, "data key".getBytes(UTF_8));
    assertArrayEquals("data key".getBytes(UTF_8), Envelope.open(kp, INFO, ad, msg));
  }

  @Test
  void rejectsTampering() throws Exception {
    Envelope.KeyPair kp = Envelope.generateKey();
    byte[] msg = Envelope.seal(kp.publicKey(), INFO, EMPTY, "secret".getBytes(UTF_8));
    for (int i : new int[] {0, 6, 6 + 1087, 6 + 1088, 6 + Envelope.ENC_LEN, msg.length - 1}) {
      byte[] bad = msg.clone();
      bad[i] ^= 1;
      assertThrows(Envelope.OpenException.class, () -> Envelope.open(kp, INFO, EMPTY, bad), "byte " + i);
    }
    assertThrows(Envelope.OpenException.class, () -> Envelope.open(kp, "other/app".getBytes(UTF_8), EMPTY, msg));
    assertThrows(Envelope.OpenException.class, () -> Envelope.open(kp, INFO, new byte[] {1}, msg));
    Envelope.KeyPair other = Envelope.generateKey();
    assertThrows(Envelope.OpenException.class, () -> Envelope.open(other, INFO, EMPTY, msg));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    Envelope.KeyPair kp = new Envelope.KeyPair(
        hex.parseHex(v.get("private_key").asText()), hex.parseHex(v.get("public_key").asText()));
    byte[] pt = Envelope.open(kp, hex.parseHex(v.get("info").asText()), hex.parseHex(v.get("aad").asText()),
        hex.parseHex(v.get("message").asText()));
    assertArrayEquals(hex.parseHex(v.get("plaintext").asText()), pt);

    byte[] msg = Envelope.seal(kp.publicKey(), INFO, EMPTY, "java to anyone".getBytes(UTF_8));
    assertArrayEquals("java to anyone".getBytes(UTF_8), Envelope.open(kp, INFO, EMPTY, msg));
  }
}
