package io.github.morsec.pqcpatterns.hash02;

import static io.github.morsec.pqcpatterns.hash02.Kdf.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class KdfTest {
  static final byte[] SECRET = new byte[32];
  static final String PURPOSE = "billing-exports/aes-256-gcm/v1";
  static final byte[] NONE = new byte[0];

  static {
    Arrays.fill(SECRET, (byte) 0x0b);
  }

  static byte[] b(String s) {
    return s.getBytes(UTF_8);
  }

  @Test
  void separation() {
    byte[] base = derive(SECRET, NONE, PURPOSE, b("tenant-42"), 32);
    for (byte[] other : List.of(
        derive(SECRET, NONE, "billing-exports/hmac-sha256/v1", b("tenant-42"), 32),
        derive(SECRET, NONE, PURPOSE, b("tenant-43"), 32),
        derive(SECRET, b("salt"), PURPOSE, b("tenant-42"), 32),
        derive(SECRET, NONE, PURPOSE + "t", b("enant-42"), 32))) {
      assertFalse(Arrays.equals(base, other));
    }
    byte[] shortKey = derive(SECRET, NONE, PURPOSE, b("tenant-42"), 16);
    assertFalse(Arrays.equals(shortKey, Arrays.copyOf(base, 16)));
  }

  @Test
  void rejectsBadInput() {
    assertThrows(IllegalArgumentException.class, () -> derive(Arrays.copyOf(SECRET, 31), NONE, "p", NONE, 32));
    assertThrows(IllegalArgumentException.class, () -> derive(SECRET, NONE, "", NONE, 32));
    assertThrows(IllegalArgumentException.class, () -> derive(SECRET, NONE, "p", NONE, 8));
    assertThrows(IllegalArgumentException.class, () -> derive(SECRET, NONE, "p", NONE, MAX_KEY_LEN + 1));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    byte[] ctx = hex.parseHex(v.get("context").asText());
    int len = v.get("key_len").asInt();
    assertEquals(v.get("info").asText(), hex.formatHex(info(v.get("purpose").asText(), ctx, len)));
    byte[] k = derive(hex.parseHex(v.get("secret").asText()), hex.parseHex(v.get("salt").asText()),
        v.get("purpose").asText(), ctx, len);
    assertEquals(v.get("key").asText(), hex.formatHex(k));
  }
}
