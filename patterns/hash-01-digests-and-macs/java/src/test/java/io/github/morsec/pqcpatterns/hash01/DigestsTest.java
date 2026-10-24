package io.github.morsec.pqcpatterns.hash01;

import static io.github.morsec.pqcpatterns.hash01.Digests.Result.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.morsec.pqcpatterns.hash01.Digests.Alg;
import java.io.ByteArrayInputStream;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

class DigestsTest {
  static final HexFormat HEX = HexFormat.of();
  static final byte[] ABC = "abc".getBytes(UTF_8);

  @Test
  void sumKnownAnswer() throws Exception {
    // FIPS 180-4 example value for "abc".
    byte[] want = HEX.parseHex("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
        + "8086072ba1e7cc2358baeca134c825a7");
    assertEquals("sha384-" + Base64.getEncoder().encodeToString(want), Digests.sum(ABC));
    assertEquals(Digests.sum(ABC), Digests.sum(new ByteArrayInputStream(ABC)));
  }

  @Test
  void checkRejects() {
    String good = Digests.sum(ABC);
    assertEquals(OK, Digests.check(good, ABC, Digests.STRONG));
    assertEquals(MISMATCH, Digests.check(good, "abd".getBytes(UTF_8), Digests.STRONG));
    String old = Digests.sumWith(Alg.SHA256, ABC);
    assertEquals(OK, Digests.check(old, ABC, Digests.COMPATIBLE));
    assertEquals(ALGORITHM_NOT_ALLOWED, Digests.check(old, ABC, Digests.STRONG));
    assertEquals(ALGORITHM_NOT_ALLOWED, Digests.check("md5-kAFQmDzST7DWlj99KOF/cg==", ABC, Digests.COMPATIBLE));
    assertEquals(MALFORMED, Digests.check(good.replaceFirst("-", ""), ABC, Digests.STRONG));
    assertEquals(MALFORMED, Digests.check(good.substring(0, good.length() - 8), ABC, Digests.STRONG));
    assertEquals(MALFORMED, Digests.check(good + "=", ABC, Digests.STRONG));
    String unpadded = old.substring(0, old.length() - 1);
    assertEquals(MALFORMED, Digests.check(unpadded, ABC, Digests.COMPATIBLE));
    assertNotEquals(OK, Digests.check(good.replace('+', '-').replace('/', '_'), ABC, Digests.STRONG));
  }

  @Test
  void tagKnownAnswer() {
    // RFC 4231 test case 6: a 131-byte key, larger than the hash block.
    byte[] key = new byte[131];
    Arrays.fill(key, (byte) 0xaa);
    byte[] msg = "Test Using Larger Than Block-Size Key - Hash Key First".getBytes(UTF_8);
    byte[] tag = Digests.tag(key, msg);
    assertEquals("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6"
        + "0c2ef6ab4030fe8296248df163f44952", HEX.formatHex(tag));
    assertTrue(Digests.verify(key, msg, tag));
    byte[] flipped = tag.clone();
    flipped[0] ^= 1;
    assertFalse(Digests.verify(key, msg, flipped));
    assertFalse(Digests.verify(key, "other".getBytes(UTF_8), tag));
    assertFalse(Digests.verify(key, msg, Arrays.copyOf(tag, 16)));
    assertThrows(IllegalArgumentException.class, () -> Digests.tag(Arrays.copyOf(key, 31), msg));
  }

  @Test
  void goVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    byte[] data = HEX.parseHex(v.get("data").asText());
    v.get("sums").forEach(s -> assertEquals(OK, Digests.check(s.asText(), data, Digests.COMPATIBLE), s.asText()));
    assertEquals(v.get("sums").get("sha384").asText(), Digests.sum(data));
    v.get("reject").forEach(s -> assertNotEquals(OK, Digests.check(s.asText(), data, Digests.COMPATIBLE), s.asText()));
    assertTrue(Digests.verify(HEX.parseHex(v.get("hmac_key").asText()), HEX.parseHex(v.get("hmac_msg").asText()),
        HEX.parseHex(v.get("hmac_tag").asText())));
  }
}
