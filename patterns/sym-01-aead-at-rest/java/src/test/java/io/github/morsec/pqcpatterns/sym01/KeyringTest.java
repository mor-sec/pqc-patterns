package io.github.morsec.pqcpatterns.sym01;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;

class KeyringTest {
  private static final byte[] EMPTY = new byte[0];

  @Test
  void roundTrip() throws Exception {
    Keyring k = new Keyring(1, Keyring.newKey());
    byte[] ad = "customers/42/payment_method".getBytes(UTF_8);
    byte[] blob = k.encrypt("card ending 4242".getBytes(UTF_8), ad);
    assertArrayEquals("card ending 4242".getBytes(UTF_8), k.decrypt(blob, ad));
  }

  @Test
  void rejectsTampering() throws Exception {
    Keyring k = new Keyring(1, Keyring.newKey());
    byte[] ad = "customers/42".getBytes(UTF_8);
    byte[] blob = k.encrypt("secret".getBytes(UTF_8), ad);
    for (int i = 0; i < blob.length; i++) {
      byte[] bad = blob.clone();
      bad[i] ^= 1;
      final int at = i;
      assertThrows(Keyring.DecryptException.class, () -> k.decrypt(bad, ad), "byte " + at);
    }
    assertThrows(Keyring.DecryptException.class, () -> k.decrypt(blob, "customers/43".getBytes(UTF_8)));
    byte[] truncated = java.util.Arrays.copyOf(blob, blob.length - 1);
    assertThrows(Keyring.DecryptException.class, () -> k.decrypt(truncated, ad));
  }

  @Test
  void rotation() throws Exception {
    Keyring k = new Keyring(1, Keyring.newKey());
    byte[] old = k.encrypt("v1 data".getBytes(UTF_8), EMPTY);
    k.add(2, Keyring.newKey());
    k.rotate(2);
    byte[] fresh = k.encrypt("v2 data".getBytes(UTF_8), EMPTY);
    assertEquals(2, fresh[4]);
    assertArrayEquals("v1 data".getBytes(UTF_8), k.decrypt(old, EMPTY));
  }

  @Test
  void rejectsShortKey() {
    assertThrows(IllegalArgumentException.class, () -> new Keyring(1, new byte[16]));
  }

  @Test
  void noncesAreUnique() throws Exception {
    Keyring k = new Keyring(1, Keyring.newKey());
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      byte[] blob = k.encrypt(new byte[] {1}, EMPTY);
      assertTrue(seen.add(HexFormat.of().formatHex(blob, 5, 17)), "nonce reused");
    }
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    Keyring k = new Keyring(v.get("key_id").asInt(), hex.parseHex(v.get("key").asText()));
    byte[] pt = k.decrypt(hex.parseHex(v.get("blob").asText()), hex.parseHex(v.get("associated_data").asText()));
    assertArrayEquals(hex.parseHex(v.get("plaintext").asText()), pt);
  }
}
