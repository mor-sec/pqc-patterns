package io.github.morsec.pqcpatterns.sym03;

import static io.github.morsec.pqcpatterns.sym03.StreamingAead.HEADER_SIZE;
import static io.github.morsec.pqcpatterns.sym03.StreamingAead.SEGMENT_SIZE;
import static io.github.morsec.pqcpatterns.sym03.StreamingAead.TAG_SIZE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Set;
import org.junit.jupiter.api.Test;

class StreamingAeadTest {
  private static final int SEG = SEGMENT_SIZE;
  private static final byte[] EMPTY = new byte[0];

  private static byte[] pattern(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) {
      b[i] = (byte) (i % 251);
    }
    return b;
  }

  private static byte[] seal(byte[] key, byte[] pt, byte[] ad) throws IOException {
    ByteArrayOutputStream ct = new ByteArrayOutputStream();
    StreamingAead.encrypt(new ByteArrayInputStream(pt), ct, key, ad);
    return ct.toByteArray();
  }

  private static byte[] open(byte[] ct, byte[] key, byte[] ad)
      throws IOException, StreamingAead.DecryptException {
    ByteArrayOutputStream pt = new ByteArrayOutputStream();
    StreamingAead.decrypt(new ByteArrayInputStream(ct), pt, key, ad);
    return pt.toByteArray();
  }

  private static void assertRejected(byte[] ct, byte[] key, byte[] ad, String message) {
    assertThrows(StreamingAead.DecryptException.class, () -> open(ct, key, ad), message);
  }

  @Test
  void roundTrip() throws Exception {
    byte[] key = StreamingAead.newKey();
    byte[] ad = "backups/2026-10-23.tar".getBytes(UTF_8);
    for (int n : new int[] {0, 1, SEG - 1, SEG, SEG + 1, 3 * SEG, 3 * SEG + 7}) {
      byte[] pt = pattern(n);
      byte[] ct = seal(key, pt, ad);
      int segments = Math.max(1, (n + SEG - 1) / SEG);
      assertEquals(HEADER_SIZE + n + segments * TAG_SIZE, ct.length, "size " + n);
      assertArrayEquals(pt, open(ct, key, ad), "size " + n);
    }
  }

  /** Returns at most one byte per read, like a slow network peer. */
  private static final class OneByte extends FilterInputStream {
    OneByte(InputStream in) {
      super(in);
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      return super.read(b, off, Math.min(len, 1));
    }
  }

  @Test
  void shortReads() throws Exception {
    byte[] key = StreamingAead.newKey();
    byte[] pt = pattern(2 * SEG + 3);
    ByteArrayOutputStream ct = new ByteArrayOutputStream();
    StreamingAead.encrypt(new OneByte(new ByteArrayInputStream(pt)), ct, key, EMPTY);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    StreamingAead.decrypt(new OneByte(new ByteArrayInputStream(ct.toByteArray())), out, key, EMPTY);
    assertArrayEquals(pt, out.toByteArray());
  }

  @Test
  void rejectsTruncation() throws Exception {
    byte[] key = StreamingAead.newKey();
    for (int n : new int[] {SEG, 2 * SEG, 2 * SEG + 5}) {
      byte[] ct = seal(key, pattern(n), EMPTY);
      int finalLen = (n - 1) % SEG + 1 + TAG_SIZE;
      for (int cut : new int[] {finalLen, 1, SEG + TAG_SIZE, ct.length - HEADER_SIZE + 1, ct.length}) {
        if (cut > ct.length) {
          continue;
        }
        assertRejected(Arrays.copyOf(ct, ct.length - cut), key, EMPTY, "size " + n + " cut " + cut);
      }
    }
  }

  @Test
  void rejectsAppendedData() throws Exception {
    byte[] key = StreamingAead.newKey();
    for (int n : new int[] {0, 5, SEG}) {
      byte[] ct = seal(key, pattern(n), EMPTY);
      for (int extra : new int[] {1, TAG_SIZE, SEG + TAG_SIZE}) {
        assertRejected(Arrays.copyOf(ct, ct.length + extra), key, EMPTY, "size " + n + " +" + extra);
      }
    }
    byte[] a = seal(key, pattern(SEG), EMPTY);
    byte[] b = seal(key, pattern(SEG), EMPTY);
    byte[] joined = Arrays.copyOf(a, a.length + b.length - HEADER_SIZE);
    System.arraycopy(b, HEADER_SIZE, joined, a.length, b.length - HEADER_SIZE);
    assertRejected(joined, key, EMPTY, "concatenated streams accepted");
  }

  @Test
  void rejectsReorderedSegments() throws Exception {
    byte[] key = StreamingAead.newKey();
    byte[] ct = seal(key, pattern(3 * SEG), EMPTY);
    int s = SEG + TAG_SIZE;
    byte[] swapped = ct.clone();
    System.arraycopy(ct, HEADER_SIZE + s, swapped, HEADER_SIZE, s);
    System.arraycopy(ct, HEADER_SIZE, swapped, HEADER_SIZE + s, s);
    assertRejected(swapped, key, EMPTY, "swapped segments accepted");
  }

  @Test
  void rejectsTampering() throws Exception {
    byte[] key = StreamingAead.newKey();
    byte[] ad = "uploads/42".getBytes(UTF_8);
    byte[] ct = seal(key, pattern(100), ad);
    for (int i = 0; i < ct.length; i++) {
      byte[] bad = ct.clone();
      bad[i] ^= 1;
      assertRejected(bad, key, ad, "byte " + i);
    }
    assertRejected(ct, key, "uploads/43".getBytes(UTF_8), "wrong associated data");
    assertRejected(ct, StreamingAead.newKey(), ad, "wrong key");
    assertRejected(EMPTY, key, ad, "empty input");
  }

  @Test
  void rejectsShortKey() {
    assertThrows(IllegalArgumentException.class, () -> seal(new byte[16], EMPTY, EMPTY));
  }

  @Test
  void headersAreUnique() throws Exception {
    byte[] key = StreamingAead.newKey();
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      byte[] header = Arrays.copyOf(seal(key, EMPTY, EMPTY), HEADER_SIZE);
      assertTrue(seen.add(HexFormat.of().formatHex(header)), "header reused");
    }
  }

  @Test
  void passesThroughIoErrors() throws Exception {
    byte[] key = StreamingAead.newKey();
    byte[] ct = seal(key, "x".getBytes(UTF_8), EMPTY);
    OutputStream diskFull =
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            throw new IOException("disk full");
          }
        };
    assertThrows(
        IOException.class,
        () -> StreamingAead.decrypt(new ByteArrayInputStream(ct), diskFull, key, EMPTY));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    HexFormat hex = HexFormat.of();
    byte[] key = hex.parseHex(v.get("key").asText());
    byte[] ad = hex.parseHex(v.get("associated_data").asText());
    byte[] salt = hex.parseHex(v.get("salt").asText());
    byte[] prefix = hex.parseHex(v.get("nonce_prefix").asText());

    byte[] pt = hex.parseHex(v.get("plaintext").asText());
    byte[] ct = hex.parseHex(v.get("ciphertext").asText());
    assertArrayEquals(ct, sealFixed(pt, key, ad, salt, prefix));
    assertArrayEquals(pt, open(ct, key, ad));

    byte[] large = pattern(v.get("large_plaintext_length").asInt());
    byte[] largeCt = sealFixed(large, key, ad, salt, prefix);
    byte[] hash = MessageDigest.getInstance("SHA-256").digest(largeCt);
    assertEquals(v.get("large_ciphertext_sha256").asText(), hex.formatHex(hash));
    assertArrayEquals(large, open(largeCt, key, ad));
  }

  private static byte[] sealFixed(byte[] pt, byte[] key, byte[] ad, byte[] salt, byte[] prefix)
      throws IOException {
    ByteArrayOutputStream ct = new ByteArrayOutputStream();
    StreamingAead.encrypt(new ByteArrayInputStream(pt), ct, key, ad, salt, prefix);
    return ct.toByteArray();
  }
}
