package io.github.morsec.pqcpatterns.key01;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.morsec.pqcpatterns.key01.PqcKeys.Algorithm;
import io.github.morsec.pqcpatterns.key01.PqcKeys.KeyPair;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.HexFormat;
import org.bouncycastle.jcajce.interfaces.MLDSAPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PqcKeysTest {
  @Test
  void roundTrip() throws Exception {
    for (Algorithm alg : Algorithm.values()) {
      KeyPair k = PqcKeys.generate(alg);
      KeyPair got = PqcKeys.parsePrivateKeyPem(k.privateKeyPem());
      assertEquals(alg, got.algorithm());
      assertArrayEquals(k.seed(), got.seed());
      assertArrayEquals(k.publicKey(), got.publicKey());
      PqcKeys.PublicKeyInfo pub = PqcKeys.parsePublicKeyPem(k.publicKeyPem());
      assertEquals(alg, pub.algorithm());
      assertArrayEquals(k.publicKey(), pub.publicKey());
    }
  }

  @Test
  void usableJcaKey() throws Exception {
    PrivateKey sk = PqcKeys.generate(Algorithm.ML_DSA_65).privateKey();
    Signature s = Signature.getInstance("ML-DSA", new BouncyCastleProvider());
    s.initSign(sk);
    s.update("hello".getBytes(UTF_8));
    byte[] sig = s.sign();
    s.initVerify(((MLDSAPrivateKey) sk).getPublicKey());
    s.update("hello".getBytes(UTF_8));
    assertTrue(s.verify(sig));
  }

  @Test
  void keyId() throws Exception {
    KeyPair a = PqcKeys.generate(Algorithm.ML_DSA_65);
    KeyPair b = PqcKeys.generate(Algorithm.ML_DSA_65);
    assertEquals(64, a.keyId().length());
    assertNotEquals(a.keyId(), b.keyId());
    assertEquals(a.keyId(), PqcKeys.parsePrivateKeyPem(a.privateKeyPem()).keyId());
  }

  @Test
  void destroyWipesSeed() throws Exception {
    KeyPair k = PqcKeys.generate(Algorithm.ML_KEM_768);
    k.destroy();
    assertTrue(k.isDestroyed());
    assertArrayEquals(new byte[64], k.seed());
  }

  @Test
  void rejectsBadSeed() {
    assertThrows(
        IllegalArgumentException.class, () -> PqcKeys.fromSeed(Algorithm.ML_DSA_65, new byte[31]));
  }

  @Test
  void privateKeyFile(@TempDir Path dir) throws Exception {
    KeyPair k = PqcKeys.generate(Algorithm.ML_DSA_65);
    Path path = dir.resolve("signing.pem");
    PqcKeys.writePrivateKeyFile(path, k);
    assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(path)));
    assertThrows(java.nio.file.FileAlreadyExistsException.class, () -> PqcKeys.writePrivateKeyFile(path, k));
    assertArrayEquals(k.seed(), PqcKeys.readPrivateKeyFile(path).seed());
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
    assertThrows(java.io.IOException.class, () -> PqcKeys.readPrivateKeyFile(path));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode vectors = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    assertEquals(Algorithm.values().length, vectors.size());
    for (JsonNode v : vectors) {
      String name = v.get("algorithm").asText();
      Algorithm alg = null;
      for (Algorithm a : Algorithm.values()) {
        if (a.fipsName.equals(name)) {
          alg = a;
        }
      }
      KeyPair k = PqcKeys.fromSeed(alg, HexFormat.of().parseHex(v.get("seed").asText()));
      assertEquals(v.get("private_key_pem").asText(), k.privateKeyPem(), name);
      assertEquals(v.get("public_key_pem").asText(), k.publicKeyPem(), name);
      assertEquals(v.get("key_id").asText(), k.keyId(), name);
      assertArrayEquals(k.seed(), PqcKeys.parsePrivateKeyPem(v.get("private_key_pem").asText()).seed());
      assertArrayEquals(
          k.publicKey(), PqcKeys.parsePublicKeyPem(v.get("public_key_pem").asText()).publicKey());
      int i = 0;
      for (JsonNode bad : v.get("invalid_private_key_pems")) {
        int at = i++;
        assertThrows(
            GeneralSecurityException.class,
            () -> PqcKeys.parsePrivateKeyPem(bad.asText()),
            name + " invalid private key " + at);
      }
      i = 0;
      for (JsonNode bad : v.get("invalid_public_key_pems")) {
        int at = i++;
        assertThrows(
            GeneralSecurityException.class,
            () -> PqcKeys.parsePublicKeyPem(bad.asText()),
            name + " invalid public key " + at);
      }
    }
  }
}
