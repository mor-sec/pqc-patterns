package io.github.morsec.pqcpatterns.sess01;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.morsec.pqcpatterns.sess01.Sessions.InvalidSessionException;
import io.github.morsec.pqcpatterns.sess01.Sessions.Manager;
import io.github.morsec.pqcpatterns.sess01.Sessions.MemoryStore;
import io.github.morsec.pqcpatterns.sess01.Sessions.Session;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;

class SessionsTest {
  private static final Duration MIN = Duration.ofMinutes(1);

  /** A clock the test moves by hand. */
  private static final class TestClock extends Clock {
    Instant now = Instant.parse("2026-10-23T09:00:00Z");

    void advance(Duration d) {
      now = now.plus(d);
    }

    @Override
    public Instant instant() {
      return now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }
  }

  private final TestClock clock = new TestClock();
  private final MemoryStore store = new MemoryStore();
  private final Manager m =
      new Manager(store, Sessions.DEFAULT_IDLE_TIMEOUT, Sessions.DEFAULT_ABSOLUTE_TIMEOUT, clock);

  @Test
  void createAndValidate() throws Exception {
    String tok = m.create("user-42");
    assertTrue(tok.startsWith(Sessions.PREFIX));
    assertEquals(Sessions.PREFIX.length() + 43, tok.length());
    assertEquals("user-42", m.validate(tok).userId());
  }

  @Test
  void storesOnlyTheHash() {
    String tok = m.create("u");
    String enc = tok.substring(Sessions.PREFIX.length());
    for (String id : store.ids()) {
      assertEquals(64, id.length());
      assertFalse(id.contains(enc) || enc.contains(id));
    }
  }

  @Test
  void idleTimeout() throws Exception {
    String tok = m.create("u");
    clock.advance(MIN.multipliedBy(20));
    m.validate(tok);
    clock.advance(MIN.multipliedBy(20));
    m.validate(tok);
    clock.advance(Sessions.DEFAULT_IDLE_TIMEOUT);
    assertThrows(InvalidSessionException.class, () -> m.validate(tok));
    assertTrue(store.ids().isEmpty(), "expired session not deleted");
  }

  @Test
  void absoluteTimeout() throws Exception {
    String tok = m.create("u");
    Duration elapsed = Duration.ZERO;
    Duration step = MIN.multipliedBy(20);
    while (elapsed.compareTo(Sessions.DEFAULT_ABSOLUTE_TIMEOUT.minus(step)) < 0) {
      clock.advance(step);
      elapsed = elapsed.plus(step);
      m.validate(tok);
    }
    clock.advance(step);
    assertThrows(InvalidSessionException.class, () -> m.validate(tok));
  }

  @Test
  void rotate() throws Exception {
    Instant start = clock.now;
    String old = m.create("u");
    clock.advance(MIN.multipliedBy(20));
    String fresh = m.rotate(old);
    assertThrows(InvalidSessionException.class, () -> m.validate(old));
    Session s = m.validate(fresh);
    assertEquals("u", s.userId());
    assertEquals(start, s.created(), "rotation reset the absolute timeout");
    assertThrows(InvalidSessionException.class, () -> m.rotate(old));
  }

  @Test
  void revoke() {
    String tok = m.create("u");
    m.revoke(tok);
    assertThrows(InvalidSessionException.class, () -> m.validate(tok));
    m.revoke("garbage");
    m.revoke(null);
  }

  @Test
  void rejectsUnknownToken() {
    Manager other = new Manager(new MemoryStore());
    String tok = m.create("u");
    assertThrows(InvalidSessionException.class, () -> other.validate(tok));
  }

  @Test
  void tokensAreUnique() {
    Set<String> seen = new HashSet<>();
    for (int i = 0; i < 1000; i++) {
      assertTrue(seen.add(m.create("u")), "token reused");
    }
  }

  @Test
  void readsCookieHeader() {
    assertEquals(
        Optional.of("sess_abc"), Sessions.fromCookieHeader("theme=dark; __Host-session=sess_abc; x=y"));
    assertEquals(Optional.empty(), Sessions.fromCookieHeader("session=sess_abc"));
  }

  @Test
  void crossLanguageVector() throws Exception {
    JsonNode v = new ObjectMapper().readTree(Path.of("../testdata/vector.json").toFile());
    String token = v.get("token").asText();
    assertEquals(v.get("session_id").asText(), Sessions.sessionId(token));
    for (JsonNode bad : v.get("invalid_tokens")) {
      assertThrows(
          InvalidSessionException.class, () -> Sessions.sessionId(bad.asText()), bad.asText());
    }
    assertEquals(v.get("set_cookie").asText(), Sessions.setCookie(token));
    assertEquals(v.get("clear_cookie").asText(), Sessions.clearCookie());
  }
}
