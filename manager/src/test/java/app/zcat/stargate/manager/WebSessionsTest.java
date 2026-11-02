// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;

class WebSessionsTest {
    @Test void csrfIsBoundToTheSessionAndLogoutRevokesIt() {
        var sessions = new WebSessions(Clock.systemUTC());
        var first = sessions.create();var second = sessions.create();
        assertNotEquals(first.id(), first.csrf());
        assertTrue(sessions.csrf(first.id(), first.csrf()));
        assertFalse(sessions.csrf(first.id(), second.csrf()));
        assertFalse(sessions.csrf(first.id(), null));
        sessions.remove(first.id());assertNull(sessions.get(first.id()));
        assertFalse(sessions.csrf(first.id(), first.csrf()));
    }
    @Test void sessionExpiresWithoutRenewalByReads() {
        var clock = new MutableClock();var sessions = new WebSessions(clock);var session = sessions.create();
        clock.now = clock.now.plusSeconds(1799);assertNotNull(sessions.get(session.id()));
        clock.now = clock.now.plusSeconds(1);assertNull(sessions.get(session.id()));
        assertFalse(sessions.csrf(session.id(), session.csrf()));
    }
    @Test void htmlEscapesValuesAndRejectsMalformedSessionIdentifiers() {
        assertEquals("&lt;script&gt;&amp;&quot;&#39;", WebUi.escape("<script>&\"'"));
        assertNull(new WebSessions(Clock.systemUTC()).get("a\r\nb"));
    }
    private static class MutableClock extends Clock {
        Instant now = Instant.parse("2026-10-24T12:00:00Z");
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return now; }
    }
}
