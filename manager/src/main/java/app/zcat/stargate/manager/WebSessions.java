// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/** Owner sessions stay in memory, expire after 30 minutes and carry a separate CSRF secret. */
final class WebSessions {
    record Session(String id, String csrf, Instant expires) {}
    private final Map<String, Session> sessions = new HashMap<>();
    private final Clock clock;
    WebSessions(Clock clock) { this.clock = clock; }
    synchronized Session create() {
        sessions.values().removeIf(value -> !value.expires.isAfter(clock.instant()));
        if (sessions.size() >= 64) throw new IllegalStateException("SESSION_LIMIT");
        Session value = new Session(secret(), secret(), clock.instant().plusSeconds(1800));sessions.put(value.id, value);return value;
    }
    synchronized Session get(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{43}")) return null;
        Session value = sessions.get(id);
        if (value != null && !value.expires.isAfter(clock.instant())) { sessions.remove(id);return null; }
        return value;
    }
    synchronized void remove(String id) { if (id != null) sessions.remove(id); }
    boolean csrf(String id, String supplied) {
        Session value = get(id);
        return value != null && supplied != null && supplied.length() == 43
                && MessageDigest.isEqual(value.csrf.getBytes(java.nio.charset.StandardCharsets.US_ASCII), supplied.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    }
    private static String secret() {
        byte[] value = new byte[32];new SecureRandom().nextBytes(value);return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }
}
