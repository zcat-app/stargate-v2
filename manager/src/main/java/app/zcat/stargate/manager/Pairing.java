// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Single-use approval codes; purpose-separated read-only grants survive manager restarts. */
final class Pairing {
    record Ticket(String code, String label, String expiresAt, String id) {}
    record Redeemed(String authorization, String profileId, String username, String password) {}
    record Invitation(String id, String label, String expiresAt) {}
    private record Pending(String id, String label, Instant expires) {}
    private final Map<String, Pending> pending = new HashMap<>();
    private final DeviceCredentials devices;
    private final String key;
    private final Clock clock;

    Pairing(String key, DeviceCredentials devices, Clock clock) { this.key = key;this.devices = devices;this.clock = clock; }

    synchronized Ticket issue(String label) { return issue(label, null); }

    synchronized Ticket issue(String label, String lifetime) {
        Duration duration = switch (lifetime == null ? "5m" : lifetime) {
            case "5m" -> Duration.ofMinutes(5);
            case "24h" -> Duration.ofHours(24);
            default -> throw new IllegalArgumentException("INVALID_INVITATION_LIFETIME");
        };
        DeviceCredentials.validateLabel(label);
        pending.values().removeIf(value -> !value.expires.isAfter(clock.instant()));
        if (pending.size() >= 32) throw new IllegalStateException("TOO_MANY_PENDING_CODES");
        String code = secret(), id = secret();
        Instant expires = clock.instant().plus(duration);pending.put(code, new Pending(id, label, expires));
        return new Ticket(code, label, expires.toString(), id);
    }

    synchronized java.util.List<Invitation> invitations() {
        pending.values().removeIf(value -> !value.expires.isAfter(clock.instant()));
        return pending.values().stream().map(value -> new Invitation(value.id, value.label, value.expires.toString()))
                .sorted(java.util.Comparator.comparing(Invitation::expiresAt).thenComparing(Invitation::id)).toList();
    }

    synchronized boolean cancel(String id) {
        if (id == null || !id.matches("[A-Za-z0-9_-]{43}")) return false;
        pending.values().removeIf(value -> !value.expires.isAfter(clock.instant()));
        return pending.values().removeIf(value -> value.id.equals(id));
    }

    private static String secret() {
        byte[] random = new byte[32];new SecureRandom().nextBytes(random);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    synchronized Redeemed redeem(String code, String origin) {
        if (!extensionOrigin(origin) || code == null || !code.matches("[A-Za-z0-9_-]{43}")) return null;
        Pending approval = pending.remove(code);
        if (approval == null || !approval.expires.isAfter(clock.instant())) return null;
        var device = devices.create(approval.label);
        return new Redeemed("StargateProfile " + device.id() + ":" + signature(device.id(), origin, device.token()), device.id(),
                device.id(), device.token());
    }

    String profile(String authorization, String origin) {
        if (!extensionOrigin(origin) || authorization == null || authorization.length() > 256 || !authorization.startsWith("StargateProfile ")) return null;
        String[] parts = authorization.substring(16).split(":", -1);
        if (parts.length != 2) return null;
        String token;
        try { token = devices.tokens().get(parts[0]); } catch (IllegalStateException e) { return null; }
        if (token == null) return null;
        return MessageDigest.isEqual(parts[1].getBytes(StandardCharsets.US_ASCII), signature(parts[0], origin, token).getBytes(StandardCharsets.US_ASCII)) ? parts[0] : null;
    }

    static boolean extensionOrigin(String origin) {
        return origin != null && (origin.matches("chrome-extension://[a-p]{32}")
                || origin.matches("moz-extension://[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    private String signature(String profileId, String origin, String token) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            byte[] message = ("stargate-extension-status-v1\0" + origin + "\0" + profileId + "\0" + token).getBytes(StandardCharsets.US_ASCII);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(message));
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException("PAIRING_CRYPTO_UNAVAILABLE", e); }
    }
}
