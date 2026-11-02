// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PairingTest {
    @TempDir Path directory;
    private static final String ORIGIN = "chrome-extension://" + "a".repeat(32);
    private static final String KEY = "synthetic-manager-key-for-unit-tests-only-000";
    private DeviceCredentials store() throws Exception {
        Path path = directory.resolve("proxy.properties");
        if (!Files.exists(path)) {
            Files.writeString(path, "isolation.key=" + "00".repeat(32) + "\nnym.enabled=true\n");
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
        return new DeviceCredentials(path);
    }
    @Test void sameLabelCreatesDistinctDevicesAndCodesRemainSingleUse() throws Exception {
        var store = store();var pairing = new Pairing(KEY, store, Clock.systemUTC());
        var ticket = pairing.issue("Firefox");assertEquals(43, ticket.code().length());
        assertTrue(store.tokens().isEmpty());
        assertNull(pairing.redeem(ticket.code(), "https://attacker.invalid"));
        var first = pairing.redeem(ticket.code(), ORIGIN);
        var second = pairing.redeem(pairing.issue("Firefox").code(), ORIGIN);
        assertNotEquals(first.profileId(), second.profileId());assertNotEquals(first.password(), second.password());
        assertEquals(first.profileId(), first.username());assertEquals(43, first.password().length());
        assertEquals(first.profileId(), pairing.profile(first.authorization(), ORIGIN));
        assertNull(pairing.redeem(ticket.code(), ORIGIN));
        assertNull(pairing.profile(first.authorization(), "chrome-extension://" + "b".repeat(32)));
        assertNull(pairing.profile(first.authorization() + "x", ORIGIN));
        assertThrows(IllegalArgumentException.class, () -> pairing.issue("<script>"));
        assertEquals(2, store.tokens().size());
        assertTrue(Files.readString(directory.resolve("proxy.properties")).contains("nym.enabled=true"));
    }
    @Test void restartPreservesBothDevicesAndRevokingOneRejectsOnlyItsGrant() throws Exception {
        var first = new Pairing(KEY, store(), Clock.systemUTC());
        var a = first.redeem(first.issue("A").code(), ORIGIN);
        var b = first.redeem(first.issue("B").code(), ORIGIN);
        var restarted = new Pairing(KEY, store(), Clock.systemUTC());
        assertEquals(a.profileId(), restarted.profile(a.authorization(), ORIGIN));
        assertEquals(b.profileId(), restarted.profile(b.authorization(), ORIGIN));
        assertTrue(store().revoke(a.profileId()));assertFalse(store().revoke(a.profileId()));
        assertNull(first.profile(a.authorization(), ORIGIN));assertNull(restarted.profile(a.authorization(), ORIGIN));
        assertEquals(b.profileId(), restarted.profile(b.authorization(), ORIGIN));
        assertNull(new Pairing(KEY + "changed", store(), Clock.systemUTC()).profile(b.authorization(), ORIGIN));
        assertFalse(b.authorization().contains(KEY));assertFalse(b.authorization().contains(b.password()));
        Files.delete(directory.resolve("proxy.properties"));assertNull(restarted.profile(b.authorization(), ORIGIN));
    }
    @Test void freshIsolatedRedemptionPersistsUniquePortsBeforeReconciliation() throws Exception {
        Path path = directory.resolve("proxy.properties");
        Files.writeString(path, "network.mode=container\ni2p.deviceIsolation=true\ni2p.nextPort=14447\n"
                + "i2p.lifecycleDirectory=" + directory.resolve("lifecycle") + "\nnym.enabled=true\n");
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        var devices = new DeviceCredentials(path, directory.resolve("tunnels.conf"));
        var pairing = new Pairing(KEY, devices, Clock.systemUTC());
        // No manager timer or manual reconciliation has run when a browser receives its grant.
        for (int port = 14447; port < 14449; port++) {
            var grant = pairing.redeem(pairing.issue("fresh").code(), ORIGIN);
            var saved = new java.util.Properties();
            try (var reader = Files.newBufferedReader(path)) { saved.load(reader); }
            assertEquals(grant.password(), saved.getProperty("profile." + grant.profileId() + ".token"));
            assertEquals(Integer.toString(port), saved.getProperty("profile." + grant.profileId() + ".i2pPort"));
            assertEquals(Integer.toString(port + 1), saved.getProperty("i2p.nextPort"));
            assertEquals(port, new DeviceCredentials(path, directory.resolve("tunnels.conf")).i2pPort(grant.profileId()));
            assertEquals(grant.profileId(), pairing.profile(grant.authorization(), ORIGIN));
            assertEquals("true", saved.getProperty("nym.enabled"));
        }
        assertEquals(2, devices.tokens().size());
        assertFalse(Files.exists(directory.resolve("tunnels.conf")));
        assertFalse(Files.exists(directory.resolve("lifecycle")));
    }

    @Test void exhaustedIsolatedAllocationRejectsPairingWithoutPublishingCredentials() throws Exception {
        Path path = directory.resolve("proxy.properties");
        Files.writeString(path, "isolation.key=" + "00".repeat(32)
                + "\ni2p.deviceIsolation=true\ni2p.nextPort=65536\ni2p.lifecycleDirectory=" + directory.resolve("lifecycle") + "\n");
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        var devices = new DeviceCredentials(path, directory.resolve("tunnels.conf"));
        devices.reconcileI2p();
        var pairing = new Pairing(KEY, devices, Clock.systemUTC());
        var ticket = pairing.issue("new");
        byte[] before = Files.readAllBytes(path);
        var error = assertThrows(IllegalStateException.class, () -> pairing.redeem(ticket.code(), ORIGIN));
        assertEquals("DEVICE_STORE_UNAVAILABLE", error.getMessage());
        assertArrayEquals(before, Files.readAllBytes(path));
        assertTrue(devices.tokens().isEmpty());
        assertTrue(pairing.invitations().isEmpty());
        assertNull(pairing.redeem(ticket.code(), ORIGIN));
        assertFalse(Files.exists(directory.resolve("tunnels.conf")));
    }

    @Test void sharedModeIgnoresExhaustedCounterAndLaterIsolationStillCannotAllocate() throws Exception {
        var devices = store();
        Path path = directory.resolve("proxy.properties");
        Files.writeString(path, Files.readString(path) + "i2p.deviceIsolation=false\ni2p.nextPort=65536\n");
        devices = new DeviceCredentials(path, directory.resolve("tunnels.conf"));
        var pairing = new Pairing(KEY, devices, Clock.systemUTC());
        var grant = pairing.redeem(pairing.issue("shared").code(), ORIGIN);
        devices.reconcileI2p();
        assertEquals(-1, devices.i2pPort(grant.profileId()));
        assertEquals("NOT_CONFIGURED", devices.i2pStatus(grant.profileId(), null).state());
        assertEquals(grant.profileId(), pairing.profile(grant.authorization(), ORIGIN));
        Files.writeString(path, Files.readString(path).replace("i2p.deviceIsolation=false", "i2p.deviceIsolation=true"));
        assertThrows(IllegalStateException.class, devices::reconcileI2p);
        assertEquals(0, devices.i2pPort(grant.profileId()));
        assertTrue(Files.readString(path).contains("i2p.nextPort=65536"));
        assertFalse(Files.readString(path).contains(".i2pPort="));
    }

    @Test void expiredAndUnknownCodesNeverCreateDevices() throws Exception {
        class Time extends Clock {
            Instant now = Instant.parse("2026-10-24T00:00:00Z");
            @Override public ZoneId getZone() { return ZoneOffset.UTC; }
            @Override public Clock withZone(ZoneId zone) { return this; }
            @Override public Instant instant() { return now; }
        }
        Time time = new Time();var store = store();var pairing = new Pairing(KEY, store, time);
        String code = pairing.issue("device").code();time.now = time.now.plus(Duration.ofMinutes(5));
        assertNull(pairing.redeem(code, ORIGIN));assertNull(pairing.redeem("a".repeat(43), ORIGIN));assertTrue(store.tokens().isEmpty());
    }
    @Test void invitationsExpireCancelAndNeverRevealCodesInTheList() throws Exception {
        class Time extends Clock {
            Instant now = Instant.parse("2026-10-24T00:00:00Z");
            public ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(ZoneId zone) { return this; }
            public Instant instant() { return now; }
        }
        Time time = new Time();var pairing = new Pairing(KEY, store(), time);
        var shortTicket = pairing.issue("short");var longTicket = pairing.issue("long", "24h");
        assertEquals(time.now.plus(Duration.ofMinutes(5)).toString(), shortTicket.expiresAt());
        assertEquals(time.now.plus(Duration.ofHours(24)).toString(), longTicket.expiresAt());
        assertThrows(IllegalArgumentException.class, () -> pairing.issue("bad", "25h"));
        var list = pairing.invitations();assertEquals(2, list.size());
        assertFalse(list.toString().contains(shortTicket.code()));assertFalse(list.toString().contains(longTicket.code()));
        String id = list.stream().filter(i -> i.label().equals("long")).findFirst().orElseThrow().id();
        assertNotEquals(longTicket.code(), id);assertFalse(pairing.cancel("invalid"));
        time.now = time.now.plus(Duration.ofMinutes(5));
        assertNull(pairing.redeem(shortTicket.code(), ORIGIN));assertEquals(1, pairing.invitations().size());
        assertTrue(pairing.cancel(id));assertFalse(pairing.cancel(id));assertNull(pairing.redeem(longTicket.code(), ORIGIN));
        var next = pairing.issue("long", "24h");
        assertNull(new Pairing(KEY, store(), time).redeem(next.code(), ORIGIN));
        time.now = time.now.plus(Duration.ofHours(24));assertNull(pairing.redeem(next.code(), ORIGIN));
    }
    @Test void sameLabelAndExpiryInvitationsCanBeCancelledByTheirIssuedReferences() throws Exception {
        var devices = store();
        var pairing = new Pairing(KEY, devices, Clock.fixed(Instant.parse("2026-10-24T00:00:00Z"), ZoneOffset.UTC));
        var first = pairing.issue("browser");var second = pairing.issue("browser");
        assertEquals(first.label(), second.label());assertEquals(first.expiresAt(), second.expiresAt());
        assertNotEquals(first.code(), second.code());assertNotEquals(first.id(), second.id());
        for (var ticket : java.util.List.of(first, second)) {
            assertTrue(ticket.id().matches("[A-Za-z0-9_-]{43}"));
            assertNotEquals(ticket.code(), ticket.id());
            assertTrue(pairing.invitations().contains(new Pairing.Invitation(ticket.id(), ticket.label(), ticket.expiresAt())));
        }
        assertTrue(pairing.cancel(first.id()));assertFalse(pairing.cancel(first.id()));
        assertEquals(java.util.List.of(new Pairing.Invitation(second.id(), second.label(), second.expiresAt())), pairing.invitations());
        assertNull(pairing.redeem(first.code(), ORIGIN));assertTrue(devices.tokens().isEmpty());
        assertNotNull(pairing.redeem(second.code(), ORIGIN));assertEquals(1, devices.tokens().size());
        assertNull(pairing.redeem(second.code(), ORIGIN));assertTrue(pairing.invitations().isEmpty());
    }
    @Test void cancellationAndRedemptionAreAtomic() throws Exception {
        var pairing = new Pairing(KEY, store(), Clock.systemUTC());
        var ticket = pairing.issue("race", "24h");String id = pairing.invitations().getFirst().id();
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var start = new java.util.concurrent.CountDownLatch(1);
            var cancel = pool.submit(() -> { start.await();return pairing.cancel(id); });
            var redeem = pool.submit(() -> { start.await();return pairing.redeem(ticket.code(), ORIGIN); });
            start.countDown();assertNotEquals(cancel.get(), redeem.get() != null);
            assertNull(pairing.redeem(ticket.code(), ORIGIN));assertTrue(pairing.invitations().isEmpty());
        }
    }
    @Test void pendingCapacityRemainsBoundedAndExpiryFreesSlots() throws Exception {
        class Time extends Clock {
            Instant now = Instant.parse("2026-10-24T00:00:00Z");
            public ZoneId getZone() { return ZoneOffset.UTC; }
            public Clock withZone(ZoneId zone) { return this; }
            public Instant instant() { return now; }
        }
        Time time = new Time();var pairing = new Pairing(KEY, store(), time);
        for (int i = 0; i < 32; i++) pairing.issue("pending");
        assertThrows(IllegalStateException.class, () -> pairing.issue("overflow", "24h"));
        time.now = time.now.plus(Duration.ofMinutes(5));assertEquals(0, pairing.invitations().size());
        assertNotNull(pairing.issue("available", "24h"));
    }
    @Test void pairingAndRestartAccept129Devices() throws Exception {
        var devices = store();var pairing = new Pairing(KEY, devices, Clock.systemUTC());
        for (int i = 0; i < 128; i++) devices.create("device");
        devices.requireCapacity();
        var ticket = pairing.issue("extra");
        var grant = pairing.redeem(ticket.code(), ORIGIN);
        assertNotNull(grant);assertEquals(129, store().tokens().size());
        assertEquals(grant.profileId(), new Pairing(KEY, store(), Clock.systemUTC()).profile(grant.authorization(), ORIGIN));
        assertNull(pairing.redeem(ticket.code(), ORIGIN));
    }

    @Test void fullStorePreservesPreviousSnapshotAndConsumesFailedInvitation() throws Exception {
        var devices = store();Path path = directory.resolve("proxy.properties");
        // Fill a valid Properties snapshot close to the byte bound; serialization drops comments.
        var properties = new java.util.Properties();
        properties.setProperty("isolation.key", "00".repeat(32));
        properties.setProperty("profile.existing.token", "a".repeat(43));
        properties.setProperty("nym.host", "x".repeat(261900));
        try (var writer = Files.newBufferedWriter(path)) { properties.store(writer, "Stargate private configuration"); }
        assertTrue(Files.size(path) <= 262144);
        byte[] before = Files.readAllBytes(path);
        var pairing = new Pairing(KEY, devices, Clock.systemUTC());
        var ticket = pairing.issue("a".repeat(32));
        var error = assertThrows(IllegalStateException.class, () -> pairing.redeem(ticket.code(), ORIGIN));
        assertEquals("DEVICE_STORE_FULL", error.getMessage());
        assertArrayEquals(before, Files.readAllBytes(path));
        assertEquals(1, devices.tokens().size());
        assertNull(pairing.redeem(ticket.code(), ORIGIN));
        assertTrue(pairing.invitations().isEmpty());
    }

    @Test void storeFailureStillConsumesInvitation() throws Exception {
        var pairing = new Pairing(KEY, store(), Clock.systemUTC());var ticket = pairing.issue("device", "24h");
        Files.delete(directory.resolve("proxy.properties"));
        assertThrows(IllegalStateException.class, () -> pairing.redeem(ticket.code(), ORIGIN));
        assertTrue(pairing.invitations().isEmpty());assertNull(pairing.redeem(ticket.code(), ORIGIN));
    }
    @Test void legacyGrantStillWorksUntilExplicitlyRevoked() throws Exception {
        var store = store();String legacyToken = "a".repeat(43);
        Files.writeString(directory.resolve("proxy.properties"), "profile.firefox.token=" + legacyToken + "\nisolation.key=" + "00".repeat(32) + "\n");
        var mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(KEY.getBytes(java.nio.charset.StandardCharsets.US_ASCII), "HmacSHA256"));
        byte[] data = ("stargate-extension-status-v1\0" + ORIGIN + "\0firefox\0" + legacyToken).getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        String grant = "StargateProfile firefox:" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(mac.doFinal(data));
        var pairing = new Pairing(KEY, store, Clock.systemUTC());assertEquals("firefox", pairing.profile(grant, ORIGIN));
        store.revoke("firefox");assertNull(pairing.profile(grant, ORIGIN));assertTrue(store.tokens().isEmpty());
        var next = pairing.redeem(pairing.issue("Firefox").code(), ORIGIN);assertNotNull(next);assertNotEquals("firefox", next.profileId());
    }
    @Test void concurrentRedemptionCannotDuplicateADeviceOrLoseOtherDevices() throws Exception {
        var store = store();var pairing = new Pairing(KEY, store, Clock.systemUTC());String code = pairing.issue("same").code();
        try (var pool = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            var calls = new java.util.ArrayList<java.util.concurrent.Callable<Pairing.Redeemed>>();
            for (int i = 0; i < 12; i++) calls.add(() -> pairing.redeem(code, ORIGIN));
            int issued = 0;for (var result : pool.invokeAll(calls)) if (result.get() != null) issued++;
            assertEquals(1, issued);assertEquals(1, store.tokens().size());
            calls.clear();for (int i = 0; i < 12; i++) { String unique = pairing.issue("same").code();calls.add(() -> pairing.redeem(unique, ORIGIN)); }
            for (var result : pool.invokeAll(calls)) assertNotNull(result.get());assertEquals(13, store.tokens().size());
        }
    }
    @Test void storeRejectsInsecureMissingAndSymlinkedFiles() throws Exception {
        var store = store();var path = directory.resolve("proxy.properties");
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(IllegalStateException.class, () -> store.create("device"));
        Files.delete(path);Files.createSymbolicLink(path, directory.resolve("missing"));
        assertThrows(IllegalStateException.class, store::tokens);
    }
}
