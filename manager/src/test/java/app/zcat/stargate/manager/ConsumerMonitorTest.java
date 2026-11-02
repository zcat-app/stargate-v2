// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import app.zcat.stargate.monitor.MonitorPublicationFixture;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ConsumerMonitorTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:10Z");
    private static final String TIME = "2026-01-01T00:00:05Z";
    private static final ObjectMapper JSON = new ObjectMapper();
    private ObjectNode snapshot(String outcome, String acceptance, Boolean blocked) {
        var node = JSON.createObjectNode().put("schema_version", 1).put("published_at", TIME)
                .put("attempt_at", TIME).put("outcome", outcome).put("local_acceptance", acceptance);
        if (blocked == null) node.putNull("future_collection_blocked"); else node.put("future_collection_blocked", blocked);
        return node;
    }
    private ReleaseMonitor.ConsumerObservation read(String data, long age) throws Exception {
        Path file = directory.resolve("consumer.json"); Files.writeString(file, data);
        return ReleaseMonitor.readConsumer(file, age, NOW);
    }
    private ReleaseMonitor.ConsumerObservation read(ObjectNode node) throws Exception { return read(node.toString(), 5); }
    @Test void validatesEveryOutcomeAndAcceptanceBlockedCombination() throws Exception {
        for (String outcome : new String[]{"quiet", "locally_accepted", "collection_unknown", "fresh_observation_required",
                "blocked_pending", "blocked_uncertain", "busy", "unknown", "incomplete", "private-value"}) {
            for (String acceptance : new String[]{"not_attempted", "accepted", "unknown", "private-value"}) {
                for (Boolean blocked : new Boolean[]{false, true, null}) {
                    boolean valid = switch (outcome) {
                        case "quiet" -> acceptance.equals("not_attempted") && Boolean.FALSE.equals(blocked);
                        case "locally_accepted" -> acceptance.equals("accepted") && Boolean.FALSE.equals(blocked);
                        case "collection_unknown", "fresh_observation_required" -> !acceptance.equals("unknown")
                                && !acceptance.equals("private-value") && Boolean.FALSE.equals(blocked);
                        case "blocked_pending", "blocked_uncertain" -> acceptance.equals("unknown") && Boolean.TRUE.equals(blocked);
                        case "busy" -> acceptance.equals("unknown") && blocked == null;
                        default -> false;
                    };
                    var result = read(snapshot(outcome, acceptance, blocked));
                    assertEquals(valid ? outcome : "unknown", result.outcome(), outcome + "/" + acceptance + "/" + blocked);
                    assertEquals(valid ? TIME : null, result.attemptAt());
                    assertEquals(valid ? acceptance : "unknown", result.localAcceptance());
                    assertEquals(valid ? blocked : null, result.futureCollectionBlocked());
                }
            }
        }
    }
    @Test void rejectsStaleFutureMissingMalformedAndPrivateData() throws Exception {
        var valid = snapshot("quiet", "not_attempted", false);
        assertEquals("quiet", read(valid).outcome());
        assertEquals("unknown", read(valid.toString(), 4).outcome());
        assertEquals("unknown", read(valid.toString(), 0).outcome());
        assertEquals("unknown", read(valid.deepCopy().put("published_at", "2026-01-01T00:00:11Z")).outcome());
        assertEquals("unknown", read(valid.deepCopy().put("attempt_at", "2026-01-01T00:00:06Z")).outcome());
        assertEquals("unknown", read(valid.deepCopy().put("published_at", "2026-01-01T00:00:09Z").put("attempt_at", "2026-01-01T00:00:04Z")).outcome());
        for (String key : new String[]{"schema_version", "published_at", "attempt_at", "outcome", "local_acceptance", "future_collection_blocked"}) {
            var absent = valid.deepCopy(); absent.remove(key); assertEquals("unknown", read(absent).outcome());
            assertEquals("unknown", read(valid.deepCopy().putNull(key)).outcome());
            assertEquals("unknown", read(valid.deepCopy().put(key, 2)).outcome());
        }
        for (String invalid : new String[]{"", "[]", "{}", "x".repeat(513), valid + "{}", valid + " trailing",
                valid.toString().replace("{", "{\"outcome\":\"quiet\","),
                valid.deepCopy().put("schema_version", true).toString(), valid.deepCopy().put("schema_version", 1.0).toString(),
                valid.deepCopy().put("attempt_at", "2026-01-01T00:00:05.000Z").toString(),
                valid.deepCopy().put("published_at", "2026-02-30T00:00:05Z").toString(),
                valid.deepCopy().put("secret", "private-contact-event-path-report-message-token").toString()}) {
            var result = read(invalid, 60);
            assertEquals("unknown", result.outcome()); assertNull(result.publishedAt());
            assertFalse(WebUi.consumerMonitor(result).contains("private-contact"));
        }
        Path missing = directory.resolve("absent");
        assertEquals("unknown", ReleaseMonitor.readConsumer(missing, 60, NOW).outcome());
        Files.createSymbolicLink(missing, directory.resolve("consumer.json"));
        assertEquals("unknown", ReleaseMonitor.readConsumer(missing, 60, NOW).outcome());
        assertEquals("unknown", ReleaseMonitor.readConsumer(directory, 60, NOW).outcome());
    }
    @Test void actualJavaPublicationAndRecordLockFeedTheReadOnlyReader() throws Exception {
        var publication = new MonitorPublicationFixture(directory);
        Path file = publication.consumerSnapshot();
        Object inode = null;
        for (boolean changed : new boolean[]{false, true}) {
            assertEquals(0, publication.run(changed, () -> {}));
            if (inode != null) assertEquals(inode, Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes.class).fileKey());
            inode = Files.readAttributes(file, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
            var result = ReleaseMonitor.readConsumer(file, 60, Instant.now());
            assertEquals(changed ? "locally_accepted" : "quiet", result.outcome());
            assertEquals(changed ? "accepted" : "not_attempted", result.localAcceptance());
            assertEquals(Boolean.FALSE, result.futureCollectionBlocked());
            assertEquals(changed ? 1 : 0, publication.sends());
            assertFalse(Files.readString(file).contains(MonitorPublicationFixture.PRIVATE_TOKEN));
            assertFalse(Files.readString(file).contains(publication.privateIdentity()));
        }
        try (var locked = SnapshotLockProcess.hold(file)) {
            assertEquals("unknown", ReleaseMonitor.readConsumer(file, 60, Instant.now()).outcome());
        }
        assertEquals("locally_accepted", ReleaseMonitor.readConsumer(file, 60, Instant.now()).outcome());
    }
    @Test void anonymousPageHidesStatusAndAllDisplayValuesAreEscaped() {
        assertFalse(WebUi.page(null, null, null, null).contains("Consumer outcome snapshot"));
        String attack = "<script>private&\"'";
        String html = WebUi.consumerMonitor(new ReleaseMonitor.ConsumerObservation(attack, attack, null, attack, attack, 60));
        assertFalse(html.contains(attack)); assertFalse(html.contains("<script>"));
        assertTrue(html.contains("&lt;script&gt;private&amp;&quot;&#39;"));
        assertTrue(html.contains("Local acceptance does not prove phone delivery"));
        assertTrue(html.contains("not necessarily the latest invocation"));
    }
    @Test void authenticatedPageReadsConfiguredOutcomeWithoutPublishingPrivateInputs() throws Exception {
        var node = snapshot("locally_accepted", "accepted", false);
        String now = java.time.format.DateTimeFormatter.ISO_INSTANT.format(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
        Files.writeString(directory.resolve("consumer.json"), node.put("attempt_at", now).put("published_at", now).toString());
        var manager = manager();
        try {
            assertFalse(WebUi.page(manager, null, null, null).contains("consumer-monitor-state"));
            String html = WebUi.page(manager, manager.sessions().create(), null, null);
            assertTrue(html.contains("id=\"consumer-monitor-state\">locally_accepted"));
            assertFalse(html.contains(directory.toString())); assertFalse(html.contains("b".repeat(43))); assertFalse(html.contains("<script"));
            assertFalse(html.contains("Release observation snapshot"));
            assertEquals("locally_accepted", manager.consumerMonitor().outcome());
        } finally { manager.closeI2pConfiguration(); }
    }
    private ManagerService manager() throws Exception {
        Path proxy = directory.resolve("proxy.properties");
        privateFile(proxy, "network.mode=container\nisolation.key=" + "00".repeat(32) + "\n");
        Path config = directory.resolve("manager.properties");
        privateFile(config, "consumer.snapshot=" + directory.resolve("consumer.json") + "\nconsumer.max-age-seconds=60\nmanager.token=" + "b".repeat(43) + "\nproxy.config=" + proxy
                + "\nproxy.control.socket=" + directory.resolve("unused.sock")
                + "\ntor.cookie=" + directory.resolve("cookie") + "\ntor.control.port=9051\n");
        // Render the configured consumer outcome with synthetic observations; no sockets or process controls.
        return new ManagerService(config.toString(), "0.0.0.0", 9080) {
            @Override public Status status() {
                return new Status("synthetic", "SUPERVISOR", null,
                        new ProxyControl.Unit("synthetic", "loaded", "inactive", "dead", 0L, null, null, null, null),
                        new ProxyObservation("REFUSED", "synthetic", false),
                        new TorProbe.Observation(TorProbe.Health.UNAVAILABLE, "synthetic", null, null, null, null, null, null, null, null),
                        new I2pProbe.Observation("UNAVAILABLE", "synthetic", null, null, null, null, null, null, null, "UNKNOWN"),
                        new NymProbe.Observation("DISABLED", null, "UNKNOWN"), null);
            }
            @Override public String i2pLifecycleObservation() { return "synthetic"; }
        };
    }

    private static void privateFile(Path path, String content) throws Exception {
        Files.writeString(path, content);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
}
