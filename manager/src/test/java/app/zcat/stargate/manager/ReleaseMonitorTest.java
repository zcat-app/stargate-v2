// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import app.zcat.stargate.monitor.MonitorPublicationFixture;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ReleaseMonitorTest {
    @TempDir Path directory;
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:10Z");
    private String snapshot(String latest, String attempt, String published) {
        return "{\"schema_version\":1,\"latest\":\"" + latest + "\",\"attempt_at\":" + attempt
                + ",\"published_at\":\"" + published + "\"}";
    }
    private ReleaseMonitor.Observation read(String text, long age) throws Exception {
        Path file = directory.resolve("snapshot.json"); Files.writeString(file, text);
        return ReleaseMonitor.read(file, age, NOW);
    }
    @Test void acceptsOnlyFreshValidSnapshots() throws Exception {
        String time = "2026-01-01T00:00:05Z";
        var observed = read(snapshot("observed", "\"" + time + "\"", time), 5);
        assertEquals("observed", observed.latest()); assertEquals(time, observed.attemptAt());
        assertEquals("pending", read(snapshot("pending", "\"" + time + "\"", time), 5).latest());
        assertEquals("unknown", read(snapshot("observed", "\"" + time + "\"", time), 4).latest());
        assertEquals("unknown", read(snapshot("pending", "\"2026-01-01T00:00:01Z\"", "2026-01-01T00:00:09Z"), 5).latest());
        assertNull(read(snapshot("unknown", "null", "2026-01-01T00:00:01Z"), 5).publishedAt());
        assertEquals("unknown", read(snapshot("pending", "\"2026-01-01T00:00:11Z\"", "2026-01-01T00:00:11Z"), 60).latest());
        assertEquals("unknown", read(snapshot("observed", "\"2026-01-01T00:00:06Z\"", time), 60).latest());
        assertEquals("unknown", read(snapshot("observed", "null", time), 60).latest());
        assertEquals("unknown", read(snapshot("observed", "\"" + time + "\"", time) + "{}", 60).latest());
        assertEquals("unknown", read("{\"schema_version\":1,\"schema_version\":1}", 60).latest());
        assertEquals("unknown", read("x".repeat(513), 60).latest());
        String secret = "b".repeat(32);
        var privateState = read("{\"schema_version\":1,\"latest_attempt\":{\"token\":\"" + secret + "\"},\"last_success\":null}", 60);
        assertEquals("unknown", privateState.latest()); assertFalse(WebUi.releaseMonitor(privateState).contains(secret));
        Path link = directory.resolve("link"); Files.createSymbolicLink(link, directory.resolve("snapshot.json"));
        assertEquals("unknown", ReleaseMonitor.read(link, 60, NOW).latest());
    }
    @Test void concurrentReadersDoNotReleaseEachOthersProcessLocks() throws Exception {
        Path file = directory.resolve("concurrent.json");
        String time = "2026-01-01T00:00:05Z";
        Files.writeString(file, snapshot("observed", "\"" + time + "\"", time));
        var firstLocked = new java.util.concurrent.CountDownLatch(1);
        var releaseFirst = new java.util.concurrent.CountDownLatch(1);
        var secondStarted = new java.util.concurrent.CountDownLatch(1);
        var secondLocked = new java.util.concurrent.CountDownLatch(1);
        var releaseSecond = new java.util.concurrent.CountDownLatch(1);
        var pool = java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            var first = pool.submit(() -> ReleaseMonitor.read(file, 60, NOW, () -> awaitLatch(firstLocked, releaseFirst)));
            assertTrue(firstLocked.await(5, java.util.concurrent.TimeUnit.SECONDS));
            var second = pool.submit(() -> { secondStarted.countDown(); return ReleaseMonitor.read(file, 60, NOW, () -> awaitLatch(secondLocked, releaseSecond)); });
            assertTrue(secondStarted.await(5, java.util.concurrent.TimeUnit.SECONDS));
            assertFalse(secondLocked.await(200, java.util.concurrent.TimeUnit.MILLISECONDS));
            assertEquals(3, writerLockResult(file));
            releaseFirst.countDown();
            assertTrue(secondLocked.await(5, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals("observed", first.get(5, java.util.concurrent.TimeUnit.SECONDS).latest());
            // Closing the first reader must not release the second reader's lock.
            assertEquals(3, writerLockResult(file));
            releaseSecond.countDown();
            assertEquals("observed", second.get(5, java.util.concurrent.TimeUnit.SECONDS).latest());
            assertEquals(0, writerLockResult(file));
        } finally {
            releaseFirst.countDown(); releaseSecond.countDown(); pool.shutdownNow();
        }
    }
    private static void awaitLatch(java.util.concurrent.CountDownLatch acquired, java.util.concurrent.CountDownLatch release) {
        acquired.countDown();
        try { if (!release.await(5, java.util.concurrent.TimeUnit.SECONDS)) throw new IllegalStateException("timed out"); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new IllegalStateException(e); }
    }
    private static int writerLockResult(Path file) throws Exception {
        return SnapshotLockProcess.run("probe", file);
    }
    @Test void actualRecorderAndPublisherFeedTheReaderWithoutTokenExposure() throws Exception {
        var publication = new MonitorPublicationFixture(directory);
        assertEquals(0, publication.run(false, () -> {}));
        assertEquals(0, publication.sends());
        assertTrue(Files.readString(publication.recordedReport()).contains(MonitorPublicationFixture.PRIVATE_TOKEN));
        Path snapshot = publication.snapshot();
        String published = Files.readString(snapshot);
        assertFalse(published.contains(MonitorPublicationFixture.PRIVATE_TOKEN));
        assertFalse(published.contains(publication.privateIdentity()));
        var result = ReleaseMonitor.read(snapshot, 60, Instant.now());
        assertEquals("observed", result.latest());
        String html = WebUi.releaseMonitor(result);
        assertTrue(html.contains("observed"));
        assertFalse(html.contains(MonitorPublicationFixture.PRIVATE_TOKEN));
        assertFalse(html.contains(publication.privateIdentity()));
        assertFalse(html.contains(directory.toString()));
        assertFalse(WebUi.page(null, null, null, null).contains("Release observation snapshot"));

        // A second JVM holds an exclusive POSIX record lock while the manager tries a shared lock.
        try (var locked = SnapshotLockProcess.hold(snapshot)) {
            assertEquals("unknown", ReleaseMonitor.read(snapshot, 60, Instant.now()).latest());
        }
        assertEquals("observed", ReleaseMonitor.read(snapshot, 60, Instant.now()).latest());

        // A bind mount retains the inode: an existing descriptor sees the next pending publication.
        Object before = Files.readAttributes(snapshot, java.nio.file.attribute.BasicFileAttributes.class).fileKey();
        try (var held = java.nio.channels.FileChannel.open(snapshot)) {
            assertEquals(0, publication.run(false, () -> {
                assertEquals(before, Files.readAttributes(snapshot, java.nio.file.attribute.BasicFileAttributes.class).fileKey());
                var bytes = java.nio.ByteBuffer.allocate(512); held.read(bytes); bytes.flip();
                assertTrue(java.nio.charset.StandardCharsets.UTF_8.decode(bytes).toString().contains("pending"));
                assertEquals("pending", ReleaseMonitor.read(snapshot, 60, Instant.now()).latest());
            }));
            assertEquals(before, Files.readAttributes(snapshot, java.nio.file.attribute.BasicFileAttributes.class).fileKey());
            assertEquals("observed", ReleaseMonitor.read(snapshot, 60, Instant.now()).latest());
        }
        assertEquals(0, SnapshotLockProcess.run("tear", snapshot));
        assertEquals("unknown", ReleaseMonitor.read(snapshot, 60, Instant.now()).latest());
    }
}
