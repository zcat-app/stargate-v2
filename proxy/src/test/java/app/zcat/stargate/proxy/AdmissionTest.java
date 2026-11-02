// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AdmissionTest {
    @TempDir Path directory;

    @Test void countsPreAuthSocketsAndEachRefusalOnceAcrossPaths() throws Exception {
        var admission = new Admission(2);
        assertFalse(admission.accept());
        assertFalse(admission.accept());
        assertTrue(admission.accept()); // A plaintext refusal follows the shared decision.
        assertTrue(admission.accept()); // A TLS refusal follows the same decision.
        assertEquals(4, admission.occupancy.get());
        assertEquals(2, admission.refusals.get());
        admission.release();admission.release();admission.release();
        assertEquals(1, admission.occupancy.get());
        assertFalse(admission.accept());
        assertEquals(2, admission.refusals.get());
        Path file = directory.resolve("metrics.json");
        try (var metrics = new AggregateMetrics(file, admission)) {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            while (!Files.exists(file) && System.nanoTime() < deadline) Thread.sleep(10);
            String json = Files.readString(file);
            assertTrue(json.contains("\"globalConnectionLimit\":2"));
            assertTrue(json.contains("\"acceptedConnections\":2"));
            assertTrue(json.contains("\"connectionLimitRefusals\":2"));
        }
    }
    @Test void bothListenerPathsRecordOneRefusalWithoutClosingAdmittedSocket() throws Exception {
        Path file = directory.resolve("server.json");
        var loopback = new java.net.InetSocketAddress("127.0.0.1", 0);
        var tor = new java.net.InetSocketAddress("127.0.0.1", 1);
        var config = new ProxyConfig(loopback, tor, java.util.Map.of(), 1, 1000, 1000, false, file);
        try (var server = new ProxyServer(config)) {
            var admitted = new io.netty.channel.embedded.EmbeddedChannel();
            server.initializeConnection(admitted, false);
            var plaintext = new io.netty.channel.embedded.EmbeddedChannel();
            server.initializeConnection(plaintext, false);
            plaintext.pipeline().fireChannelActive();
            plaintext.runPendingTasks();
            var tls = new io.netty.channel.embedded.EmbeddedChannel();
            server.initializeConnection(tls, true);
            tls.runPendingTasks();
            assertTrue(admitted.isOpen());
            assertFalse(plaintext.isOpen());
            assertFalse(tls.isOpen());
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5);
            String json = "";
            while (System.nanoTime() < deadline) {
                if (Files.exists(file)) json = Files.readString(file);
                if (json.contains("\"connectionLimitRefusals\":2")) break;
                Thread.sleep(10);
            }
            assertTrue(json.contains("\"acceptedConnections\":1"), json);
            assertTrue(json.contains("\"connectionLimitRefusals\":2"), json);
            admitted.close();
            admitted.finishAndReleaseAll();plaintext.finishAndReleaseAll();tls.finishAndReleaseAll();
        }
    }

}
