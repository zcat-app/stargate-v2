// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TrafficStatsTest {
    @TempDir Path directory;
    @Test void previousPidAndStaleSnapshotsCannotBecomeCurrentAfterRestart() throws Exception {
        Path file = directory.resolve("traffic.json");
        write(file, 42, Instant.now());
        var current = process(42);
        assertEquals("CURRENT", TrafficStats.read(file, current).state());
        assertEquals("STALE", TrafficStats.read(file, process(43)).state());
        write(file, 42, Instant.now().minusSeconds(15));
        assertEquals("STALE", TrafficStats.read(file, current).state());
        var stopped = new ProxyControl.Unit("OBSERVED", "loaded", "inactive", "dead", 0L, "", "success", 0, "TEST");
        assertEquals("LAST_PROCESS", TrafficStats.read(file, stopped).state());
    }
    @Test void malformedOrDestinationBearingSnapshotsAreRejected() throws Exception {
        Path file = directory.resolve("traffic.json");write(file, 42, Instant.now());
        Files.writeString(file, Files.readString(file).replace("}", ",\"destination\":\"forbidden.example\"}"));
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).state());
        Files.writeString(file, "x".repeat(4097));assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).state());
    }
    @Test void admissionRequiresCompleteFreshCurrentMetrics() throws Exception {
        Path file = directory.resolve("traffic.json");
        write(file, 42, Instant.now());
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).admission().state());
        String base = Files.readString(file);
        Files.writeString(file, base.replace("}", ",\"globalConnectionLimit\":2,\"acceptedConnections\":1,\"connectionLimitRefusals\":7}"));
        var observed = TrafficStats.read(file, process(42));
        assertEquals(new TrafficStats.Admission("CURRENT", 2L, 1L, 7L), observed.admission());
        String html = WebUi.admission(observed.admission());
        assertTrue(html.contains("Past refusals do not mean the limit is currently full"));
        assertTrue(html.contains("<dd>1</dd>"));
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(43)).admission().state());
        var stopped = new ProxyControl.Unit("OBSERVED", "loaded", "inactive", "dead", 0L, "", "success", 0, "TEST");
        assertEquals("UNAVAILABLE", TrafficStats.read(file, stopped).admission().state());
        Files.writeString(file, Files.readString(file).replace("\"acceptedConnections\":1", "\"acceptedConnections\":-1"));
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).admission().state());
        assertTrue(WebUi.admission(TrafficStats.read(file, process(42)).admission()).contains("Unavailable"));
        Files.writeString(file, base.replace("}", ",\"globalConnectionLimit\":2,\"acceptedConnections\":0}"));
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).admission().state());
        write(file, 42, Instant.now().minusSeconds(15));
        Files.writeString(file, Files.readString(file).replace("}", ",\"globalConnectionLimit\":2,\"acceptedConnections\":0,\"connectionLimitRefusals\":0}"));
        assertEquals("UNAVAILABLE", TrafficStats.read(file, process(42)).admission().state());
    }
    private static ProxyControl.Unit process(long pid) { return new ProxyControl.Unit("OBSERVED", "loaded", "active", "running", pid, "", "success", 0, "TEST"); }
    private static void write(Path file, long pid, Instant time) throws Exception {
        Files.writeString(file, "{\"pid\":" + pid + ",\"startedAt\":\"" + time + "\",\"observedAt\":\"" + time
                + "\",\"connections\":1,\"connected\":1,\"failures\":0,\"uploaded\":123,\"downloaded\":456,\"active\":0}");
    }
}
