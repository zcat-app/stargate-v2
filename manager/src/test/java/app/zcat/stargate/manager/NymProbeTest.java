package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.net.*;
import org.junit.jupiter.api.Test;

class NymProbeTest {
    @Test void greetingNeverClaimsNetworkReadinessAndPastTrafficStaysHistorical() throws Exception {
        try (var server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            var thread = Thread.ofVirtual().start(() -> {
                try (var client = server.accept()) { client.getInputStream().readNBytes(3);client.getOutputStream().write(new byte[]{5,0}); }
                catch (Exception e) { throw new RuntimeException(e); }
            });
            var counters = new TrafficStats.Counters(42, "", "", 1, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1);
            var observed = NymProbe.sample(new InetSocketAddress("127.0.0.1", server.getLocalPort()), new TrafficStats.Observation("CURRENT", counters));
            assertEquals("UNKNOWN", observed.readiness());assertEquals("RESPONDING", observed.socks().state());
            assertEquals("OBSERVED_THIS_PROCESS", observed.destinationAccess());thread.join();
        }
        assertEquals("DISABLED", NymProbe.sample(null, new TrafficStats.Observation("CURRENT", null)).readiness());
    }
}
