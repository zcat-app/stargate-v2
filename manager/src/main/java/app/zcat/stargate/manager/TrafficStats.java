// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;

final class TrafficStats {
    record Counters(long pid, String startedAt, String observedAt, long connections, long connected,
                    long failures, long uploaded, long downloaded, long active, long i2pConnections, long i2pConnected, long i2pResponses, long nymConnections, long nymConnected, long nymResponses) {}
    record Admission(String state, Long limit, Long occupancy, Long refusals) {
        static Admission unavailable() { return new Admission("UNAVAILABLE", null, null, null); }
    }
    record Observation(String state, Counters counters, Admission admission) {
        Observation(String state, Counters counters) { this(state, counters, Admission.unavailable()); }
    }
    static Observation read(Path file, ProxyControl.Unit process) {
        if (file == null) return new Observation("NOT_CONFIGURED", null);
        try {
            byte[] bytes;
            try (var input = Files.newInputStream(file)) { bytes = input.readNBytes(4097); }
            if (bytes.length > 4096) throw new IllegalArgumentException();
            var mapper = new ObjectMapper();
            var root = mapper.readTree(bytes);
            if (!(root instanceof com.fasterxml.jackson.databind.node.ObjectNode object)) throw new IllegalArgumentException();
            var limit = object.remove("globalConnectionLimit");
            var occupancy = object.remove("acceptedConnections");
            var refusals = object.remove("connectionLimitRefusals");
            Counters c = mapper.treeToValue(object, Counters.class);
            if (c.pid < 1 || c.connections < 0 || c.connected < 0 || c.failures < 0 || c.uploaded < 0 || c.downloaded < 0 || c.active < 0
                    || c.i2pConnections < 0 || c.i2pConnected < 0 || c.i2pResponses < 0 || c.nymConnections < 0 || c.nymConnected < 0 || c.nymResponses < 0) throw new IllegalArgumentException();
            Instant.parse(c.startedAt);Instant observed = Instant.parse(c.observedAt);
            if (!"OBSERVED".equals(process.observation())) return new Observation("UNAVAILABLE", null);
            if (!"active".equals(process.activeState())) return new Observation("LAST_PROCESS", c);
            long age = Duration.between(observed, Instant.now()).toSeconds();
            if (process.pid() == null || c.pid != process.pid() || age < -2 || age > 5) return new Observation("STALE", null);
            Admission admission = Admission.unavailable();
            if (nonnegativeLong(limit) && limit.longValue() > 0 && nonnegativeLong(occupancy) && nonnegativeLong(refusals))
                admission = new Admission("CURRENT", limit.longValue(), occupancy.longValue(), refusals.longValue());
            return new Observation("CURRENT", c, admission);
        } catch (Exception e) { return new Observation("UNAVAILABLE", null); }
    }
    private static boolean nonnegativeLong(com.fasterxml.jackson.databind.JsonNode value) {
        return value != null && value.isIntegralNumber() && value.canConvertToLong() && value.longValue() >= 0;
    }
}
