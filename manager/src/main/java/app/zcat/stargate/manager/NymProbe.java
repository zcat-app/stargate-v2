// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.net.InetSocketAddress;

final class NymProbe {
    record Observation(String readiness, SocketProbe.Observation socks, String destinationAccess) {}
    static Observation sample(InetSocketAddress endpoint, TrafficStats.Observation traffic) {
        if (endpoint == null) return new Observation("DISABLED", null, "NOT_OBSERVED");
        var socks = SocketProbe.socks(endpoint);
        String access = "CURRENT".equals(traffic.state()) && traffic.counters() != null
                ? traffic.counters().nymResponses() > 0 ? "OBSERVED_THIS_PROCESS" : "NOT_OBSERVED" : "UNKNOWN";
        // The native client acknowledges SOCKS CONNECT before sending the request to the mixnet.
        return new Observation("RESPONDING".equals(socks.state()) ? "UNKNOWN" : "UNAVAILABLE", socks, access);
    }
}
