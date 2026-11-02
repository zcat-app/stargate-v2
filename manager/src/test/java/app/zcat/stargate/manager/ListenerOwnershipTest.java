// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import org.junit.jupiter.api.Test;

class ListenerOwnershipTest {
    @Test void wildcardListenerOwnsItsLoopbackEndpoint() throws Exception {
        try (var listener = java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.INET)) {
            listener.bind(new InetSocketAddress("0.0.0.0", 0));
            var endpoint = new InetSocketAddress("127.0.0.1", ((InetSocketAddress) listener.getLocalAddress()).getPort());
            assertEquals(Boolean.TRUE, ListenerOwnership.sample(ProcessHandle.current().pid(), endpoint));
        }
    }
    @Test void observesTheActualListeningSocketAndItsClosure() throws Exception {
        var listener = new ServerSocket(0, 16, InetAddress.getByName("127.0.0.1"));
        try {
            var endpoint = new InetSocketAddress("127.0.0.1", listener.getLocalPort());
            long pid = ProcessHandle.current().pid();
            assertEquals(Boolean.TRUE, ListenerOwnership.sample(pid, endpoint));
            assertEquals(Boolean.FALSE, ListenerOwnership.sample(0L, endpoint));
            listener.close();assertEquals(Boolean.FALSE, ListenerOwnership.sample(pid, endpoint));
        } finally { listener.close(); }
    }
}
