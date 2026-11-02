// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

class SocketProbeTest {
    @Test void arbitraryListeningHttpServiceIsNotARespondingProxy() throws Exception {
        try (var listener = new ServerSocket(0, 16, InetAddress.getLoopbackAddress());
             var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            executor.submit(() -> {
                try (var socket = listener.accept()) {
                    SocketProbe.line(socket.getInputStream(), 2048);
                    socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                } catch (java.io.IOException ignored) { }
            });
            assertEquals("UNEXPECTED", SocketProbe.proxy(new InetSocketAddress("127.0.0.1", listener.getLocalPort())).state());
        }
    }

    @Test void tricklingBytesCannotKeepAnObservationRunningIndefinitely() throws Exception {
        try (var listener = new ServerSocket(0, 16, InetAddress.getLoopbackAddress())) {
            var executor = Executors.newVirtualThreadPerTaskExecutor();
            try {
                executor.submit(() -> {
                    try (var socket = listener.accept()) {
                        SocketProbe.line(socket.getInputStream(), 2048);
                        for (int i = 0; i < 60; i++) { socket.getOutputStream().write('H');socket.getOutputStream().flush();Thread.sleep(100); }
                    } catch (java.io.IOException | InterruptedException ignored) { }
                });
                var observation = assertTimeoutPreemptively(Duration.ofSeconds(3),
                        () -> SocketProbe.proxy(new InetSocketAddress("127.0.0.1", listener.getLocalPort())));
                assertEquals("UNAVAILABLE", observation.state());
            } finally { executor.shutdownNow();executor.close(); }
        }
    }
}
