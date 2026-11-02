// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HexFormat;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** V1 SidecarMonitor's unavailable/not-ready recovery cases, against the new wire protocol. */
class TorProbeTest {
    @TempDir Path directory;

    @Test void authenticatedBootstrapAndCircuitsAreRequiredForReadiness() throws Exception {
        try (Fixture f = new Fixture(100, true, false, false, false)) {
            var observation = f.sample();
            assertEquals(TorProbe.Health.READY, observation.readiness());assertEquals(100, observation.bootstrapPercent());
            assertEquals("AUTHENTICATED", observation.control());assertEquals(1234L, observation.processId());
            assertTrue(f.authenticated.get());
        }
        try (Fixture f = new Fixture(37, false, false, false, false)) {
            var observation = f.sample();assertEquals(TorProbe.Health.NOT_READY, observation.readiness());
            assertEquals(37, observation.bootstrapPercent());assertEquals("BOOTSTRAPPING", observation.code());
        }
        try (Fixture f = new Fixture(100, false, false, false, false)) {
            assertEquals("NO_ESTABLISHED_CIRCUIT", f.sample().code());
        }
    }

    @Test void controlFailureDoesNotInventTorExitDespiteLiveSocks() throws Exception {
        try (Fixture f = new Fixture(100, true, false, false, false)) {
            f.control.close();var observation = f.sample();
            assertEquals(TorProbe.Health.UNAVAILABLE, observation.readiness());assertNull(observation.bootstrapPercent());
            assertNull(observation.processId());assertEquals("RESPONDING", observation.socks().state());
        }
    }

    @Test void rejectsForgedServerBeforeSendingClientAuthentication() throws Exception {
        try (Fixture f = new Fixture(100, true, false, false, true)) {
            assertEquals(TorProbe.Health.UNAVAILABLE, f.sample().readiness());
            assertFalse(f.authenticated.get());
        }
    }

    @Test void disabledNetworkOrDifferentSocksEndpointCannotBeReady() throws Exception {
        try (Fixture f = new Fixture(100, true, true, false, false)) {
            var observation = f.sample();assertEquals(TorProbe.Health.NOT_READY, observation.readiness());assertEquals("NETWORK_DISABLED", observation.code());
        }
        try (Fixture f = new Fixture(100, true, false, true, false)) {
            var observation = f.sample();assertEquals(TorProbe.Health.NOT_READY, observation.readiness());assertFalse(observation.socksEndpointMatches());
        }
    }

    @Test void malformedAuthenticatedBootstrapIsUnknownNotZeroPercent() throws Exception {
        try (Fixture f = new Fixture(101, true, false, false, false)) {
            var observation = f.sample();assertEquals(TorProbe.Health.UNAVAILABLE, observation.readiness());assertNull(observation.bootstrapPercent());
        }
    }

    private final class Fixture implements AutoCloseable {
        final ServerSocket socks = new ServerSocket(0, 16, java.net.InetAddress.getLoopbackAddress());
        final ServerSocket control = new ServerSocket(0, 16, java.net.InetAddress.getLoopbackAddress());
        final java.util.concurrent.ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        final AtomicBoolean authenticated = new AtomicBoolean();
        final Path cookie;
        Fixture(int progress, boolean circuit, boolean disabled, boolean mismatch, boolean forged) throws Exception {
            cookie = directory.resolve("cookie-" + control.getLocalPort());Files.write(cookie, new byte[32]);
            executor.submit(() -> {
                try (var socket = socks.accept()) {
                    assertArrayEquals(new byte[]{5,1,0}, socket.getInputStream().readNBytes(3));socket.getOutputStream().write(new byte[]{5,0});
                } catch (IOException ignored) { }
            });
            executor.submit(() -> {
                try (var socket = control.accept()) {
                    socket.setSoTimeout(2000);
                    String challenge = SocketProbe.line(socket.getInputStream(), 1024);
                    assertTrue(challenge.startsWith("AUTHCHALLENGE SAFECOOKIE "));
                    byte[] nonce = HexFormat.of().parseHex(challenge.substring("AUTHCHALLENGE SAFECOOKIE ".length()));
                    byte[] message = new byte[96];System.arraycopy(nonce, 0, message, 32, 32);
                    byte[] serverHash = TorProbe.hmac("Tor safe cookie authentication server-to-controller hash", message);
                    if (forged) serverHash[0] ^= 1;
                    send(socket, "250 AUTHCHALLENGE SERVERHASH=" + HexFormat.of().formatHex(serverHash) + " SERVERNONCE=" + "00".repeat(32) + "\r\n");
                    String auth = SocketProbe.line(socket.getInputStream(), 1024);
                    assertEquals("AUTHENTICATE " + HexFormat.of().formatHex(TorProbe.hmac("Tor safe cookie authentication controller-to-server hash", message)), auth);
                    authenticated.set(true);send(socket, "250 OK\r\n");
                    assertTrue(SocketProbe.line(socket.getInputStream(), 1024).startsWith("GETINFO "));
                    send(socket, "250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=" + progress + " TAG=done SUMMARY=\"fixture\"\r\n"
                            + "250-status/circuit-established=" + (circuit ? 1 : 0) + "\r\n250-version=fixture\r\n250-process/pid=1234\r\n"
                            + "250-net/listeners/socks=\"127.0.0.1:" + (mismatch ? 1 : socks.getLocalPort()) + "\"\r\n250 OK\r\n");
                    String command = SocketProbe.line(socket.getInputStream(), 1024);assertEquals("GETCONF DisableNetwork", command);
                    send(socket, "250 DisableNetwork=" + (disabled ? 1 : 0) + "\r\n");
                } catch (IOException ignored) { }
            });
        }
        TorProbe.Observation sample() { return TorProbe.sample(new InetSocketAddress("127.0.0.1", control.getLocalPort()), cookie, new InetSocketAddress("127.0.0.1", socks.getLocalPort())); }
        private void send(java.net.Socket socket, String value) throws IOException { socket.getOutputStream().write(value.getBytes(StandardCharsets.US_ASCII)); }
        @Override public void close() throws Exception { socks.close();control.close();executor.shutdownNow();assertTrue(executor.awaitTermination(3, TimeUnit.SECONDS)); }
    }
}
