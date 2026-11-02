package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyStore;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Real TLS/JSON-RPC boundaries; no network readiness inferred from a SOCKS greeting. */
class I2pProbeTest {
    @TempDir static Path directory;
    static final ObjectMapper JSON = new ObjectMapper();
    static SSLContext tls;
    static Path certificate, otherCertificate, password;
    static final String SECRET = "a".repeat(43);

    @BeforeAll static void certificates() throws Exception {
        Path store = directory.resolve("fixture.p12");certificate = directory.resolve("fixture.crt");
        String keytool = Path.of(System.getProperty("java.home"), "bin/keytool").toString();
        var generated = new ProcessBuilder(keytool, "-genkeypair", "-alias", "fixture", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", "CN=controlled-test", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", "fixture-password", "-noprompt").redirectErrorStream(true).start();
        generated.getInputStream().readAllBytes();assertEquals(0, generated.waitFor());
        var second = new ProcessBuilder(keytool, "-genkeypair", "-alias", "other", "-keyalg", "RSA", "-keysize", "2048",
                "-sigalg", "SHA256withRSA", "-dname", "CN=wrong-peer", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", store.toString(), "-storepass", "fixture-password", "-noprompt").redirectErrorStream(true).start();
        second.getInputStream().readAllBytes();assertEquals(0, second.waitFor());
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { keys.load(input, "fixture-password".toCharArray()); }
        Files.write(certificate, keys.getCertificate("fixture").getEncoded());
        otherCertificate = directory.resolve("other.crt");Files.write(otherCertificate, keys.getCertificate("other").getEncoded());
        keys.deleteEntry("other");
        var managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());managers.init(keys, "fixture-password".toCharArray());
        tls = SSLContext.getInstance("TLS");tls.init(managers.getKeyManagers(), null, null);
        password = directory.resolve("password");Files.writeString(password, SECRET);
        Files.setPosixFilePermissions(password, PosixFilePermissions.fromString("rw-------"));
    }

    @Test void authenticatedTunnelsAndActualDestinationAccessAreSeparate() throws Exception {
        try (var f = new Fixture()) {
            var observation = f.sample(certificate, password, null);
            assertEquals("READY", observation.readiness());assertEquals("AUTHENTICATED", observation.control());
            assertEquals("UNKNOWN", observation.destinationAccess());assertEquals(1, f.auth.get());assertEquals(1, f.info.get());
            var c = new TrafficStats.Counters(42, "", "", 1, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0);
            assertEquals("OBSERVED_THIS_PROCESS", f.sample(certificate, password, new TrafficStats.Observation("CURRENT", c)).destinationAccess());
            assertEquals("UNKNOWN", f.sample(certificate, password, new TrafficStats.Observation("STALE", c)).destinationAccess());
        }
    }
    @Test void greetingWithoutReadyDestinationOrTunnelsCannotBeReady() throws Exception {
        try (var f = new Fixture()) {
            f.ready = false;assertEquals("NOT_READY", f.sample(certificate, password, null).readiness());
            f.ready = true;f.outbound = 0;var value = f.sample(certificate, password, null);
            assertEquals("NOT_READY", value.readiness());assertEquals("RESPONDING", value.socks().state());
            f.failControl = true;value = f.sample(certificate, password, null);
            assertEquals("UNAVAILABLE", value.readiness());assertNull(value.sharedDestinationReady());assertEquals("RESPONDING", value.socks().state());
        }
    }
    @Test void rejectedAuthenticationStopsBeforeRouterInfoAndMissingPinSendsNoPassword() throws Exception {
        try (var f = new Fixture()) {
            Path wrong = directory.resolve("wrong-password");Files.writeString(wrong, "b".repeat(43));
            Files.setPosixFilePermissions(wrong, PosixFilePermissions.fromString("rw-------"));
            assertEquals("UNAVAILABLE", f.sample(certificate, wrong, null).readiness());assertEquals(0, f.info.get());
            assertEquals("UNAVAILABLE", f.sample(directory.resolve("missing.crt"), password, null).readiness());assertEquals(1, f.auth.get());
        }
    }
    @Test void pinRejectsDifferentPeerCertificate() throws Exception {
        try (var f = new Fixture()) {
            assertEquals("UNAVAILABLE", f.sample(otherCertificate, password, null).readiness());
            assertEquals(0, f.auth.get());assertEquals(0, f.info.get());
        }
    }

    static class Fixture implements AutoCloseable {
        final ServerSocket socks = new ServerSocket(0, 16, InetAddress.getLoopbackAddress());
        final SSLServerSocket control = (SSLServerSocket) tls.getServerSocketFactory().createServerSocket(0, 16, InetAddress.getLoopbackAddress());
        final java.util.concurrent.ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
        final AtomicInteger auth = new AtomicInteger(), info = new AtomicInteger();
        volatile boolean ready = true, failControl;volatile int outbound = 3;
        Fixture() throws Exception {
            executor.submit(() -> {
                while (!socks.isClosed()) try (var socket = socks.accept()) {
                    socket.getInputStream().readNBytes(3);socket.getOutputStream().write(new byte[]{5,0});
                } catch (Exception ignored) {}
            });
            executor.submit(() -> {
                while (!control.isClosed()) {
                    try { var socket = control.accept();executor.submit(() -> {
                        try (socket) {
                            socket.setSoTimeout(2500);var input = socket.getInputStream();SocketProbe.line(input, 1024);
                            int length = 0;
                            for (String line; !(line = SocketProbe.line(input, 1024)).isEmpty();)
                                if (line.startsWith("Content-Length:")) length = Integer.parseInt(line.substring(15).trim());
                            JsonNode request = JSON.readTree(input.readNBytes(length));Object result;
                            if (request.path("method").asText().equals("Authenticate")) {
                                auth.incrementAndGet();result = request.path("params").path("Password").asText().equals(SECRET) ? Map.of("API", 1, "Token", "fixture-token") : Map.of();
                            } else {
                                info.incrementAndGet();assertEquals("fixture-token", request.path("params").path("Token").asText());
                                result = Map.of("i2p.router.status", ready ? "1" : "0", "i2p.router.version", "3.0.0", "i2p.router.netdb.activepeers", 4,
                                        "i2p.router.net.tunnels.inbound", 3, "i2p.router.net.tunnels.outbound", outbound);
                            }
                            byte[] body = JSON.writeValueAsBytes(failControl ? Map.of("id", 1, "error", "fixture") : Map.of("id", 1, "result", result));
                            socket.getOutputStream().write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));socket.getOutputStream().write(body);
                        } catch (Exception ignored) {}
                    }); } catch (Exception ignored) {}
                }
            });
        }
        I2pProbe.Observation sample(Path pin, Path secret, TrafficStats.Observation traffic) {
            return I2pProbe.sample(new InetSocketAddress("127.0.0.1", socks.getLocalPort()), new InetSocketAddress("127.0.0.1", control.getLocalPort()), secret, pin, traffic);
        }
        public void close() throws Exception { socks.close();control.close();executor.close(); }
    }
}
