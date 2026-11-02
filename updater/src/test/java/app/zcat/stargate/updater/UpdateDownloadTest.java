// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import com.sun.net.httpserver.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import static app.zcat.stargate.updater.UpdateFiles.*;
import static org.junit.jupiter.api.Assertions.*;

class UpdateDownloadTest {
    @TempDir static Path certificates;
    @TempDir Path temp;
    static SSLContext serverTls, trustedTls;
    @BeforeAll static void certificate() throws Exception {
        Path store = certificates.resolve("fixture.p12"); char[] password = "fixture-only-password".toCharArray();
        var keytool = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/keytool").toString(),
                "-genkeypair", "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", store.toString(), "-storepass", new String(password), "-noprompt")
                .redirectErrorStream(true).start();
        try {
            assertTrue(keytool.waitFor(15, TimeUnit.SECONDS));
            assertEquals(0, keytool.exitValue(), new String(keytool.getInputStream().readAllBytes()));
        } finally { keytool.destroyForcibly(); }
        var keys = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) { keys.load(input, password); }
        var keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); keyManagers.init(keys, password);
        serverTls = SSLContext.getInstance("TLS"); serverTls.init(keyManagers.getKeyManagers(), null, null);
        var trust = KeyStore.getInstance("PKCS12"); trust.load(null, null); trust.setCertificateEntry("fixture", keys.getCertificate("fixture"));
        var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); trustManagers.init(trust);
        trustedTls = SSLContext.getInstance("TLS"); trustedTls.init(null, trustManagers.getTrustManagers(), null);
    }
    static HttpClient client() { return HttpClient.newBuilder().sslContext(trustedTls).followRedirects(HttpClient.Redirect.NEVER).build(); }
    static void redirect(HttpExchange exchange, String location) throws IOException {
        exchange.getResponseHeaders().add("Location", location); exchange.sendResponseHeaders(302, -1);
    }
    static void body(HttpExchange exchange, byte[] bytes) throws IOException {
        exchange.sendResponseHeaders(200, bytes.length); exchange.getResponseBody().write(bytes);
    }
    static final class Server implements AutoCloseable {
        final HttpsServer server;
        final ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
        final AtomicInteger requests = new AtomicInteger();
        Server(HttpHandler handler) throws IOException {
            server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setHttpsConfigurator(new HttpsConfigurator(serverTls)); server.setExecutor(workers);
            server.createContext("/", exchange -> {
                requests.incrementAndGet();
                try { handler.handle(exchange); } finally { exchange.close(); }
            });
            server.start();
        }
        URI uri(String path) { return URI.create("https://127.0.0.1:" + server.getAddress().getPort() + path); }
        @Override public void close() throws InterruptedException { server.stop(0); workers.shutdownNow(); assertTrue(workers.awaitTermination(2, TimeUnit.SECONDS)); }
    }
    void fetch(Server server, String path, Path output, long limit, boolean exact, Duration budget) throws Exception {
        try (var client = client()) { UpdateDownload.https(server.uri(path), output, limit, exact, client, budget); }
    }
    @Test void redirectedReleaseAndArchiveStillUseSignatureAndHashVerification() throws Exception {
        var fixtures = new UpdateTest(); fixtures.tmp = temp;
        var fixture = fixtures.fixture();
        try (var server = new Server(exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/release.json") || path.equals("/release.json.sig") || path.equals("/archive")) redirect(exchange, "/assets" + path);
            else if (path.equals("/assets/release.json")) body(exchange, Files.readAllBytes(fixture.release));
            else if (path.equals("/assets/release.json.sig")) body(exchange, Files.readAllBytes(Path.of(fixture.release + ".sig")));
            else if (path.equals("/assets/archive")) body(exchange, Files.readAllBytes(temp.resolve("image.tar")));
            else exchange.sendResponseHeaders(404, -1);
        })) {
            ((ObjectNode)fixture.doc.path("changes").get(0)).put("archive", server.uri("/archive").toString()); fixture.signRelease();
            var config = (ObjectNode)json(fixture.config);
            config.put("releaseUrl", server.uri("/release.json").toString()); write(fixture.config, config, false);
            fixture.engine = new UpdateTest.Fake(fixture.config, fixture.engine.commands) {
                @Override HttpClient downloadClient() { return client(); }
            };
            fixture.engine.refresh(); String plan = fixture.engine.state.path("plan").asText();
            assertEquals("PREPARED", fixture.engine.state.path("phase").asText()); assertTrue(fixture.calls.isEmpty());
            Files.writeString(temp.resolve("image.tar"), "other");
            assertEquals("ARTIFACT_HASH_MISMATCH", assertThrows(IllegalArgumentException.class, () -> fixture.engine.apply(plan, false)).getMessage());
            assertTrue(fixture.calls.isEmpty());
            Files.writeString(temp.resolve("image.tar"), "image"); fixture.engine.apply(plan, false);
            assertEquals("INSTALLED", fixture.engine.state.path("phase").asText());
            byte[] signature = Files.readAllBytes(Path.of(fixture.release + ".sig")); signature[0] ^= 1;
            Files.write(Path.of(fixture.release + ".sig"), signature); fixture.calls.clear();
            assertThrows(Exception.class, () -> fixture.engine.refresh()); assertTrue(fixture.calls.isEmpty());
        }
    }
    @Test void onlyTheObservedPublicGithubReleaseAssetHopMayCrossOrigins() {
        URI source = URI.create("https://github.com/owner/repo/releases/download/v1.0/image.tar");
        String asset = "https://release-assets.githubusercontent.com/github-production-release-asset/370668507/4937bfe7-85f6-4ede-96c2-1968894594a4?fixture-query=public";
        assertEquals(URI.create(asset), UpdateDownload.redirect(source, List.of(asset)));
        for (String wrong : List.of(asset.replace("release-assets.githubusercontent.com", "release-assets.githubusercontent.com.attacker.invalid"),
                asset.replace(".com/", ".com:444/"), asset.replace("/github-production-release-asset/", "/other/"))) {
            assertThrows(IllegalArgumentException.class, () -> UpdateDownload.redirect(source, List.of(wrong)));
        }
        assertThrows(IllegalArgumentException.class, () -> UpdateDownload.redirect(URI.create("https://github.com/owner/repo/archive/v1.0.tar.gz"), List.of(asset)));
        assertEquals(URI.create(asset + "&next=1"), UpdateDownload.redirect(URI.create(asset), List.of(asset + "&next=1")));
    }
    @Test void unsafeLocationsLoopsAndUnboundedChainsAreNotFollowed() throws Exception {
        try (var target = new Server(exchange -> body(exchange, new byte[]{1}));
             var source = new Server(exchange -> {
                 switch (exchange.getRequestURI().getPath()) {
                     case "/cross" -> redirect(exchange, target.uri("/payload").toString());
                     case "/downgrade" -> redirect(exchange, "http://127.0.0.1:1/payload");
                     case "/userinfo" -> redirect(exchange, "https://user@127.0.0.1/payload");
                     case "/fragment" -> redirect(exchange, "/payload#private");
                     case "/multiple" -> { exchange.getResponseHeaders().add("Location", "/one"); exchange.getResponseHeaders().add("Location", "/two"); exchange.sendResponseHeaders(302, -1); }
                     case "/missing" -> exchange.sendResponseHeaders(302, -1);
                     case "/loop" -> redirect(exchange, "/loop");
                     default -> { int hop = Integer.parseInt(exchange.getRequestURI().getPath().substring(1)); redirect(exchange, "/" + (hop + 1)); }
                 }
             })) {
            for (String path : List.of("/cross", "/downgrade", "/userinfo", "/fragment", "/multiple", "/missing", "/loop", "/0")) {
                Path output = temp.resolve(path.substring(1)); int before = source.requests.get();
                assertThrows(Exception.class, () -> fetch(source, path, output, 1, true, Duration.ofSeconds(5)), path);
                assertFalse(Files.exists(output)); assertEquals(path.equals("/0") ? 6 : 1, source.requests.get() - before, path);
            }
            assertEquals(0, target.requests.get(), "cross-origin target must never be contacted");
        }
    }
    @Test void systemTrustAndSizeFailuresPreserveOutputOwnership() throws Exception {
        try (var server = new Server(exchange -> body(exchange, new byte[]{1, 2, 3}))) {
            Path output = temp.resolve("artifact");
            try (var untrusted = HttpClient.newHttpClient()) {
                assertThrows(IOException.class, () -> UpdateDownload.https(server.uri("/payload"), output, 3, true, untrusted, Duration.ofSeconds(5)));
            }
            assertFalse(Files.exists(output));
            assertThrows(Exception.class, () -> fetch(server, "/payload", output, 2, false, Duration.ofSeconds(5))); assertFalse(Files.exists(output));
            assertThrows(Exception.class, () -> fetch(server, "/payload", output, 4, true, Duration.ofSeconds(5))); assertFalse(Files.exists(output));
            Files.writeString(output, "keep-existing");
            assertThrows(FileAlreadyExistsException.class, () -> fetch(server, "/payload", output, 3, true, Duration.ofSeconds(5)));
            assertEquals("keep-existing", Files.readString(output));
            assertThrows(FileAlreadyExistsException.class, () -> UpdateDownload.local(new ByteArrayInputStream(new byte[]{1}), output, 1, true));
            assertEquals("keep-existing", Files.readString(output));
        }
    }
    @Test void oneDeadlineIncludesRedirectHeadersAndStalledBody() throws Exception {
        var bodyStarted = new CountDownLatch(1);
        try (var server = new Server(exchange -> {
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/warmup")) { body(exchange, new byte[]{1}); return; }
            if (path.equals("/start")) {
                try { Thread.sleep(1300); } catch (InterruptedException stop) { Thread.currentThread().interrupt(); return; }
                redirect(exchange, "/body");
            } else {
                if (path.equals("/body")) {
                    exchange.sendResponseHeaders(200, 0); exchange.getResponseBody().write(1); exchange.getResponseBody().flush(); bodyStarted.countDown();
                }
                try { Thread.sleep(5000); } catch (InterruptedException stop) { Thread.currentThread().interrupt(); }
            }
        }); var client = client()) {
            UpdateDownload.https(server.uri("/warmup"), temp.resolve("warmup"), 1, true, client, Duration.ofSeconds(5));
            Path output = temp.resolve("partial");
            assertTimeoutPreemptively(Duration.ofMillis(2800), () -> {
                assertThrows(Exception.class, () -> UpdateDownload.https(server.uri("/start"), output, 10, false, client, Duration.ofSeconds(2)));
            });
            assertEquals(0, bodyStarted.getCount()); assertFalse(Files.exists(output));
            try (var headersClient = client()) {
                assertTimeoutPreemptively(Duration.ofSeconds(2), () -> assertThrows(Exception.class,
                        () -> UpdateDownload.https(server.uri("/headers"), output, 10, false, headersClient, Duration.ofMillis(300))));
            }
            assertFalse(Files.exists(output));
        }
    }
}
