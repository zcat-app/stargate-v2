// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Wire-level cases adapted from v1 forward/tor_test.go and fake_socks5_tor.go. */
class ProxyServerTest {
    private static final String HOST = "a".repeat(56) + ".onion";
    private static final String TOKEN = "synthetic-browser-token-for-unit-tests";
    private static final byte[] KEY = new byte[32];
    private final List<AutoCloseable> resources = new ArrayList<>();

    @AfterEach void cleanup() throws Exception {
        for (int i = resources.size() - 1; i >= 0; i--) resources.get(i).close();
    }

    private ProxyServer proxy(FakeTor tor, int timeout, int maximum) throws Exception {
        return proxy(tor, null, timeout, maximum);
    }
    private ProxyServer proxy(FakeTor tor, FakeTor i2p, int timeout, int maximum) throws Exception {
        return proxy(tor, i2p, null, timeout, maximum);
    }
    private ProxyServer proxy(FakeTor tor, FakeTor i2p, FakeTor nym, int timeout, int maximum) throws Exception {
        HmacPartition hmac = new HmacPartition(KEY);
        var profile = new ProxyConfig.Profile(ProxyConfig.digest(TOKEN.getBytes(StandardCharsets.US_ASCII)), hmac.forProfile("browser"));
        var profiles = Map.of("browser", profile, "other", new ProxyConfig.Profile(profile.tokenDigest(), hmac.forProfile("other")));
        var config = new ProxyConfig(new InetSocketAddress("127.0.0.1", 0),
                new InetSocketAddress("127.0.0.1", tor.listener.getLocalPort()), profiles, maximum, timeout, 500, false, null,
                i2p == null ? null : new InetSocketAddress("127.0.0.1", i2p.listener.getLocalPort()), timeout,
                nym == null ? null : new InetSocketAddress("127.0.0.1", nym.listener.getLocalPort()), timeout);
        ProxyServer server = new ProxyServer(config).start();resources.add(server);return server;
    }
    private FakeTor tor(Mode mode) throws Exception { FakeTor tor = new FakeTor(mode);resources.add(tor);return tor; }
    private Socket client(ProxyServer proxy) throws Exception {
        Socket socket = new Socket("127.0.0.1", proxy.port());socket.setSoTimeout(4000);return socket;
    }
    private static String auth(String user, String token) {
        return "Proxy-Authorization: Basic " + Base64.getEncoder().encodeToString((user + ":" + token).getBytes(StandardCharsets.US_ASCII)) + "\r\n";
    }
    private static String request(String target, String host, String extra) {
        return "GET " + target + " HTTP/1.1\r\nHost: " + host + "\r\n" + auth("browser", TOKEN) + extra + "\r\n";
    }
    private String exchange(ProxyServer proxy, String request) throws Exception {
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            return new String(socket.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
        }
    }
    private static String headers(InputStream input) throws IOException {
        var bytes = new ByteArrayOutputStream();int current;
        while ((current = input.read()) != -1 && bytes.size() < 131072) {
            bytes.write(current);
            byte[] value = bytes.toByteArray();
            int n = value.length;
            if (n >= 4 && value[n-4] == 13 && value[n-3] == 10 && value[n-2] == 13 && value[n-1] == 10) break;
        }
        return bytes.toString(StandardCharsets.ISO_8859_1);
    }

    @Test void authenticationAndDestinationFailuresNeverReachTor() throws Exception {
        FakeTor tor = tor(Mode.HTTP);ProxyServer proxy = proxy(tor, 1000, 8);
        assertTrue(exchange(proxy, "GET http://" + HOST + "/ HTTP/1.1\r\nHost: " + HOST + "\r\n\r\n").startsWith("HTTP/1.1 407"));
        assertTrue(exchange(proxy, "GET http://" + HOST + "/ HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("browser", "wrong") + "\r\n").startsWith("HTTP/1.1 407"));
        assertTrue(exchange(proxy, request("http://example.com/", "example.com", "")).startsWith("HTTP/1.1 403"));
        String unsupported = exchange(proxy, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n");
        assertTrue(unsupported.startsWith("HTTP/1.1 403"), unsupported);
        assertFalse(unsupported.toLowerCase().contains("proxy-authenticate"));
        assertTrue(exchange(proxy, request("http://" + HOST + "/", "different.onion", "")).startsWith("HTTP/1.1 400"));
        assertTrue(exchange(proxy, request("/relative", HOST, "")).startsWith("HTTP/1.1 400"));
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "Host: " + HOST + "\r\n")).startsWith("HTTP/1.1 400"));
        assertEquals(0, tor.seen.size());
    }

    @Test void httpForwardsUnresolvedTargetOpaquePartitionAndNoLocalSecret() throws Exception {
        FakeTor tor = tor(Mode.HTTP);ProxyServer proxy = proxy(tor, 1000, 8);
        String result = exchange(proxy, request("http://" + HOST + ":8080/a?b=1", HOST + ":8080", "Proxy-Connection: keep-alive\r\nConnection: X-Remove\r\nX-Remove: hidden\r\n"));
        assertTrue(result.startsWith("HTTP/1.1 200"), result);assertTrue(result.endsWith("fixture-ok"), result);
        Seen seen = tor.seen.getFirst();
        assertEquals(3, seen.atyp);assertEquals(HOST, seen.host);assertEquals(8080, seen.port);
        assertEquals(new HmacPartition(KEY).forProfile("browser"), seen.username);assertEquals("", seen.password);
        assertFalse(seen.username.contains(TOKEN));
        assertTrue(seen.http.startsWith("GET /a?b=1 HTTP/1.1\r\n"));
        assertFalse(seen.http.toLowerCase().contains("proxy-authorization"));
        assertFalse(seen.http.toLowerCase().contains("proxy-connection"));
        assertFalse(seen.http.toLowerCase().contains("x-remove:"));
        assertFalse(seen.http.contains(TOKEN));
    }

    @Test void canonicalOnionAndProfilesKeepTheirIntendedBoundaries() throws Exception {
        FakeTor tor = tor(Mode.HTTP);ProxyServer proxy = proxy(tor, 1000, 8);
        assertTrue(exchange(proxy, request("http://" + HOST.toUpperCase() + "./", HOST.toUpperCase() + ".", "")).endsWith("fixture-ok"));
        exchange(proxy, "GET http://" + HOST + "/ HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("other", TOKEN) + "\r\n");
        assertEquals(HOST, tor.seen.getFirst().host);
        assertNotEquals(tor.seen.get(0).username, tor.seen.get(1).username);
    }

    @Test void connectBridgesBytesWithoutInjectingHttpAfterEstablishment() throws Exception {
        FakeTor tor = tor(Mode.ECHO);ProxyServer proxy = proxy(tor, 1000, 8);
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(("CONNECT " + HOST + ":443 HTTP/1.1\r\nHost: " + HOST + ":443\r\n" + auth("browser", TOKEN) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            String response = headers(socket.getInputStream());assertTrue(response.startsWith("HTTP/1.1 200"), response);
            byte[] payload = new byte[49152];new java.util.Random(7).nextBytes(payload);
            socket.getOutputStream().write(payload);assertArrayEquals(payload, socket.getInputStream().readNBytes(payload.length));
        }
        assertTrue(tor.closed.await(2, TimeUnit.SECONDS));
        assertEquals("", tor.seen.getFirst().password);
    }

    @Test void streamedPostRetainsBodyAndStripsProxyCredentials() throws Exception {
        FakeTor tor = tor(Mode.HTTP);ProxyServer proxy = proxy(tor, 1000, 8);
        byte[] payload = "upload-data-".repeat(20000).getBytes(StandardCharsets.US_ASCII);
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(("POST http://" + HOST + "/upload HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("browser", TOKEN) + "Content-Length: " + payload.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(payload);
            assertTrue(new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII).endsWith("fixture-ok"));
        }
        assertArrayEquals(payload, tor.seen.getFirst().body);
    }

    @Test void establishedTunnelAndStreamingUploadOutliveHeaderDeadline() throws Exception {
        FakeTor echo = tor(Mode.ECHO);ProxyServer tunnel = proxy(echo, 2000, 8);
        try (Socket socket = client(tunnel)) {
            socket.getOutputStream().write(("CONNECT " + HOST + ":443 HTTP/1.1\r\nHost: " + HOST + ":443\r\n" + auth("browser", TOKEN) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            assertTrue(headers(socket.getInputStream()).startsWith("HTTP/1.1 200"));
            Thread.sleep(700);
            socket.getOutputStream().write("alive".getBytes(StandardCharsets.US_ASCII));
            assertEquals("alive", new String(socket.getInputStream().readNBytes(5), StandardCharsets.US_ASCII));
        }
        FakeTor upstream = tor(Mode.HTTP);ProxyServer upload = proxy(upstream, 2000, 8);
        try (Socket socket = client(upload)) {
            socket.getOutputStream().write(("POST http://" + HOST + "/upload HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("browser", TOKEN) + "Content-Length: 5\r\n\r\na").getBytes(StandardCharsets.US_ASCII));
            assertTrue(upstream.accepted.await(2, TimeUnit.SECONDS));
            Thread.sleep(700);
            socket.getOutputStream().write("live".getBytes(StandardCharsets.US_ASCII));
            assertTrue(new String(socket.getInputStream().readAllBytes(), StandardCharsets.US_ASCII).endsWith("fixture-ok"));
        }
        assertEquals("alive", new String(upstream.seen.getFirst().body, StandardCharsets.US_ASCII));
    }

    @Test void delayedSetupBackpressuresAnUploadInsteadOfRejectingIt() throws Exception {
        FakeTor tor = tor(Mode.SLOW_HTTP);ProxyServer proxy = proxy(tor, 2000, 8);
        byte[] payload = "slow-upstream-upload".repeat(30000).getBytes(StandardCharsets.US_ASCII);
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(("POST http://" + HOST + "/upload HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("browser", TOKEN) + "Content-Length: " + payload.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(payload);
            String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
            assertTrue(response.endsWith("fixture-ok"), response);
        }
        assertArrayEquals(payload, tor.seen.getFirst().body);
    }

    @Test void responseTransferCodingIsPreservedWhileReframingChunks() throws Exception {
        FakeTor tor = tor(Mode.GZIP_RESPONSE);ProxyServer proxy = proxy(tor, 1000, 8);
        byte[] response;
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(request("http://" + HOST + "/", HOST, "").getBytes(StandardCharsets.US_ASCII));
            String received = headers(socket.getInputStream()).toLowerCase();
            assertTrue(received.contains("transfer-encoding: gzip, chunked"), received);
            String length = line(socket.getInputStream());int n = Integer.parseInt(length.trim(), 16);
            response = socket.getInputStream().readNBytes(n);
        }
        try (var gzip = new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(response))) {
            assertEquals("fixture-ok", new String(gzip.readAllBytes(), StandardCharsets.US_ASCII));
        }
    }

    private static String line(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();int value;
        while ((value=in.read()) != -1) { if (value=='\n') break; if (value!='\r') out.write(value); }
        return out.toString(StandardCharsets.US_ASCII);
    }

    @Test void refusalTimeoutAndConnectionLimitAreBounded() throws Exception {
        FakeTor refused = tor(Mode.REFUSE);ProxyServer p1 = proxy(refused, 1000, 8);
        String refusedResponse = exchange(p1, request("http://" + HOST + "/", HOST, ""));assertTrue(refusedResponse.startsWith("HTTP/1.1 502"), refusedResponse);
        FakeTor hung = tor(Mode.HANG);ProxyServer p2 = proxy(hung, 150, 8);
        assertTrue(exchange(p2, request("http://" + HOST + "/", HOST, "")).startsWith("HTTP/1.1 504"));
        FakeTor held = tor(Mode.HANG);ProxyServer p3 = proxy(held, 3000, 1);
        try (Socket first = client(p3)) {
            first.getOutputStream().write(request("http://" + HOST + "/", HOST, "").getBytes(StandardCharsets.US_ASCII));
            assertTrue(held.accepted.await(2, TimeUnit.SECONDS));
            assertTrue(exchange(p3, request("http://" + HOST + "/", HOST, "")).startsWith("HTTP/1.1 503"));
        }
        assertTrue(held.closed.await(2, TimeUnit.SECONDS));
    }

    @Test void ambiguousFramingAndOversizedHeadersDoNotOpenTorConnections() throws Exception {
        FakeTor tor = tor(Mode.HTTP);ProxyServer proxy = proxy(tor, 1000, 8);
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "Connection: content-length\r\nContent-Length: 0\r\n")).startsWith("HTTP/1.1 400"));
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "Content-Length: 1\r\nContent-Length: 2\r\n")).startsWith("HTTP/1.1 400"));
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "X-Huge: " + "x".repeat(20000) + "\r\n")).startsWith("HTTP/1.1 400"));
        assertEquals(0, tor.seen.size());
    }

    @Test void websocketUpgradeRelaysRawFrames() throws Exception {
        FakeTor tor = tor(Mode.UPGRADE);ProxyServer proxy = proxy(tor, 1000, 8);
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(request("http://" + HOST + "/socket", HOST, "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n").getBytes(StandardCharsets.US_ASCII));
            String response = headers(socket.getInputStream());assertTrue(response.startsWith("HTTP/1.1 101"), response);
            byte[] raw = { (byte) 0x81, 2, 'o', 'k' };
            socket.getOutputStream().write(raw);assertArrayEquals(raw, socket.getInputStream().readNBytes(raw.length));
        }
    }

    @Test void authenticatedDevicesSelectOnlyTheirI2pListenerAndNeverSharedFallback() throws Exception {
        FakeTor tor = tor(Mode.HTTP), shared = new FakeTor(Mode.HTTP,true), a = new FakeTor(Mode.HTTP,true), b = new FakeTor(Mode.REFUSE,true);
        resources.add(shared); resources.add(a); resources.add(b);
        var hmac = new HmacPartition(KEY); byte[] digest = ProxyConfig.digest(TOKEN.getBytes(StandardCharsets.US_ASCII));
        var profiles = Map.of("browser", new ProxyConfig.Profile(digest,hmac.forProfile("browser"),a.listener.getLocalPort()),
                "other",new ProxyConfig.Profile(digest,hmac.forProfile("other"),b.listener.getLocalPort()),
                "missing",new ProxyConfig.Profile(digest,hmac.forProfile("missing"),0));
        var config = new ProxyConfig(new InetSocketAddress("127.0.0.1",0),new InetSocketAddress("127.0.0.1",tor.listener.getLocalPort()),profiles,16,1500,500,false,null,new InetSocketAddress("127.0.0.1",shared.listener.getLocalPort()),1500);
        var proxy = new ProxyServer(config).start();resources.add(proxy);
        String req = request("http://controlled.i2p/proof","controlled.i2p","");
        assertTrue(exchange(proxy,req).endsWith("fixture-ok"));
        assertTrue(exchange(proxy,req.replace(auth("browser",TOKEN),auth("other",TOKEN))).endsWith("I2P_UNAVAILABLE\n"));
        assertTrue(exchange(proxy,req.replace(auth("browser",TOKEN),auth("missing",TOKEN))).endsWith("I2P_DEVICE_UNAVAILABLE\n"));
        assertEquals(0,shared.seen.size());assertEquals(0,tor.seen.size());
        assertEquals(1,a.seen.size());assertEquals(3,a.seen.getFirst().atyp);assertNull(a.seen.getFirst().username);
        assertTrue(exchange(proxy,request("http://"+HOST+"/",HOST,"")).endsWith("fixture-ok"));
    }

    @Test void twoNetworksRouteConcurrentlyWithDifferentAuthenticationAndUnresolvedNames() throws Exception {
        FakeTor tor = tor(Mode.HTTP), i2p = new FakeTor(Mode.HTTP, true);resources.add(i2p);
        ProxyServer proxy = proxy(tor, i2p, 1500, 16);
        List<String> names = List.of(HOST, "controlled.i2p", "b".repeat(52) + ".b32.i2p");
        try (var threads = Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = names.stream().map(host -> threads.submit(() -> exchange(proxy, request("http://" + host + "/proof", host, "")))).toList();
            for (var task : tasks) assertTrue(task.get().endsWith("fixture-ok"));
        }
        assertEquals(1, tor.seen.size());assertEquals(2, i2p.seen.size());
        assertEquals(HOST, tor.seen.getFirst().host);
        for (Seen s : i2p.seen) {
            assertEquals(3, s.atyp);assertNull(s.username);assertNull(s.password);
            assertTrue(names.contains(s.host));assertFalse(s.http.toLowerCase().contains("proxy-authorization"));assertFalse(s.http.contains(TOKEN));
        }
        assertTrue(tor.seen.getFirst().username.startsWith("sg2:"));
    }

    @Test void unavailableAndUnauthenticatedI2pNeverFallBackToTorOrDirect() throws Exception {
        FakeTor tor = tor(Mode.HTTP), i2p = new FakeTor(Mode.REFUSE, true);resources.add(i2p);
        ProxyServer proxy = proxy(tor, i2p, 1000, 16);
        String host = "controlled.i2p";
        assertTrue(exchange(proxy, "GET http://" + host + "/ HTTP/1.1\r\nHost: " + host + "\r\n\r\n").startsWith("HTTP/1.1 407"));
        assertEquals(0, i2p.seen.size());
        String failed = exchange(proxy, request("http://" + host + "/", host, ""));
        assertTrue(failed.startsWith("HTTP/1.1 502"));assertTrue(failed.endsWith("I2P_UNAVAILABLE\n"));assertEquals(0, tor.seen.size());
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).endsWith("fixture-ok"));
        assertTrue(exchange(proxy, request("http://controlled.i2p.evil.invalid/", "controlled.i2p.evil.invalid", "")).startsWith("HTTP/1.1 403"));
        assertEquals(1, tor.seen.size());assertEquals(1, i2p.seen.size());
        ProxyServer missing = proxy(tor, 1000, 16);
        assertTrue(exchange(missing, request("http://" + host + "/", host, "")).endsWith("I2P_NOT_CONFIGURED\n"));
        assertEquals(1, tor.seen.size());
    }

    @Test void i2pTimeoutDoesNotPreventTorConnectionsAndConnectUsesNoCredentials() throws Exception {
        FakeTor tor = tor(Mode.HTTP), hung = new FakeTor(Mode.HANG, true);resources.add(hung);
        ProxyServer proxy = proxy(tor, hung, 150, 16);
        assertTrue(exchange(proxy, request("http://controlled.i2p/", "controlled.i2p", "")).endsWith("I2P_SETUP_TIMEOUT\n"));
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).endsWith("fixture-ok"));
        FakeTor echo = new FakeTor(Mode.ECHO, true);resources.add(echo);ProxyServer tunnel = proxy(tor, echo, 1000, 8);
        try (Socket socket = client(tunnel)) {
            socket.getOutputStream().write(("CONNECT controlled.i2p:443 HTTP/1.1\r\nHost: controlled.i2p:443\r\n" + auth("browser", TOKEN) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            assertTrue(headers(socket.getInputStream()).startsWith("HTTP/1.1 200"));
            socket.getOutputStream().write(new byte[]{1,2,3});assertArrayEquals(new byte[]{1,2,3}, socket.getInputStream().readNBytes(3));
        }
        assertEquals(443, echo.seen.getFirst().port);assertNull(echo.seen.getFirst().username);
    }

    @Test void threeRoutesKeepNamesUnresolvedAndNymGetsNoCredentials() throws Exception {
        FakeTor tor = tor(Mode.HTTP), i2p = new FakeTor(Mode.HTTP, true), nym = new FakeTor(Mode.HTTP, true);
        resources.add(i2p);resources.add(nym);
        ProxyServer proxy = proxy(tor, i2p, nym, 2000, 16);
        try (var threads = Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = List.of(HOST, "controlled.i2p", "controlled.example.com").stream()
                    .map(host -> threads.submit(() -> exchange(proxy, request("http://" + host + "/", host, "")))).toList();
            for (var task : tasks) assertTrue(task.get().endsWith("fixture-ok"));
        }
        assertEquals(1, tor.seen.size());assertEquals(1, i2p.seen.size());assertEquals(1, nym.seen.size());
        Seen seen = nym.seen.getFirst();assertEquals(3, seen.atyp);assertEquals("controlled.example.com", seen.host);
        assertNull(seen.username);assertNull(seen.password);assertFalse(seen.http.contains(TOKEN));
        assertFalse(seen.http.toLowerCase().contains("proxy-authorization"));
        for (String host : List.of("127.0.0.1", "2130706433", "0x7f000001", "127.1", "host.local", "x.home.arpa", "localhost", "x.invalid", "x.test", "x.example"))
        {
            String rejected = exchange(proxy, request("http://" + host + "/", host, ""));
            assertTrue(rejected.startsWith("HTTP/1.1 403") || rejected.startsWith("HTTP/1.1 400"), host);
        }
        assertEquals(1, nym.seen.size());
        assertTrue(exchange(proxy, "GET http://controlled.example.com/ HTTP/1.1\r\nHost: controlled.example.com\r\n\r\n").startsWith("HTTP/1.1 407"));
        assertEquals(1, nym.seen.size());
    }

    @Test void nymEarlyAcknowledgementStillHasAFirstResponseDeadlineAndNoFallback() throws Exception {
        FakeTor tor = tor(Mode.HTTP), nym = new FakeTor(Mode.ACK_HANG, true);resources.add(nym);
        ProxyServer proxy = proxy(tor, null, nym, 200, 16);
        assertTrue(exchange(proxy, request("http://controlled.example.com/", "controlled.example.com", "")).endsWith("NYM_SETUP_TIMEOUT\n"));
        try (Socket socket = client(proxy)) {
            socket.getOutputStream().write(("CONNECT controlled.example.com:443 HTTP/1.1\r\nHost: controlled.example.com:443\r\n" + auth("browser", TOKEN) + "\r\n").getBytes(StandardCharsets.US_ASCII));
            assertTrue(headers(socket.getInputStream()).startsWith("HTTP/1.1 200"));
            assertEquals(-1, socket.getInputStream().read());
        }
        assertEquals(0, tor.seen.size());
        assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).endsWith("fixture-ok"));
        FakeTor refused = new FakeTor(Mode.REFUSE, true);resources.add(refused);
        ProxyServer unavailable = proxy(tor, null, refused, 500, 16);
        assertTrue(exchange(unavailable, request("http://controlled.example.com/", "controlled.example.com", "")).endsWith("NYM_UNAVAILABLE\n"));
        assertEquals(1, tor.seen.size());
    }

    @Test void stoppingI2pClosesItsTunnelButPreservesSameDevicesTorTunnel() throws Exception {
        FakeTor tor = tor(Mode.ECHO), i2p = new FakeTor(Mode.ECHO,true);resources.add(i2p);
        var directory = java.nio.file.Files.createTempDirectory("stargate-route-stop");var path=directory.resolve("proxy.properties");
        String base="listen.port=0\ntor.port="+tor.listener.getLocalPort()+"\ni2p.host=127.0.0.1\ni2p.port=4447\ni2p.deviceIsolation=true\nisolation.key="+"00".repeat(32)+"\nprofile.browser.token="+TOKEN+"\nprofile.browser.i2pPort="+i2p.listener.getLocalPort()+"\n";
        atomicConfig(path,base);
        try (ProxyServer proxy=new ProxyServer(ProxyConfig.load(path),path).start();Socket one=client(proxy);Socket two=client(proxy)) {
            for (var entry : Map.of(one,"controlled.i2p",two,HOST).entrySet()) {
                entry.getKey().getOutputStream().write(("CONNECT "+entry.getValue()+":443 HTTP/1.1\r\nHost: "+entry.getValue()+":443\r\n"+auth("browser",TOKEN)+"\r\n").getBytes(StandardCharsets.US_ASCII));
                assertTrue(headers(entry.getKey().getInputStream()).startsWith("HTTP/1.1 200"));
            }
            atomicConfig(path,base+"profile.browser.i2pEnabled=false\n");assertEquals(-1,one.getInputStream().read());
            two.getOutputStream().write(72);assertEquals(72,two.getInputStream().read());
            assertTrue(exchange(proxy,request("http://controlled.i2p/","controlled.i2p","")).endsWith("I2P_DEVICE_UNAVAILABLE\n"));
        } finally { java.nio.file.Files.deleteIfExists(path);java.nio.file.Files.deleteIfExists(directory); }
    }

    @Test void liveRevocationClosesOnlyRevokedTunnelAndRejectsNewRequests() throws Exception {
        FakeTor tor = tor(Mode.ECHO);
        var directory = java.nio.file.Files.createTempDirectory("stargate-live-auth-test");
        var path = directory.resolve("proxy.properties");
        String base = "listen.port=0\ntor.port=" + tor.listener.getLocalPort() + "\nisolation.key=" + "00".repeat(32) + "\n";
        String a = "profile.browser.token=" + TOKEN + "\n", b = "profile.other.token=" + TOKEN + "\n";
        java.nio.file.Files.writeString(path, base + a + b);
        java.nio.file.Files.setPosixFilePermissions(path, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        try (ProxyServer proxy = new ProxyServer(ProxyConfig.load(path), path).start();
             Socket one = client(proxy); Socket two = client(proxy)) {
            for (var entry : Map.of(one, "browser", two, "other").entrySet()) {
                entry.getKey().getOutputStream().write(("CONNECT " + HOST + ":443 HTTP/1.1\r\nHost: " + HOST + ":443\r\n" + auth(entry.getValue(), TOKEN) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                assertTrue(headers(entry.getKey().getInputStream()).startsWith("HTTP/1.1 200"));
            }
            var next = directory.resolve("next");
            java.nio.file.Files.writeString(next, base + b);
            java.nio.file.Files.setPosixFilePermissions(next, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
            java.nio.file.Files.move(next, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            assertEquals(-1, one.getInputStream().read());
            two.getOutputStream().write(71);assertEquals(71, two.getInputStream().read());
            assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).startsWith("HTTP/1.1 407"));
            // An unreadable store must not keep accepting the last good credentials.
            java.nio.file.Files.delete(path);assertEquals(-1, two.getInputStream().read());
            assertTrue(exchange(proxy, "GET http://" + HOST + "/ HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("other", TOKEN) + "\r\n").startsWith("HTTP/1.1 407"));
        } finally { java.nio.file.Files.deleteIfExists(path);java.nio.file.Files.deleteIfExists(directory); }
    }

    @Test void newlyPublishedDeviceAuthenticatesBeforeTheNextScheduledRefresh() throws Exception { authenticationRefresh(AuthRefresh.BETWEEN_READS); }
    @Test void authenticationMissDoesNotRetryAgainstAnAlreadyRunningRead() throws Exception { authenticationRefresh(AuthRefresh.DURING_READ); }
    @Test void authenticationRefreshTimeoutFailsClosedAndReleasesPendingBody() throws Exception { authenticationRefresh(AuthRefresh.TIMEOUT); }
    @Test void malformedAuthenticationDoesNotWaitForARefresh() throws Exception { authenticationRefresh(AuthRefresh.MALFORMED); }
    @Test void shutdownDuringAuthenticationReleasesPendingBody() throws Exception { authenticationRefresh(AuthRefresh.SHUTDOWN); }
    @Test void wellFormedInvalidCredentialFailsClosedAfterRefresh() throws Exception { authenticationRefresh(AuthRefresh.INVALID); }
    @Test void authenticationWaitEnforcesThePendingBodyLimit() throws Exception { authenticationRefresh(AuthRefresh.BODY_LIMIT); }

    private enum AuthRefresh { BETWEEN_READS, DURING_READ, TIMEOUT, MALFORMED, SHUTDOWN, INVALID, BODY_LIMIT }

    private static Object privateField(Object owner, String name) throws Exception {
        var field = owner.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(owner);
    }

    private void authenticationRefresh(AuthRefresh scenario) throws Exception {
        FakeTor tor = tor(Mode.HTTP);
        var directory = java.nio.file.Files.createTempDirectory("stargate-new-device-auth");
        var path = directory.resolve("proxy.properties");
        String base = "listen.port=0\nheaderTimeoutMillis=1000\ntor.port=" + tor.listener.getLocalPort() + "\nisolation.key=" + "00".repeat(32) + "\n";
        String id = "d_new_phone", token = "new-device-token-" + "a".repeat(32);
        atomicConfig(path, base);
        try (ProxyServer proxy = new ProxyServer(ProxyConfig.load(path), path).start()) {
            // Hold the scheduler after its initial refresh: publication now occurs between ticks.
            // Only the test controls scheduling; requests still use the real authentication path.
            var refresh = (java.util.concurrent.ScheduledExecutorService) privateField(proxy, "credentialRefresh");
            var held = new CountDownLatch(1);var resume = new CountDownLatch(1);
            if (scenario == AuthRefresh.DURING_READ) {
                refresh.submit(() -> {}).get(2, TimeUnit.SECONDS);
                var field = ProxyServer.class.getDeclaredField("connections");field.setAccessible(true);
                var original = (io.netty.channel.group.ChannelGroup) field.get(proxy);
                var once = new java.util.concurrent.atomic.AtomicBoolean(true);
                // Hold the real refresh after reading the old file, before notifying front handlers.
                var observed = java.lang.reflect.Proxy.newProxyInstance(getClass().getClassLoader(),
                        new Class<?>[]{io.netty.channel.group.ChannelGroup.class}, (object, method, arguments) -> {
                            if (method.getName().equals("iterator") && once.compareAndSet(true, false)) {
                                held.countDown();resume.await();
                            }
                            try { return method.invoke(original, arguments); }
                            catch (java.lang.reflect.InvocationTargetException e) { throw e.getCause(); }
                        });
                field.set(proxy, observed);
                refresh.submit(() -> {
                    try {
                        var method = ProxyServer.class.getDeclaredMethod("refreshCredentials");method.setAccessible(true);method.invoke(proxy);
                    } catch (ReflectiveOperationException e) { throw new AssertionError(e); }
                });
            } else refresh.submit(() -> {
                held.countDown();
                try { resume.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
            });
            try {
                assertTrue(held.await(2, TimeUnit.SECONDS), "credential refresh barrier was not reached");
                atomicConfig(path, base + "profile." + id + ".token=" + token + "\n");
                // The manager publishes this same atomic, private properties snapshot before returning credentials.
                var published = ProxyConfig.loadProfiles(path).get(id);
                assertNotNull(published, "new credential must already be visible in the source file");
                assertArrayEquals(ProxyConfig.digest(token.getBytes(StandardCharsets.US_ASCII)), published.tokenDigest());
                var acceptedClient = new java.util.concurrent.CompletableFuture<io.netty.channel.Channel>();
                var listener = (io.netty.channel.Channel) privateField(proxy, "listener");
                listener.eventLoop().submit(() -> listener.pipeline().addFirst(new io.netty.channel.ChannelInboundHandlerAdapter() {
                    @Override public void channelRead(io.netty.channel.ChannelHandlerContext context, Object message) {
                        context.fireChannelRead(message);
                        if (message instanceof io.netty.channel.Channel child) acceptedClient.complete(child);
                    }
                })).sync();
                try (Socket socket = client(proxy)) {
                    var channel = acceptedClient.get(2, TimeUnit.SECONDS);
                    Object front = channel.eventLoop().submit(() -> channel.pipeline().get("front")).get(2, TimeUnit.SECONDS);
                    var requestState = new java.util.concurrent.CompletableFuture<String>();
                    channel.eventLoop().submit(() -> channel.pipeline().addBefore("front", "resume-refresh", new io.netty.channel.ChannelInboundHandlerAdapter() {
                        @Override public void channelRead(io.netty.channel.ChannelHandlerContext context, Object message) throws Exception {
                            context.fireChannelRead(message);
                            if (message instanceof io.netty.handler.codec.http.HttpRequest) {
                                requestState.complete(privateField(front, "state").toString());
                                if (scenario == AuthRefresh.BETWEEN_READS || scenario == AuthRefresh.DURING_READ || scenario == AuthRefresh.INVALID) resume.countDown();
                            }
                        }
                        @Override public void channelReadComplete(io.netty.channel.ChannelHandlerContext context) throws Exception {
                            context.fireChannelReadComplete();
                            // Force reads beyond normal backpressure to exercise the hard byte bound.
                            if (scenario == AuthRefresh.BODY_LIMIT && privateField(front, "state").toString().equals("AUTHENTICATING")) context.read();
                        }
                    })).sync();
                    String body = scenario == AuthRefresh.BODY_LIMIT ? "x".repeat(73728) : "new-device-upload";
                    String authorization = scenario == AuthRefresh.MALFORMED ? "Proxy-Authorization: Basic not-base64!\r\n"
                            : auth(id, scenario == AuthRefresh.INVALID ? "wrong-token-" + "b".repeat(32) : token);
                    socket.getOutputStream().write(("POST http://" + HOST + "/ HTTP/1.1\r\nHost: " + HOST + "\r\n" + authorization + "Content-Length: " + body.length() + "\r\n\r\n" + body).getBytes(StandardCharsets.US_ASCII));
                    assertEquals(scenario == AuthRefresh.MALFORMED ? "CLOSED" : "AUTHENTICATING", requestState.get(2, TimeUnit.SECONDS));
                    if (scenario == AuthRefresh.SHUTDOWN) proxy.close();
                    String response = new String(socket.getInputStream().readAllBytes(), StandardCharsets.ISO_8859_1);
                    if (scenario == AuthRefresh.BETWEEN_READS || scenario == AuthRefresh.DURING_READ) {
                        assertTrue(response.startsWith("HTTP/1.1 200"), "newly published credential rejected before the next refresh: " + response);
                        assertTrue(response.endsWith("fixture-ok"), response);
                        assertEquals(1, tor.seen.size(), "the single client request must reach Tor once");
                        assertEquals(new HmacPartition(KEY).forProfile(id), tor.seen.getFirst().username);
                        assertArrayEquals(body.getBytes(StandardCharsets.US_ASCII), tor.seen.getFirst().body);
                    } else {
                        assertTrue(scenario == AuthRefresh.SHUTDOWN ? response.isEmpty()
                                : response.startsWith(scenario == AuthRefresh.BODY_LIMIT ? "HTTP/1.1 413" : "HTTP/1.1 407"), response);
                        assertTrue(tor.seen.isEmpty());
                    }
                    channel.closeFuture().sync();
                    assertNull(privateField(front, "authenticationRequest"));
                    assertNull(privateField(front, "setupTimeout"));
                    assertTrue(((java.util.Deque<?>) privateField(front, "pending")).isEmpty());
                }
            } finally { resume.countDown(); }
        } finally { java.nio.file.Files.deleteIfExists(path);java.nio.file.Files.deleteIfExists(directory); }
    }

    @Test void addingDeviceThenRevokingLastDeviceDuringSetupDoesNotNeedRestart() throws Exception {
        FakeTor tor = tor(Mode.HANG);var directory = java.nio.file.Files.createTempDirectory("stargate-pending-revoke");
        var path = directory.resolve("proxy.properties");String base = "listen.port=0\ntor.port=" + tor.listener.getLocalPort() + "\nisolation.key=" + "00".repeat(32) + "\n";
        atomicConfig(path, base);
        try (ProxyServer proxy = new ProxyServer(ProxyConfig.load(path), path).start()) {
            assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).startsWith("HTTP/1.1 407"));
            atomicConfig(path, base + "profile.browser.token=" + TOKEN + "\n");
            try (Socket socket = client(proxy)) {
                // Wait for the local snapshot, without making a real-network request or restarting.
                long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(3);
                while (System.nanoTime() < deadline && !tor.accepted.await(50, TimeUnit.MILLISECONDS)) {
                    try (Socket attempt = client(proxy)) {
                        attempt.setSoTimeout(80);attempt.getOutputStream().write(request("http://" + HOST + "/", HOST, "").getBytes(StandardCharsets.US_ASCII));
                        try { headers(attempt.getInputStream()); } catch (java.net.SocketTimeoutException expectedPendingSetup) { }
                    }
                }
                assertTrue(tor.accepted.await(1, TimeUnit.SECONDS));
                socket.getOutputStream().write(request("http://" + HOST + "/", HOST, "").getBytes(StandardCharsets.US_ASCII));
                Thread.sleep(80);atomicConfig(path, base);
                assertEquals(-1, socket.getInputStream().read());
                assertTrue(exchange(proxy, request("http://" + HOST + "/", HOST, "")).startsWith("HTTP/1.1 407"));
            }
        } finally { java.nio.file.Files.deleteIfExists(path);java.nio.file.Files.deleteIfExists(directory); }
    }
    @Test void revocationClosesAnIncompleteHttpUpload() throws Exception {
        FakeTor tor = tor(Mode.HTTP);var directory = java.nio.file.Files.createTempDirectory("stargate-upload-revoke");
        var path = directory.resolve("proxy.properties");String base = "listen.port=0\ntor.port=" + tor.listener.getLocalPort() + "\nisolation.key=" + "00".repeat(32) + "\n";
        atomicConfig(path, base + "profile.browser.token=" + TOKEN + "\n");
        try (ProxyServer proxy = new ProxyServer(ProxyConfig.load(path), path).start(); Socket socket = client(proxy)) {
            socket.getOutputStream().write(("POST http://" + HOST + "/upload HTTP/1.1\r\nHost: " + HOST + "\r\n" + auth("browser", TOKEN) + "Content-Length: 1000000\r\n\r\nx").getBytes(StandardCharsets.US_ASCII));
            assertTrue(tor.accepted.await(2, TimeUnit.SECONDS));
            atomicConfig(path, base);assertEquals(-1, socket.getInputStream().read());assertTrue(tor.closed.await(2, TimeUnit.SECONDS));
        } finally { java.nio.file.Files.deleteIfExists(path);java.nio.file.Files.deleteIfExists(directory); }
    }

    private static void atomicConfig(java.nio.file.Path path, String text) throws Exception {
        var temporary = java.nio.file.Files.createTempFile(path.getParent(), "snapshot", ".tmp");
        java.nio.file.Files.writeString(temporary, text);
        java.nio.file.Files.setPosixFilePermissions(temporary, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        java.nio.file.Files.move(temporary, path, java.nio.file.StandardCopyOption.ATOMIC_MOVE, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    enum Mode { HTTP, SLOW_HTTP, GZIP_RESPONSE, ECHO, REFUSE, HANG, ACK_HANG, UPGRADE }
    static class Seen { int atyp, port;String username, password, host, http;byte[] body; }
    static class FakeTor implements AutoCloseable {
        final ServerSocket listener;
        final List<Seen> seen = new CopyOnWriteArrayList<>();
        final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
        final CountDownLatch accepted = new CountDownLatch(1), closed = new CountDownLatch(1);
        final CountDownLatch hangingInput = new CountDownLatch(1), hangingPeerClosed = new CountDownLatch(1);
        final java.util.concurrent.ExecutorService threads = Executors.newVirtualThreadPerTaskExecutor();
        final Mode mode;
        final boolean noAuth;
        FakeTor(Mode mode) throws IOException {
            this(mode, false);
        }
        FakeTor(Mode mode, boolean noAuth) throws IOException { this(mode, noAuth, 0); }
        FakeTor(Mode mode, boolean noAuth, int port) throws IOException {
            this.mode = mode;this.noAuth = noAuth;
            listener = new ServerSocket(port, 20, java.net.InetAddress.getLoopbackAddress());
            threads.submit(() -> {
                while (!listener.isClosed()) {
                    try { Socket socket = listener.accept();sockets.add(socket);threads.submit(() -> serve(socket)); }
                    catch (IOException e) { break; }
                }
            });
        }
        private void serve(Socket socket) {
            accepted.countDown();
            try (socket) {
                socket.setSoTimeout(mode == Mode.HANG ? 15000 : 4000);InputStream in = socket.getInputStream();OutputStream out = socket.getOutputStream();
                if (mode == Mode.HANG) {
                    if (in.read() != -1) {
                        hangingInput.countDown();while (in.read() != -1) {}
                        hangingPeerClosed.countDown(); // EOF, not a socket timeout or local teardown.
                    }
                    return;
                }
                if (mode == Mode.SLOW_HTTP) try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt();return; }
                assertEquals(5, in.read());byte[] methods = in.readNBytes(in.read());
                boolean auth = false;for (byte m : methods) if (m == 2) auth = true;
                Seen s = new Seen();
                if (noAuth) { assertFalse(auth);assertArrayEquals(new byte[]{0}, methods);out.write(new byte[]{5,0}); }
                else {
                    if (!auth) throw new IOException("no isolation authentication offered");
                    out.write(new byte[]{5,2});assertEquals(1,in.read());
                    s.username = new String(in.readNBytes(in.read()), StandardCharsets.US_ASCII);s.password = new String(in.readNBytes(in.read()), StandardCharsets.US_ASCII);out.write(new byte[]{1,0});
                }
                assertEquals(5,in.read());assertEquals(1,in.read());in.read();s.atyp=in.read();assertEquals(3,s.atyp);
                s.host=new String(in.readNBytes(in.read()),StandardCharsets.US_ASCII);s.port=(in.read()<<8)|in.read();seen.add(s);
                out.write(new byte[]{5,(byte)(mode==Mode.REFUSE?5:0),0,1,0,0,0,0,0,0});
                if (mode == Mode.REFUSE) return;
                if (mode == Mode.ACK_HANG) { while (in.read() != -1) {} return; }
                if (mode == Mode.HTTP || mode == Mode.SLOW_HTTP || mode == Mode.GZIP_RESPONSE || mode == Mode.UPGRADE) {
                    s.http = headers(in);
                    if (mode == Mode.UPGRADE) out.write(("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    else {
                        int length = s.http.lines().filter(l -> l.toLowerCase().startsWith("content-length:")).mapToInt(l -> Integer.parseInt(l.split(":",2)[1].trim())).findFirst().orElse(0);
                        s.body = in.readNBytes(length);
                        if (mode == Mode.GZIP_RESPONSE) {
                            var encoded = new ByteArrayOutputStream();
                            try (var gzip = new java.util.zip.GZIPOutputStream(encoded)) { gzip.write("fixture-ok".getBytes(StandardCharsets.US_ASCII)); }
                            byte[] data = encoded.toByteArray();
                            out.write(("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nConnection: close\r\n\r\n" + Integer.toHexString(data.length) + "\r\n").getBytes(StandardCharsets.US_ASCII));out.write(data);out.write("\r\n0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
                        } else out.write("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfixture-ok".getBytes(StandardCharsets.US_ASCII));
                        return;
                    }
                }
                byte[] buffer = new byte[8192];int n;while ((n=in.read(buffer))!=-1) out.write(buffer,0,n);
            } catch (IOException e) { /* Closing or refusing a test stream is expected. */ }
            finally { sockets.remove(socket);closed.countDown(); }
        }
        @Override public void close() throws Exception {
            listener.close();for (Socket socket : sockets) socket.close();threads.close();
        }
    }
}
