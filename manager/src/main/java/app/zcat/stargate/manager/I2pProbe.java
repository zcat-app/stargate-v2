// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/** i2pd 3.0.0 I2PControl: pinned local TLS certificate, password and short-lived token. */
final class I2pProbe {
    record Observation(String readiness, String control, String code, Boolean sharedDestinationReady,
                       Long activePeers, Long inboundTunnels, Long outboundTunnels, String version,
                       SocketProbe.Observation socks, String destinationAccess) {}
    private static final ObjectMapper JSON = new ObjectMapper();

    static Observation sample(InetSocketAddress socksAddress, InetSocketAddress control, Path password,
                              Path certificate, TrafficStats.Observation traffic) {
        String access = "UNKNOWN";
        if (traffic != null && "CURRENT".equals(traffic.state()) && traffic.counters() != null)
            access = traffic.counters().i2pResponses() > 0 ? "OBSERVED_THIS_PROCESS" : "NOT_OBSERVED_THIS_PROCESS";
        if (socksAddress == null) return new Observation("UNAVAILABLE", "NOT_CONFIGURED", "I2P_NOT_CONFIGURED", null, null, null, null, null, null, access);
        var socks = SocketProbe.socks(socksAddress);
        try {
            if (control == null || password == null || certificate == null) throw new IOException();
            for (var permission : Files.getPosixFilePermissions(password))
                if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_")) throw new IOException();
            String secret;
            try (var input = Files.newInputStream(password)) { secret = new String(input.readNBytes(257), StandardCharsets.US_ASCII).trim(); }
            if (!secret.matches("[A-Za-z0-9_-]{43,128}")) throw new IOException();
            SSLContext tls = pinned(certificate);
            JsonNode auth = request(tls, control, "Authenticate", Map.of("API", 1, "Password", secret));
            String token = auth.path("Token").asText();
            if (token.isEmpty() || token.length() > 256) throw new IOException();
            Map<String, Object> fields = new LinkedHashMap<>();fields.put("Token", token);
            for (String field : new String[]{"i2p.router.status", "i2p.router.version", "i2p.router.netdb.activepeers",
                    "i2p.router.net.tunnels.inbound", "i2p.router.net.tunnels.outbound"}) fields.put(field, "");
            JsonNode info = request(tls, control, "RouterInfo", fields);
            boolean ready = flag(info, "i2p.router.status");
            long peers = number(info, "i2p.router.netdb.activepeers"), inbound = number(info, "i2p.router.net.tunnels.inbound"), outbound = number(info, "i2p.router.net.tunnels.outbound");
            String version = info.path("i2p.router.version").asText();
            if (!version.matches("[A-Za-z0-9.+_-]{1,64}")) throw new IOException();
            boolean available = ready && peers > 0 && inbound > 0 && outbound > 0 && socks.state().equals("RESPONDING");
            return new Observation(available ? "READY" : "NOT_READY", "AUTHENTICATED", available ? "I2P_TUNNELS_READY" : "I2P_TUNNELS_NOT_READY",
                    ready, peers, inbound, outbound, version, socks, access);
        } catch (Exception ignored) {
            return new Observation("UNAVAILABLE", "UNAVAILABLE", "I2P_CONTROL_OBSERVATION_UNAVAILABLE", null, null, null, null, null, socks, access);
        }
    }

    static SSLContext pinned(Path certificate) throws Exception {
        byte[] bytes;
        try (var input = Files.newInputStream(certificate)) { bytes = input.readNBytes(16385); }
        if (bytes.length > 16384) throw new CertificateException();
        X509Certificate expected = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(bytes));
        expected.checkValidity();
        byte[] pin = expected.getEncoded();
        var trust = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[]{expected}; }
            public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException { throw new CertificateException(); }
            public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                if (chain.length != 1 || !MessageDigest.isEqual(pin, chain[0].getEncoded())) throw new CertificateException();
                chain[0].checkValidity();
            }
        };
        SSLContext context = SSLContext.getInstance("TLS");context.init(null, new TrustManager[]{trust}, null);return context;
    }

    private static JsonNode request(SSLContext tls, InetSocketAddress endpoint, String method, Map<String, Object> params) throws IOException {
        // The underlying socket deadline also bounds slow TLS handshakes and partial HTTP replies.
        try (var raw = SocketProbe.connect(endpoint, 1800);
             var socket = (SSLSocket) tls.getSocketFactory().createSocket(raw, endpoint.getHostString(), endpoint.getPort(), true)) {
            socket.setSoTimeout(1800);socket.startHandshake();
            byte[] body = JSON.writeValueAsBytes(Map.of("jsonrpc", "2.0", "id", 1, "method", method, "params", params));
            socket.getOutputStream().write(("POST / HTTP/1.1\r\nHost: i2pcontrol\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: " + body.length + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().write(body);socket.getOutputStream().flush();
            var input = socket.getInputStream();
            if (!SocketProbe.line(input, 1024).equals("HTTP/1.1 200 OK")) throw new IOException();
            int length = -1, budget = 4096;
            for (String line; !(line = SocketProbe.line(input, Math.min(1024, budget))).isEmpty();) {
                budget -= line.length() + 2;
                if (line.toLowerCase(java.util.Locale.ROOT).startsWith("content-length:")) {
                    if (length != -1) throw new IOException();
                    length = Integer.parseInt(line.substring(15).trim());
                }
            }
            if (length < 0 || length > 16384) throw new IOException();
            byte[] reply = input.readNBytes(length);
            if (reply.length != length) throw new IOException();
            JsonNode value = JSON.readTree(reply);
            if (value.has("error") || !value.path("result").isObject() || value.path("id").asInt(-1) != 1) throw new IOException();
            return value.get("result");
        }
    }
    private static boolean flag(JsonNode info, String field) throws IOException {
        String value = info.path(field).asText();
        if (value.equals("1")) return true;if (value.equals("0")) return false;throw new IOException();
    }
    private static long number(JsonNode info, String field) throws IOException {
        String value = info.path(field).asText();
        if (!value.matches("[0-9]{1,12}")) throw new IOException();return Long.parseLong(value);
    }
}
