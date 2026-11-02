// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Advisory health semantics adapted from v1 SidecarMonitor; no inferred Tor lifecycle. */
final class TorProbe {
    enum Health { READY, NOT_READY, UNAVAILABLE }
    record Observation(Health readiness, String control, String code, Integer bootstrapPercent,
                       Boolean circuitEstablished, Boolean networkDisabled, Boolean socksEndpointMatches,
                       Long processId, String version, SocketProbe.Observation socks) {}
    private static final String SERVER = "Tor safe cookie authentication server-to-controller hash";
    private static final String CLIENT = "Tor safe cookie authentication controller-to-server hash";
    private static final Pattern PROGRESS = Pattern.compile("(?:^| )PROGRESS=(\\d{1,3})(?: |$)");
    private static final HexFormat HEX = HexFormat.of();

    static Observation sample(InetSocketAddress control, Path cookieFile, InetSocketAddress socksAddress) {
        SocketProbe.Observation socks = SocketProbe.socks(socksAddress);
        try {
            if (!Files.isRegularFile(cookieFile)) throw new IOException("COOKIE_UNAVAILABLE");
            byte[] cookie;
            try (var input = Files.newInputStream(cookieFile)) { cookie = input.readNBytes(33); }
            if (cookie.length != 32) throw new IOException("INVALID_COOKIE");
            try (Socket connection = SocketProbe.connect(control, 1200)) {
                connection.setSoTimeout(1200);
                byte[] nonce = new byte[32];new SecureRandom().nextBytes(nonce);
                String challenge = command(connection, "AUTHCHALLENGE SAFECOOKIE " + HEX.formatHex(nonce)).getFirst();
                Map<String, String> fields = fields(challenge.substring("AUTHCHALLENGE ".length()));
                byte[] serverNonce = HEX.parseHex(fields.get("SERVERNONCE"));
                byte[] serverHash = HEX.parseHex(fields.get("SERVERHASH"));
                if (serverNonce.length != 32 || serverHash.length != 32) throw new IOException("INVALID_CHALLENGE");
                byte[] message = new byte[96];
                System.arraycopy(cookie, 0, message, 0, 32);System.arraycopy(nonce, 0, message, 32, 32);System.arraycopy(serverNonce, 0, message, 64, 32);
                Arrays.fill(cookie, (byte) 0);
                if (!MessageDigest.isEqual(serverHash, hmac(SERVER, message))) throw new IOException("SERVER_AUTH_FAILED");
                command(connection, "AUTHENTICATE " + HEX.formatHex(hmac(CLIENT, message)));
                Arrays.fill(message, (byte) 0);
                List<String> response = command(connection, "GETINFO status/bootstrap-phase status/circuit-established version process/pid net/listeners/socks");
                Map<String, String> info = new HashMap<>();
                for (String value : response) { int at = value.indexOf('=');if (at > 0) info.put(value.substring(0, at), value.substring(at + 1)); }
                var progress = PROGRESS.matcher(info.getOrDefault("status/bootstrap-phase", ""));
                if (!progress.find()) throw new IOException("MISSING_BOOTSTRAP");
                int percent = Integer.parseInt(progress.group(1));
                if (percent > 100) throw new IOException("INVALID_BOOTSTRAP");
                boolean circuit = flag(info.get("status/circuit-established"));
                String disabledValue = command(connection, "GETCONF DisableNetwork").getFirst();
                boolean disabled = flag(fields(disabledValue).get("DisableNetwork"));
                String expected = socksAddress.getAddress().getHostAddress() + ":" + socksAddress.getPort();
                if (socksAddress.getAddress() instanceof java.net.Inet6Address) expected = "[::1]:" + socksAddress.getPort();
                String listeners = info.getOrDefault("net/listeners/socks", "");
                var endpoints = List.of(listeners.replace("\"", "").split(" "));
                boolean matches = endpoints.contains(expected)
                        || (socksAddress.getAddress() instanceof java.net.Inet4Address && endpoints.contains("0.0.0.0:" + socksAddress.getPort()))
                        || (socksAddress.getAddress() instanceof java.net.Inet6Address && endpoints.contains("[::]:" + socksAddress.getPort()));
                boolean ready = percent == 100 && circuit && !disabled && matches && socks.state().equals("RESPONDING");
                String code = disabled ? "NETWORK_DISABLED" : !matches ? "SOCKS_ENDPOINT_MISMATCH" : percent < 100 ? "BOOTSTRAPPING" : !circuit ? "NO_ESTABLISHED_CIRCUIT" : !socks.state().equals("RESPONDING") ? "SOCKS_UNAVAILABLE" : "TOR_READY";
                return new Observation(ready ? Health.READY : Health.NOT_READY, "AUTHENTICATED", code,
                        percent, circuit, disabled, matches, Long.valueOf(info.get("process/pid")), info.get("version"), socks);
            }
        } catch (IOException | RuntimeException e) {
            return new Observation(Health.UNAVAILABLE, "UNAVAILABLE", "CONTROL_OBSERVATION_UNAVAILABLE", null, null, null, null, null, null, socks);
        }
    }

    static byte[] hmac(String key, byte[] message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.US_ASCII), "HmacSHA256"));
            return mac.doFinal(message);
        } catch (java.security.GeneralSecurityException e) { throw new IllegalStateException(e); }
    }

    private static Map<String, String> fields(String input) throws IOException {
        Map<String, String> fields = new HashMap<>();
        for (String field : input.split(" ")) {
            int at = field.indexOf('=');if (at > 0) fields.put(field.substring(0, at), field.substring(at + 1));
        }
        return fields;
    }
    private static boolean flag(String flag) throws IOException {
        if ("0".equals(flag)) return false;if ("1".equals(flag)) return true;throw new IOException("MISSING_BOOLEAN");
    }
    private static List<String> command(Socket socket, String command) throws IOException {
        socket.getOutputStream().write((command + "\r\n").getBytes(StandardCharsets.US_ASCII));
        List<String> result = new ArrayList<>();int left = 16384;
        for (int n = 0; n < 32; n++) {
            String line = SocketProbe.line(socket.getInputStream(), Math.min(4096, left));left -= line.length() + 2;
            if (line.length() < 4 || !line.startsWith("250") || (line.charAt(3) != '-' && line.charAt(3) != ' ')) throw new IOException("CONTROL_REPLY_FAILED");
            result.add(line.substring(4));if (line.charAt(3) == ' ') return result;
        }
        throw new IOException("CONTROL_REPLY_LIMIT");
    }
}
