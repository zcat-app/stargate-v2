// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;

final class SocketProbe {
    private static final java.util.concurrent.ScheduledExecutorService DEADLINES = java.util.concurrent.Executors.newSingleThreadScheduledExecutor(
            task -> Thread.ofPlatform().daemon().name("status-probe-deadline").unstarted(task));
    private static final class TimedSocket extends Socket {
        private java.util.concurrent.ScheduledFuture<?> expiry;
        TimedSocket(int timeout) {
            expiry = DEADLINES.schedule(() -> { try { close(); } catch (IOException ignored) { } }, timeout, java.util.concurrent.TimeUnit.MILLISECONDS);
        }
        @Override public synchronized void close() throws IOException { if (expiry != null) expiry.cancel(false);super.close(); }
    }
    record Observation(String state, String code) {}

    static Observation proxy(InetSocketAddress address) {
        String host = "a".repeat(56) + ".onion";
        try (Socket socket = connect(address, 800)) {
            socket.getOutputStream().write(("GET http://" + host + "/manager-probe HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            String status = line(socket.getInputStream(), 1024);
            int remaining = 4096;
            boolean challenge = false;
            for (String header; !(header = line(socket.getInputStream(), remaining)).isEmpty();) {
                remaining -= header.length() + 2;
                challenge |= header.toLowerCase(java.util.Locale.ROOT).startsWith("proxy-authenticate: basic realm=\"stargate\"");
            }
            return status.startsWith("HTTP/1.1 407 ") && challenge
                    ? new Observation("RESPONDING", "PROXY_AUTH_CHALLENGE") : new Observation("UNEXPECTED", "UNEXPECTED_HTTP_RESPONSE");
        } catch (ConnectException e) { return new Observation("REFUSED", "CONNECTION_REFUSED"); }
        catch (SocketTimeoutException e) { return new Observation("UNAVAILABLE", "PROBE_TIMEOUT"); }
        catch (IOException e) { return new Observation("UNAVAILABLE", "PROBE_IO_FAILURE"); }
    }

    static Observation socks(InetSocketAddress address) {
        try (Socket socket = connect(address, 800)) {
            socket.getOutputStream().write(new byte[]{5, 1, 0});
            return socket.getInputStream().read() == 5 && socket.getInputStream().read() == 0
                    ? new Observation("RESPONDING", "SOCKS5_GREETING") : new Observation("UNEXPECTED", "UNEXPECTED_SOCKS_RESPONSE");
        } catch (ConnectException e) { return new Observation("REFUSED", "CONNECTION_REFUSED"); }
        catch (SocketTimeoutException e) { return new Observation("UNAVAILABLE", "PROBE_TIMEOUT"); }
        catch (IOException e) { return new Observation("UNAVAILABLE", "PROBE_IO_FAILURE"); }
    }

    static Socket connect(InetSocketAddress address, int timeout) throws IOException {
        Socket socket = new TimedSocket(timeout);
        try { socket.connect(address, timeout); socket.setSoTimeout(timeout); return socket; }
        catch (IOException e) { socket.close(); throw e; }
    }

    static String line(InputStream input, int limit) throws IOException {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        while (data.size() < limit) {
            int next = input.read();
            if (next == -1) throw new EOFException();
            if (next == '\n') {
                byte[] bytes = data.toByteArray();
                if (bytes.length == 0 || bytes[bytes.length - 1] != '\r') throw new IOException("INVALID_LINE");
                return new String(bytes, 0, bytes.length - 1, StandardCharsets.US_ASCII);
            }
            data.write(next);
        }
        throw new IOException("REPLY_LIMIT");
    }
}
