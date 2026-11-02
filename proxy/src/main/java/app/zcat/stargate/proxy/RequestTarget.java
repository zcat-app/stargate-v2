// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpRequest;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

record RequestTarget(String host, int port, String originForm, boolean tunnel) {
    static RequestTarget parse(HttpRequest request) {
        try {
            boolean tunnel = request.method().equals(HttpMethod.CONNECT);
            URI uri = new URI(tunnel ? "http://" + request.uri() : request.uri());
            if (uri.getHost() == null || uri.getRawUserInfo() != null || uri.getRawFragment() != null
                    || !uri.getScheme().equalsIgnoreCase("http")) throw new IllegalArgumentException();
            if (tunnel && (!uri.getRawPath().isEmpty() || uri.getRawQuery() != null || uri.getPort() < 1))
                throw new IllegalArgumentException();
            String host = canonical(uri.getHost());
            int port = uri.getPort() == -1 ? 80 : uri.getPort();
            if (port < 1 || port > 65535) throw new IllegalArgumentException();
            var hosts = request.headers().getAll(HttpHeaderNames.HOST);
            if (hosts.size() != 1) throw new IllegalArgumentException();
            URI declared = new URI("http://" + hosts.getFirst());
            int declaredPort = declared.getPort() == -1 ? (tunnel ? 443 : 80) : declared.getPort();
            if (declared.getHost() == null || declared.getRawUserInfo() != null
                    || !declared.getRawPath().isEmpty() || declared.getRawQuery() != null
                    || declared.getRawFragment() != null || !canonical(declared.getHost()).equals(host)
                    || declaredPort != port) throw new IllegalArgumentException();
            String path = uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
            if (uri.getRawQuery() != null) path += "?" + uri.getRawQuery();
            return new RequestTarget(host, port, path, tunnel);
        } catch (URISyntaxException | NullPointerException e) { throw new IllegalArgumentException("invalid proxy target"); }
    }

    boolean onion() { return host.endsWith(".onion"); }
    boolean i2p() { return host.endsWith(".i2p"); }
    // No local DNS or public-suffix database. Exit policy also applies after remote resolution.
    boolean publicWeb() {
        if (onion() || i2p() || !host.contains(".")) return false;
        String last = host.substring(host.lastIndexOf('.') + 1);
        if (!last.matches("[a-z][a-z0-9-]*")) return false;
        for (String suffix : java.util.List.of("localhost", "local", "internal", "home.arpa", "invalid", "test", "example", "onion", "i2p"))
            if (host.equals(suffix) || host.endsWith("." + suffix)) return false;
        return true;
    }
    String authority() { return host + ":" + port; }

    private static String canonical(String host) {
        host = host.toLowerCase(Locale.ROOT);
        while (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        if (host.isEmpty() || host.length() > 253) throw new IllegalArgumentException();
        for (String label : host.split("\\.", -1))
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) throw new IllegalArgumentException();
        return host;
    }
}
