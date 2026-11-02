// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;
import java.util.Set;
import java.util.Map;
import java.util.HashMap;

record ManagerSettings(Path proxyFile, String unit, String token, InetSocketAddress proxy,
                       InetSocketAddress socks, InetSocketAddress control, Path cookie, Map<String, String> profileTokens,
                       Path controlSocket, String origin, int publicProxyPort, Path metrics,
                       InetSocketAddress i2pSocks, InetSocketAddress i2pControl, Path i2pPassword, Path i2pCertificate, InetSocketAddress nymSocks, String publicOrigin, int remoteProxyPort, Path releaseSnapshot, long releaseMaxAge, Path consumerSnapshot, long consumerMaxAge, Path upgradeDirectory) {
    static ManagerSettings load(Path file) throws IOException {
        Properties p = privateProperties(file);
        Set<String> keys = Set.of("proxy.unit", "proxy.config", "manager.token", "tor.control.host", "tor.control.port", "tor.cookie",
                "proxy.control.socket", "manager.origin", "proxy.public.port", "i2p.control.host", "i2p.control.port", "i2p.password", "i2p.certificate", "manager.public.origin", "proxy.remote.port", "release.snapshot", "release.max-age-seconds", "consumer.snapshot", "consumer.max-age-seconds", "upgrade.directory");
        if (!keys.containsAll(p.stringPropertyNames())) throw new IllegalArgumentException("UNKNOWN_MANAGER_KEY");
        String unit = p.getProperty("proxy.unit", "stargate-v2-proxy.service");
        if (!unit.matches("stargate-v2-proxy(?:-[a-z0-9-]{1,48})?\\.service"))
            throw new IllegalArgumentException("INVALID_PROXY_UNIT");
        String token = required(p, "manager.token");
        if (!token.matches("[A-Za-z0-9_-]{43,128}")) throw new IllegalArgumentException("INVALID_MANAGER_TOKEN");
        Path proxyFile = Path.of(required(p, "proxy.config"));
        if (!proxyFile.isAbsolute()) throw new IllegalArgumentException("PROXY_CONFIG_MUST_BE_ABSOLUTE");
        Properties proxy = privateProperties(proxyFile);
        Map<String, String> profiles = new HashMap<>();
        for (String name : proxy.stringPropertyNames()) {
            if (name.startsWith("profile.") && name.endsWith(".token")) {
                String id = name.substring(8, name.length() - 6), credential = proxy.getProperty(name);
                if (!id.matches("[A-Za-z0-9_-]{1,64}") || !credential.matches("[A-Za-z0-9_-]{32,128}"))
                    throw new IllegalArgumentException("INVALID_PROXY_PROFILE");
                profiles.put(id, credential);
            }
        }
        boolean container = proxy.getProperty("network.mode", "local").equals("container");
        InetSocketAddress listen = endpoint(proxy, "listen", 8881, container);
        if (listen.getAddress().isAnyLocalAddress()) listen = new InetSocketAddress("127.0.0.1", listen.getPort());
        InetSocketAddress socks = endpoint(proxy, "tor", 9050, container);
        Properties control = new Properties();
        control.setProperty("control.host", p.getProperty("tor.control.host", "127.0.0.1"));
        control.setProperty("control.port", required(p, "tor.control.port"));
        Path cookie = Path.of(required(p, "tor.cookie"));
        if (!cookie.isAbsolute()) throw new IllegalArgumentException("COOKIE_PATH_MUST_BE_ABSOLUTE");
        Path socket = p.containsKey("proxy.control.socket") ? Path.of(p.getProperty("proxy.control.socket")) : null;
        if (socket != null && (!container || !socket.isAbsolute())) throw new IllegalArgumentException("INVALID_CONTROL_SOCKET");
        String origin = p.getProperty("manager.origin");
        if (origin != null && !origin.matches("http://127\\.0\\.0\\.1:[1-9][0-9]{0,4}")) throw new IllegalArgumentException("INVALID_MANAGER_ORIGIN");
        if (origin != null && java.net.URI.create(origin).getPort() > 65535) throw new IllegalArgumentException("INVALID_MANAGER_PORT");
        int publicPort = Integer.parseInt(p.getProperty("proxy.public.port", Integer.toString(listen.getPort())));
        if (publicPort < 1 || publicPort > 65535) throw new IllegalArgumentException("INVALID_PROXY_PORT");
        Path metrics = proxy.containsKey("metrics.path") ? Path.of(proxy.getProperty("metrics.path")) : null;
        if (metrics != null && !metrics.isAbsolute()) throw new IllegalArgumentException("INVALID_METRICS_PATH");
        boolean i2p = proxy.containsKey("i2p.host") || proxy.containsKey("i2p.port");
        Path password = p.containsKey("i2p.password") ? Path.of(p.getProperty("i2p.password")) : null;
        Path certificate = p.containsKey("i2p.certificate") ? Path.of(p.getProperty("i2p.certificate")) : null;
        if ((password != null && !password.isAbsolute()) || (certificate != null && !certificate.isAbsolute()))
            throw new IllegalArgumentException("I2P_PATHS_MUST_BE_ABSOLUTE");
        String publicOrigin = p.getProperty("manager.public.origin");
        int remotePort = Integer.parseInt(p.getProperty("proxy.remote.port", "443"));
        if (remotePort < 1 || remotePort > 65535) throw new IllegalArgumentException("INVALID_REMOTE_PROXY_PORT");
        if (publicOrigin != null) {
            var uri = java.net.URI.create(publicOrigin);
            String host = uri.getHost();
            if (!"https".equals(uri.getScheme()) || host == null || host.length()>253 || !host.equals(host.toLowerCase(java.util.Locale.ROOT))
                    || !java.util.Arrays.stream(host.split("\\.",-1)).allMatch(label -> label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
                    || host.endsWith(".onion") || host.endsWith(".i2p") || uri.getRawUserInfo()!=null || uri.getRawQuery()!=null || uri.getRawFragment()!=null
                    || !uri.getRawPath().isEmpty() || uri.getPort()==0 || uri.getPort()>65535 || uri.getPort()==443
                    || !publicOrigin.equals("https://"+host+(uri.getPort()==-1?"":":"+uri.getPort())))
                throw new IllegalArgumentException("INVALID_PUBLIC_ORIGIN");
            if (!proxy.containsKey("tls.port") || !proxy.containsKey("tls.certificate") || !proxy.containsKey("tls.key"))
                throw new IllegalArgumentException("PUBLIC_ACCESS_REQUIRES_PROXY_TLS");
        } else if (p.containsKey("proxy.remote.port")) throw new IllegalArgumentException("PUBLIC_ORIGIN_REQUIRED");
        Path releaseSnapshot = null; long releaseMaxAge = 0;
        if (p.containsKey("release.snapshot") || p.containsKey("release.max-age-seconds")) {
            releaseSnapshot = Path.of(required(p, "release.snapshot"));
            String age = required(p, "release.max-age-seconds");
            if (!releaseSnapshot.isAbsolute() || !age.matches("[1-9][0-9]{0,7}")) throw new IllegalArgumentException("INVALID_RELEASE_MONITOR");
            releaseMaxAge = Long.parseLong(age);
            if (releaseMaxAge > 31536000) throw new IllegalArgumentException("INVALID_RELEASE_MONITOR");
        }
        Path consumerSnapshot = null; long consumerMaxAge = 0;
        if (p.containsKey("consumer.snapshot") || p.containsKey("consumer.max-age-seconds")) {
            consumerSnapshot = Path.of(required(p, "consumer.snapshot"));
            String age = required(p, "consumer.max-age-seconds");
            if (!consumerSnapshot.isAbsolute() || !age.matches("[1-9][0-9]{0,7}")) throw new IllegalArgumentException("INVALID_CONSUMER_MONITOR");
            consumerMaxAge = Long.parseLong(age);
            if (consumerMaxAge > 31536000) throw new IllegalArgumentException("INVALID_CONSUMER_MONITOR");
        }
        Path upgrades=p.containsKey("upgrade.directory")?Path.of(required(p,"upgrade.directory")):null;
        if(upgrades!=null&&!upgrades.isAbsolute())throw new IllegalArgumentException("INVALID_UPGRADE_DIRECTORY");
        return new ManagerSettings(proxyFile, unit, token, listen, socks, endpoint(control, "control", 0, container), cookie, Map.copyOf(profiles), socket, origin, publicPort, metrics,
                i2p ? endpoint(proxy, "i2p", 4447, container) : null,
                p.containsKey("i2p.control.port") ? endpoint(p, "i2p.control", 7650, container) : null, password, certificate,
                proxy.getProperty("nym.enabled", "false").equals("true") ? endpoint(proxy, "nym", 1080, container) : null, publicOrigin, remotePort, releaseSnapshot, releaseMaxAge, consumerSnapshot, consumerMaxAge, upgrades);
    }

    private static final int MAX_CONFIGURATION_BYTES = 262144;

    static Properties privateProperties(Path path) throws IOException {
        if (!Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS))
            throw new IOException("CONFIGURATION_MUST_BE_REGULAR_FILE");
        for (var permission : Files.getPosixFilePermissions(path, java.nio.file.LinkOption.NOFOLLOW_LINKS))
            if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_"))
                throw new IllegalArgumentException("CONFIGURATION_MUST_BE_PRIVATE");
        byte[] bytes;
        try (var channel = java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ, java.nio.file.LinkOption.NOFOLLOW_LINKS);
             var input = java.nio.channels.Channels.newInputStream(channel)) {
            bytes = input.readNBytes(MAX_CONFIGURATION_BYTES + 1);
        }
        if (bytes.length > MAX_CONFIGURATION_BYTES) throw new IOException("CONFIGURATION_TOO_LARGE");
        Properties properties = new Properties();
        try (var input = new java.io.ByteArrayInputStream(bytes);
             var reader = java.nio.channels.Channels.newReader(java.nio.channels.Channels.newChannel(input), StandardCharsets.UTF_8)) {
            properties.load(reader);
        }
        return properties;
    }

    private static InetSocketAddress endpoint(Properties p, String prefix, int defaultPort, boolean container) throws IOException {
        String host = p.getProperty(prefix + ".host", "127.0.0.1");
        int port = Integer.parseInt(p.getProperty(prefix + ".port", Integer.toString(defaultPort)));
        if (port < 1 || port > 65535) throw new IllegalArgumentException("INVALID_ENDPOINT_PORT");
        if (container) {
            var endpoint = new InetSocketAddress(host, port);
            if (endpoint.isUnresolved() && Set.of("tor", "i2p", "nym").contains(host)) return endpoint;
            if (endpoint.isUnresolved() || !(endpoint.getAddress().isLoopbackAddress() || endpoint.getAddress().isAnyLocalAddress()
                    || endpoint.getAddress().isSiteLocalAddress())) throw new IllegalArgumentException("ENDPOINT_MUST_BE_PRIVATE");
            return endpoint;
        }
        byte[] address;
        if (host.equals("127.0.0.1")) address = new byte[]{127, 0, 0, 1};
        else if (host.equals("::1")) { address = new byte[16]; address[15] = 1; }
        else throw new IllegalArgumentException("ENDPOINT_MUST_BE_NUMERIC_LOOPBACK");
        return new InetSocketAddress(InetAddress.getByAddress(address), port);
    }

    public InetSocketAddress nymSocks() { return fresh(nymSocks); }
    public InetSocketAddress socks() { return fresh(socks); }
    public InetSocketAddress control() { return fresh(control); }
    public InetSocketAddress i2pSocks() { return fresh(i2pSocks); }
    public InetSocketAddress i2pControl() { return fresh(i2pControl); }
    private InetSocketAddress fresh(InetSocketAddress address) {
        if (address == null) return null;
        return controlSocket == null ? address : new InetSocketAddress(address.getHostString(), address.getPort());
    }

    private static String required(Properties p, String key) {
        String value = p.getProperty(key);
        if (value == null || value.isBlank()) throw new IllegalArgumentException("MISSING_MANAGER_SETTING");
        return value;
    }
}
