// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.io.IOException;
import java.io.Reader;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Properties;

public record ProxyConfig(InetSocketAddress listen, InetSocketAddress tor,
                          Map<String, Profile> profiles, int maxConnections,
                          int setupTimeoutMillis, int headerTimeoutMillis, boolean containerNetwork, Path metricsPath,
                          InetSocketAddress i2p, int i2pSetupTimeoutMillis, InetSocketAddress nym, int nymSetupTimeoutMillis,
                          Path i2pLifecycleDirectory, int i2pCooldownSeconds, RemoteTls.Settings tls) {
    public ProxyConfig(InetSocketAddress listen, InetSocketAddress tor, Map<String, Profile> profiles,
                       int maxConnections, int setupTimeoutMillis, int headerTimeoutMillis, boolean containerNetwork,
                       Path metricsPath, InetSocketAddress i2p, int i2pSetupTimeoutMillis, InetSocketAddress nym, int nymSetupTimeoutMillis,
                       Path i2pLifecycleDirectory, int i2pCooldownSeconds) {
        this(listen,tor,profiles,maxConnections,setupTimeoutMillis,headerTimeoutMillis,containerNetwork,metricsPath,
             i2p,i2pSetupTimeoutMillis,nym,nymSetupTimeoutMillis,i2pLifecycleDirectory,i2pCooldownSeconds,null);
    }
    public ProxyConfig(InetSocketAddress listen, InetSocketAddress tor, Map<String, Profile> profiles,
                       int maxConnections, int setupTimeoutMillis, int headerTimeoutMillis, boolean containerNetwork,
                       Path metricsPath, InetSocketAddress i2p, int i2pSetupTimeoutMillis, InetSocketAddress nym, int nymSetupTimeoutMillis) {
        this(listen,tor,profiles,maxConnections,setupTimeoutMillis,headerTimeoutMillis,containerNetwork,metricsPath,
             i2p,i2pSetupTimeoutMillis,nym,nymSetupTimeoutMillis,null,60);
    }
    public ProxyConfig(InetSocketAddress listen, InetSocketAddress tor, Map<String, Profile> profiles,
                       int maxConnections, int setupTimeoutMillis, int headerTimeoutMillis, boolean containerNetwork, Path metricsPath,
                       InetSocketAddress i2p, int i2pSetupTimeoutMillis) {
        this(listen, tor, profiles, maxConnections, setupTimeoutMillis, headerTimeoutMillis, containerNetwork, metricsPath, i2p, i2pSetupTimeoutMillis, null, 120000);
    }
    public ProxyConfig(InetSocketAddress listen, InetSocketAddress tor, Map<String, Profile> profiles,
                       int maxConnections, int setupTimeoutMillis, int headerTimeoutMillis, boolean containerNetwork, Path metricsPath) {
        this(listen, tor, profiles, maxConnections, setupTimeoutMillis, headerTimeoutMillis, containerNetwork, metricsPath, null, 120000);
    }
    public ProxyConfig(InetSocketAddress listen, InetSocketAddress tor, Map<String, Profile> profiles,
                       int maxConnections, int setupTimeoutMillis, int headerTimeoutMillis) {
        this(listen, tor, profiles, maxConnections, setupTimeoutMillis, headerTimeoutMillis, false, null);
    }
    public record Profile(byte[] tokenDigest, String partition, int i2pPort) {
        public Profile(byte[] tokenDigest, String partition) { this(tokenDigest, partition, -1); }
        public Profile { tokenDigest = tokenDigest.clone(); }
        @Override public byte[] tokenDigest() { return tokenDigest.clone(); }
        boolean sameCredential(Profile other) {
            return other != null && partition.equals(other.partition) && MessageDigest.isEqual(tokenDigest, other.tokenDigest);
        }
    }

    public ProxyConfig {
        if (tls != null && tls.port() == listen.getPort()) throw new IllegalArgumentException("TLS_PORT_MUST_BE_DISTINCT");
        if (listen.isUnresolved() || !privateUpstream(tor, containerNetwork)
                || (!listen.getAddress().isLoopbackAddress() && !(containerNetwork && listen.getAddress().isAnyLocalAddress())))
            throw new IllegalArgumentException("listeners and Tor must use numeric loopback addresses");
        if (metricsPath != null && !metricsPath.isAbsolute()) throw new IllegalArgumentException("metrics path must be absolute");
        if (i2p != null && !privateUpstream(i2p, containerNetwork))
            throw new IllegalArgumentException("I2P must use a loopback or explicit container endpoint");
        if (nym != null && !privateUpstream(nym, containerNetwork))
            throw new IllegalArgumentException("Nym must use a private endpoint");
        if (i2pLifecycleDirectory != null && (!i2pLifecycleDirectory.isAbsolute() || i2p == null || i2pCooldownSeconds < 1 || i2pCooldownSeconds > 3600))
            throw new IllegalArgumentException("invalid I2P lifecycle configuration");
        profiles = Map.copyOf(profiles);
        if (maxConnections < 1 || setupTimeoutMillis < 1 || headerTimeoutMillis < 1 || i2pSetupTimeoutMillis < 1 || nymSetupTimeoutMillis < 1)
            throw new IllegalArgumentException("invalid proxy limits or profiles");
    }

    private static boolean privateUpstream(InetSocketAddress endpoint, boolean container) {
        if (endpoint.getPort() == 0) return false;
        if (endpoint.isUnresolved()) return container && java.util.Set.of("tor", "i2p", "nym").contains(endpoint.getHostString());
        return endpoint.getAddress().isLoopbackAddress() || (container && endpoint.getAddress().isSiteLocalAddress());
    }

    static Properties read(Path path) throws IOException {
        if (!Files.isRegularFile(path, java.nio.file.LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 262144)
            throw new IOException("INVALID_CONFIGURATION_FILE");
        for (PosixFilePermission permission : Files.getPosixFilePermissions(path)) {
            if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_"))
                throw new IllegalArgumentException("configuration file permissions must be 0600 or stricter");
        }
        Properties p = new Properties();
        try (var channel = java.nio.channels.FileChannel.open(path, java.nio.file.StandardOpenOption.READ, java.nio.file.LinkOption.NOFOLLOW_LINKS);
             Reader reader = java.nio.channels.Channels.newReader(channel, StandardCharsets.UTF_8)) { p.load(reader); }
        return p;
    }

    static Map<String, Profile> loadProfiles(Path path) throws IOException { return profiles(read(path)); }

    static Map<String, Profile> profiles(Properties p) {
        HmacPartition partitions = new HmacPartition(HexFormat.of().parseHex(required(p, "isolation.key")));
        Map<String, Profile> profiles = new HashMap<>();
        String isolated = p.getProperty("i2p.deviceIsolation", "false");
        if (!isolated.equals("true") && !isolated.equals("false")) throw new IllegalArgumentException("invalid I2P isolation setting");
        var ports = new java.util.HashSet<Integer>();
        for (String name : p.stringPropertyNames()) {
            if (name.startsWith("profile.") && name.endsWith(".token")) {
                String id = name.substring(8, name.length() - 6);
                String token = p.getProperty(name);
                if (!id.matches("[A-Za-z0-9_-]{1,64}") || !token.matches("[A-Za-z0-9_-]{32,128}"))
                    throw new IllegalArgumentException("invalid profile id or token format");
                int port = isolated.equals("true") ? integer(p, "profile." + id + ".i2pPort", 0) : -1;
                if (port > 0 && (port < 14447 || port > 65535 || !ports.add(port))) throw new IllegalArgumentException("invalid I2P device port");
                if (isolated.equals("true") && port < 0) throw new IllegalArgumentException("invalid I2P device port");
                String enabled = p.getProperty("profile." + id + ".i2pEnabled", "true");
                if (!enabled.equals("true") && !enabled.equals("false")) throw new IllegalArgumentException("invalid I2P device setting");
                profiles.put(id, new Profile(digest(token.getBytes(StandardCharsets.US_ASCII)), partitions.forProfile(id), isolated.equals("true") && enabled.equals("false") ? 0 : port));
            } else if (!name.matches("tls\\.(port|certificate|key)|profile\\.[A-Za-z0-9_-]{1,64}\\.(i2pPort|i2pEnabled)|listen\\.(host|port)|tor\\.(host|port)|i2p\\.(host|port|deviceIsolation|nextPort|lifecycleDirectory|cooldownSeconds)|i2pSetupTimeoutMillis|nym\\.(enabled|host|port)|nymSetupTimeoutMillis|isolation\\.key|maxConnections|setupTimeoutMillis|headerTimeoutMillis|network\\.mode|metrics\\.path")) {
                throw new IllegalArgumentException("unknown configuration key");
            }
        }
        return Map.copyOf(profiles);
    }

    public static ProxyConfig load(Path path) throws IOException {
        Properties p = read(path);
        Map<String, Profile> profiles = profiles(p);
        String mode = p.getProperty("network.mode", "local");
        if (!mode.equals("local") && !mode.equals("container")) throw new IllegalArgumentException("invalid network mode");
        boolean container = mode.equals("container");
        String nymEnabled = p.getProperty("nym.enabled", "false");
        if (!nymEnabled.equals("true") && !nymEnabled.equals("false")) throw new IllegalArgumentException("invalid Nym enable setting");
        return new ProxyConfig(endpoint(p.getProperty("listen.host", "127.0.0.1"), integer(p, "listen.port", 8881), container),
                endpoint(p.getProperty("tor.host", "127.0.0.1"), integer(p, "tor.port", 9050), container), profiles,
                integer(p, "maxConnections", 128), integer(p, "setupTimeoutMillis", 60000),
                integer(p, "headerTimeoutMillis", 10000), container, p.containsKey("metrics.path") ? Path.of(p.getProperty("metrics.path")) : null,
                p.containsKey("i2p.host") || p.containsKey("i2p.port")
                        ? endpoint(p.getProperty("i2p.host", "127.0.0.1"), integer(p, "i2p.port", 4447), container) : null,
                integer(p, "i2pSetupTimeoutMillis", 120000),
                nymEnabled.equals("true") ? endpoint(p.getProperty("nym.host", "127.0.0.1"), integer(p, "nym.port", 1080), container) : null,
                integer(p, "nymSetupTimeoutMillis", 120000),
                p.containsKey("i2p.lifecycleDirectory") ? Path.of(p.getProperty("i2p.lifecycleDirectory")) : null,
                integer(p,"i2p.cooldownSeconds",60),
                p.stringPropertyNames().stream().anyMatch(k -> k.startsWith("tls."))
                    ? new RemoteTls.Settings(integer(p,"tls.port",0),Path.of(required(p,"tls.certificate")),Path.of(required(p,"tls.key"))) : null);
    }

    Profile authenticate(String authorization) { return authenticate(authorization, profiles); }

    static Profile authenticate(String authorization, Map<String, Profile> profiles) {
        if (authorization == null || authorization.length() > 1024
                || !authorization.regionMatches(true, 0, "Basic ", 0, 6)) return null;
        try {
            byte[] pair = Base64.getDecoder().decode(authorization.substring(6));
            int colon = -1;
            for (int i = 0; i < pair.length; i++) if (pair[i] == ':') { colon = i; break; }
            if (colon <= 0 || colon > 64) return null;
            String id = new String(pair, 0, colon, StandardCharsets.US_ASCII);
            Profile profile = profiles.get(id);
            byte[] candidate = java.util.Arrays.copyOfRange(pair, colon + 1, pair.length);
            return profile != null && MessageDigest.isEqual(profile.tokenDigest, digest(candidate)) ? profile : null;
        } catch (IllegalArgumentException e) { return null; }
    }

    static byte[] digest(byte[] bytes) {
        try { return MessageDigest.getInstance("SHA-256").digest(bytes); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException("SHA256_UNAVAILABLE", e); }
    }

    private static String required(Properties p, String name) {
        String value = p.getProperty(name);
        if (value == null) throw new IllegalArgumentException("missing configuration key");
        return value;
    }
    private static int integer(Properties p, String name, int fallback) {
        return Integer.parseInt(p.getProperty(name, Integer.toString(fallback)));
    }
    private static InetSocketAddress endpoint(String host, int port, boolean container) throws IOException {
        if (container) return new InetSocketAddress(host, port);
        byte[] bytes;
        if (host.equals("127.0.0.1")) bytes = new byte[]{127, 0, 0, 1};
        else if (host.equals("::1")) { bytes = new byte[16]; bytes[15] = 1; }
        else throw new IllegalArgumentException("only 127.0.0.1 and ::1 are accepted");
        return new InetSocketAddress(InetAddress.getByAddress(bytes), port);
    }
}
