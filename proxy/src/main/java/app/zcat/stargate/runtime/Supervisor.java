// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Container process owner. Manager and forwarding JVMs have independent lifetimes. */
public final class Supervisor {
    private final Path app, data, run;
    private final ConfigFiles configFiles;
    private Process proxy, manager;
    private String invocation = "", result = "success";
    private int exit;
    private volatile boolean closing;
    private String publicOrigin;

    Supervisor(Path app, Path data, Path run) { this(app, data, run, new ConfigFiles()); }
    Supervisor(Path app, Path data, Path run, ConfigFiles configFiles) {
        this.app = app;this.data = data;this.run = run;this.configFiles = configFiles;
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 2 && args[0].equals("--initialized")) {
            System.exit(Files.isRegularFile(Path.of(args[1])) ? 0 : 1);return;
        }
        if (args.length != 3) throw new IllegalArgumentException("Expected application, data and runtime directories");
        var owner = new Supervisor(Path.of(args[0]), Path.of(args[1]), Path.of(args[2]));
        owner.serve();
    }

    private static String random() {
        byte[] bytes = new byte[32];new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
    private static void privateFile(Path path, String content) throws Exception {
        Files.writeString(path, content);Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private void initialize() throws Exception { initialize(Path.of("/run/i2p-control")); }

    /** Explicit control directory permits initialization tests without host runtime state. */
    void initialize(Path i2pControl) throws Exception { initialize(i2pControl, System.getenv("STARGATE_PUBLIC_ORIGIN")); }

    void initialize(Path i2pControl, String configuredPublicOrigin) throws Exception {
        initialize(i2pControl, configuredPublicOrigin, System.getenv("STARGATE_MAX_CONNECTIONS"));
    }

    void initialize(Path i2pControl, String configuredPublicOrigin, String configuredMaxConnections) throws Exception {
        // Reject a bad operator limit before creating or rewriting any runtime/configuration files.
        if (configuredMaxConnections != null) {
            try {
                if (!configuredMaxConnections.matches("[1-9][0-9]*")) throw new NumberFormatException();
                Integer.parseInt(configuredMaxConnections);
            } catch (NumberFormatException invalid) { throw new IllegalArgumentException("INVALID_MAX_CONNECTIONS"); }
        }
        for (Path dir : List.of(data, run)) { Files.createDirectories(dir);Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------")); }
        Path token = data.resolve("admin-token");
        if (!Files.exists(token)) privateFile(token, random() + "\n");
        if (!Files.exists(data.resolve("proxy.properties"))) {
            byte[] key = new byte[32];new SecureRandom().nextBytes(key);
            configFiles.replace(data.resolve("proxy.properties"), "network.mode=container\nlisten.host=0.0.0.0\nlisten.port=8881\ntor.host=tor\ntor.port=9050\n"
                    + "metrics.path=" + run.resolve("traffic.json") + "\nisolation.key=" + HexFormat.of().formatHex(key)
                    + "\n");
        }
        // Upgrade existing volumes without changing browser credentials or the Tor isolation key.
        Path proxyConfig = data.resolve("proxy.properties");
        var existing = new java.util.Properties();
        try (var reader = Files.newBufferedReader(proxyConfig)) { existing.load(reader); }
        if (configuredMaxConnections != null && !configuredMaxConnections.equals(existing.getProperty("maxConnections"))) {
            // Properties serialization preserves escaped keys, credentials and counters when overriding the limit.
            existing.setProperty("maxConnections", configuredMaxConnections);
            var updated = new java.io.StringWriter();
            existing.store(updated, null);
            configFiles.replace(proxyConfig, updated.toString());
        }
        if (!existing.containsKey("i2p.host") && !existing.containsKey("i2p.port"))
            configFiles.replace(proxyConfig, Files.readString(proxyConfig) + "\ni2p.host=i2p\ni2p.port=4447\ni2pSetupTimeoutMillis=120000\n");
        String nymEnabled = System.getenv().getOrDefault("STARGATE_NYM_ENABLED", "false");
        if (!nymEnabled.equals("true") && !nymEnabled.equals("false")) throw new IllegalArgumentException("INVALID_NYM_SETTING");
        String configText = Files.readString(proxyConfig).replaceAll("(?m)^nym\\.enabled=.*(?:\\R|$)", "");
        if (!existing.containsKey("nym.host")) configText += lineSeparator(configText) + "nym.host=nym\nnym.port=1080\nnymSetupTimeoutMillis=120000\n";
        configFiles.replace(proxyConfig, configText + lineSeparator(configText) + "nym.enabled=" + nymEnabled + "\n");
        if (!existing.containsKey("i2p.deviceIsolation")) {
            // An existing counter may be the recovery exhaustion sentinel. Never reset it.
            String defaults = "\ni2p.deviceIsolation=true\n";
            if (!existing.containsKey("i2p.nextPort")) defaults += "i2p.nextPort=14447\n";
            configFiles.replace(proxyConfig, Files.readString(proxyConfig) + defaults);
        }
        if (!existing.containsKey("i2p.lifecycleDirectory"))
            configFiles.replace(proxyConfig, Files.readString(proxyConfig) + "\ni2p.lifecycleDirectory=/run/i2p-control\ni2p.cooldownSeconds=60\n");
        Files.createDirectories(i2pControl);
        Files.setPosixFilePermissions(i2pControl,java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
        if (!Files.exists(i2pControl.resolve("tunnels.conf"))) privateFile(i2pControl.resolve("tunnels.conf"), "");
        Path password = i2pControl.resolve("password");
        if (!Files.exists(password)) privateFile(password, random() + "\n");
        privateFile(i2pControl.resolve("i2pd.conf"), Files.readString(app.resolve("i2pd.conf"))
                + "password = " + Files.readString(password).trim() + "\n");
        String origin = System.getenv().getOrDefault("STARGATE_MANAGER_ORIGIN", "http://127.0.0.1:9080");
        if (!origin.matches("http://127\\.0\\.0\\.1:[1-9][0-9]{0,4}")) throw new IllegalArgumentException("LOCAL_MANAGER_ORIGIN_REQUIRED");
        int publicProxy = Integer.parseInt(System.getenv().getOrDefault("STARGATE_PROXY_PORT", "8881"));
        if (publicProxy < 1 || publicProxy > 65535) throw new IllegalArgumentException("INVALID_PROXY_PORT");
        publicOrigin = configuredPublicOrigin;
        String remoteSettings = "";
        if (publicOrigin != null) {
            validatePublicOrigin(publicOrigin);
            int remotePort = Integer.parseInt(System.getenv().getOrDefault("STARGATE_TLS_PROXY_PORT", "443"));
            if(remotePort<1 || remotePort>65535)throw new IllegalArgumentException("INVALID_REMOTE_PROXY_PORT");
            String previous=Files.readString(proxyConfig).replaceAll("(?m)^tls\\.(port|certificate|key)=.*(?:\\R|$)", "");
            configFiles.replace(proxyConfig, previous+lineSeparator(previous)+"tls.port=8882\ntls.certificate=/run/stargate-tls/server.crt\ntls.key=/run/stargate-tls/server.key\n");
            remoteSettings="manager.public.origin="+publicOrigin+"\nproxy.remote.port="+remotePort+"\n";
        } else if (Files.readString(proxyConfig).contains("tls.port=")) throw new IllegalArgumentException("REMOTE_CONFIGURATION_REQUIRED");
        privateFile(data.resolve("manager.properties"), "manager.token=" + Files.readString(token).trim() + "\nmanager.origin=" + origin
                + "\nproxy.config=" + data.resolve("proxy.properties") + "\nproxy.control.socket=" + run.resolve("control.sock")
                + "\nproxy.public.port=" + publicProxy + "\ntor.control.host=tor\ntor.control.port=9051\ntor.cookie=/run/tor-control/control_auth_cookie\n"
                + "i2p.control.host=i2p\ni2p.control.port=7650\ni2p.password=/run/i2p-control/password\ni2p.certificate=/run/i2p-control/control.crt\n" + remoteSettings + releaseSettings(System.getenv("STARGATE_RELEASE_MAX_AGE_SECONDS")) + consumerSettings(System.getenv("STARGATE_CONSUMER_MAX_AGE_SECONDS")) + upgradeSettings(System.getenv("STARGATE_UPGRADES_ENABLED")));
    }
    static String upgradeSettings(String enabled) {
        if(enabled==null||enabled.equals("false"))return "";
        if(!enabled.equals("true"))throw new IllegalArgumentException("INVALID_UPGRADE_SETTING");
        return "upgrade.directory=/run/stargate-upgrade\n";
    }
    static String releaseSettings(String age) {
        if (age == null) return "";
        if (!age.matches("[1-9][0-9]{0,7}") || Long.parseLong(age) > 31536000)
            throw new IllegalArgumentException("INVALID_RELEASE_MONITOR");
        return "release.snapshot=/run/release-monitor-snapshot.json\nrelease.max-age-seconds=" + age + "\n";
    }
    static String consumerSettings(String age) {
        if (age == null) return "";
        if (!age.matches("[1-9][0-9]{0,7}") || Long.parseLong(age) > 31536000)
            throw new IllegalArgumentException("INVALID_CONSUMER_MONITOR");
        return "consumer.snapshot=/run/consumer-monitor-snapshot.json\nconsumer.max-age-seconds=" + age + "\n";
    }
    private static String lineSeparator(String text) {
        return text.isEmpty() || text.endsWith("\n") || text.endsWith("\r") ? "" : "\n";
    }

    /** Publish only a complete synced proxy configuration; no non-atomic fallback. */
    static class ConfigFiles {
        void replace(Path target, String content) throws IOException {
            Path temporary = Files.createTempFile(target.getParent(), ".initialization-", ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            try {
                write(temporary, content);
                if (Files.size(temporary) > 262144) throw new IOException("CONFIGURATION_TOO_LARGE");
                move(temporary, target);
                forceDirectory(target.getParent());
            } finally { Files.deleteIfExists(temporary); }
        }
        void write(Path temporary, String content) throws IOException {
            try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE)) {
                ByteBuffer bytes = StandardCharsets.UTF_8.encode(content);
                while (bytes.hasRemaining()) channel.write(bytes);
                channel.force(true);
            }
        }
        void move(Path source, Path target) throws IOException {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }
        void forceDirectory(Path directory) throws IOException {
            try (var channel = FileChannel.open(directory, StandardOpenOption.READ)) { channel.force(true); }
        }
    }

    private Process launch(String... args) throws Exception {
        var command = new java.util.ArrayList<String>();
        command.add(Path.of(System.getProperty("java.home"), "bin/java").toString());
        command.add("-Djava.security.properties=" + app.resolve("dns.security"));command.addAll(List.of(args));
        return new ProcessBuilder(command).directory(app.toFile()).inheritIO().start();
    }
    static void validatePublicOrigin(String origin) {
        var uri = java.net.URI.create(origin);String host = uri.getHost();
        if (!"https".equals(uri.getScheme()) || host == null || host.length()>253 || !host.equals(host.toLowerCase(java.util.Locale.ROOT))
                || !java.util.Arrays.stream(host.split("\\.",-1)).allMatch(label -> label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"))
                || host.endsWith(".onion") || host.endsWith(".i2p") || uri.getRawUserInfo()!=null || uri.getRawQuery()!=null || uri.getRawFragment()!=null
                || !uri.getRawPath().isEmpty() || uri.getPort()==0 || uri.getPort()>65535 || uri.getPort()==443
                || !origin.equals("https://"+host+(uri.getPort()==-1?"":":"+uri.getPort())))
            throw new IllegalArgumentException("INVALID_PUBLIC_ORIGIN");
    }
    private Process launchManager() throws Exception {
        var args = new java.util.ArrayList<String>();
        args.add("-Dstargate.config=" + data.resolve("manager.properties"));
        args.add("-Dquarkus.http.host=0.0.0.0");
        if (publicOrigin != null) {
            args.add("-Dquarkus.http.ssl-port=9443");
            args.add("-Dquarkus.http.ssl.certificate.files=/run/stargate-tls/server.crt");
            args.add("-Dquarkus.http.ssl.certificate.key-files=/run/stargate-tls/server.key");
            args.add("-Dquarkus.http.ssl.certificate.reload-period=30s");
            args.add("-Dquarkus.http.ssl.protocols=TLSv1.3,TLSv1.2");
            args.add("-Dquarkus.tls.protocols=TLSv1.3,TLSv1.2");
        }
        args.add("-jar");args.add(app.resolve("manager/quarkus-run.jar").toString());
        return launch(args.toArray(String[]::new));
    }
    private synchronized void startProxy() throws Exception {
        if (proxy != null && proxy.isAlive()) return;
        privateFile(data.resolve("proxy-desired"), "running\n");
        Files.deleteIfExists(run.resolve("traffic.json"));
        proxy = launch("-jar", app.resolve("proxy.jar").toString(), "--config", data.resolve("proxy.properties").toString());
        invocation = UUID.randomUUID().toString();result = "success";exit = 0;
    }
    private synchronized void stopProxy(boolean remember) throws Exception {
        if (remember) privateFile(data.resolve("proxy-desired"), "stopped\n");
        if (proxy != null && proxy.isAlive()) {
            proxy.destroy();
            if (!proxy.waitFor(7, TimeUnit.SECONDS)) { proxy.destroyForcibly();proxy.waitFor(2, TimeUnit.SECONDS); }
        }
        if (proxy != null) exit = proxy.exitValue();
        proxy = null;result = "requested-stop";
    }
    private synchronized String status() {
        if (proxy != null && proxy.isAlive()) return "active|" + proxy.pid() + "|" + invocation + "|success|0";
        if (proxy != null) { exit = proxy.exitValue();result = "exit-code"; }
        return (proxy == null || exit == 0 ? "inactive" : "failed") + "|0|" + invocation + "|" + result + "|" + exit;
    }
    static void requireRecoveryComplete(Path data) throws java.io.IOException {
        for (String marker : new String[]{"volume-import-incomplete", "recovery-incomplete", "identity-recovery-incomplete", "identity-recovery-preparing"}) {
            try {
                Files.readAttributes(data.resolve(marker), java.nio.file.attribute.BasicFileAttributes.class,
                        java.nio.file.LinkOption.NOFOLLOW_LINKS);
            } catch (java.nio.file.NoSuchFileException absent) { continue; }
            throw new java.io.IOException("OFFLINE_RECOVERY_INCOMPLETE");
        }
    }

    private void serve() throws Exception {
        // Check before initialize can rewrite restored files or any manager/proxy listener starts.
        requireRecoveryComplete(data);
        initialize();Path socket = run.resolve("control.sock");Files.deleteIfExists(socket);
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            closing = true;
            try { stopProxy(false); } catch (Exception ignored) {}
            if (manager != null) { manager.destroy();try { if (!manager.waitFor(5, TimeUnit.SECONDS)) manager.destroyForcibly(); } catch (InterruptedException ignored) {} }
        }, "container-shutdown"));
        try (var server = ServerSocketChannel.open(StandardProtocolFamily.UNIX);
             var handlers = Executors.newVirtualThreadPerTaskExecutor();
             var deadlines = Executors.newSingleThreadScheduledExecutor()) {
            server.bind(UnixDomainSocketAddress.of(socket));Files.setPosixFilePermissions(socket, PosixFilePermissions.fromString("rw-------"));
            Path desired = data.resolve("proxy-desired");
            if (Files.exists(desired) && Files.readString(desired).trim().equals("running")) startProxy();
            manager = launchManager();
            Thread.ofPlatform().daemon().name("manager-owner").start(() -> {
                while (!closing) {
                    try {
                        manager.waitFor();if (closing) return;Thread.sleep(1000);
                        manager = launchManager();
                    } catch (Exception e) { if (!closing) System.err.println("MANAGER_RESTART_FAILED"); }
                }
            });
            System.out.println("STARGATE_CONTAINER_READY");
            while (!closing) {
                SocketChannel client = server.accept();
                handlers.submit(() -> {
                    var deadline = deadlines.schedule(() -> { try { client.close(); } catch (Exception ignored) {} }, 15, TimeUnit.SECONDS);
                    try (client) {
                        String action = new DataInputStream(Channels.newInputStream(client)).readUTF();
                        String reply;
                        switch (action) {
                            case "status" -> reply = status();
                            case "start" -> { startProxy();reply = "OK"; }
                            case "stop" -> { stopProxy(true);reply = "OK"; }
                            case "restart" -> { stopProxy(false);startProxy();reply = "OK"; }
                            default -> reply = "REJECTED";
                        }
                        new DataOutputStream(Channels.newOutputStream(client)).writeUTF(reply);
                    } catch (Exception ignored) { System.err.println("CONTROL_OPERATION_FAILED"); }
                    finally { deadline.cancel(false); }
                });
            }
        }
    }
}
