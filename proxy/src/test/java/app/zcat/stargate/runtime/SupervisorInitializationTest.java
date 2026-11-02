// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Properties;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SupervisorInitializationTest {
    @Test void upgradesRemainExplicitlyOptIn() {
        assertEquals("",Supervisor.upgradeSettings(null));assertEquals("",Supervisor.upgradeSettings("false"));
        assertEquals("upgrade.directory=/run/stargate-upgrade\n",Supervisor.upgradeSettings("true"));
        assertThrows(IllegalArgumentException.class,()->Supervisor.upgradeSettings("yes"));
    }
    @TempDir Path directory;

    @Test void actualRecoveryThenInitializationPreservesExhaustionWhenIsolationWasAbsent() throws Exception {
        Path data = privateDirectory("recovered");
        Path config = data.resolve("proxy.properties");
        privateFile(config, "isolation.key=" + "00".repeat(32) + "\ni2p.nextPort=14448\nprofile.old.token=" + "a".repeat(43) + "\n");
        privateFile(data.resolve("admin-token"), "b".repeat(43) + "\n");
        Process recovery = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "-XX:-UsePerfData", "-cp", System.getProperty("java.class.path"),
                "app.zcat.stargate.proxy.OfflineRecovery", "--discard-restored-credentials", "--staged-config", config.toString())
                .redirectErrorStream(true).start();
        try {
            assertTrue(recovery.waitFor(10, TimeUnit.SECONDS));
            assertEquals(0, recovery.exitValue(), () -> readOutput(recovery));
        } finally { if (recovery.isAlive()) recovery.destroyForcibly().waitFor(); }
        assertEquals("65536", read(config).getProperty("i2p.nextPort"));
        assertFalse(read(config).containsKey("i2p.deviceIsolation"));
        assertFalse(Files.exists(data.resolve("recovery-incomplete")));
        var supervisor = supervisor(data);
        for (int rerun = 0; rerun < 2; rerun++) {
            supervisor.initialize(directory.resolve("synthetic-i2p-control"));
            assertEquals("true", read(config).getProperty("i2p.deviceIsolation"));
            assertEquals("65536", read(config).getProperty("i2p.nextPort"));
            assertEquals(1, occurrences(config, "i2p.nextPort"));
            assertEquals(1, occurrences(config, "i2p.deviceIsolation"));
            assertTrue(read(config).stringPropertyNames().stream().noneMatch(k -> k.startsWith("profile.")));
        }
    }

    @Test void freshInitializationAddsBothDefaultsOnce() throws Exception {
        Path data = directory.resolve("fresh");
        var supervisor = supervisor(data);
        for (int rerun = 0; rerun < 2; rerun++) {
            supervisor.initialize(directory.resolve("fresh-i2p-control"));
            Path config = data.resolve("proxy.properties");
            assertEquals("true", read(config).getProperty("i2p.deviceIsolation"));
            assertEquals("14447", read(config).getProperty("i2p.nextPort"));
            assertEquals(1, occurrences(config, "i2p.nextPort"));
            assertEquals(1, occurrences(config, "i2p.deviceIsolation"));
        }
    }

    @Test void addingIsolationPreservesExistingCountersAndExplicitSharedMode() throws Exception {
        for (String counter : new String[]{"14480", "65536", "invalid"}) {
            Path data = privateDirectory("existing-" + counter);
            Path config = data.resolve("proxy.properties");
            privateFile(config, "isolation.key=" + "00".repeat(32) + "\ni2p.nextPort=" + counter + "\n");
            supervisor(data).initialize(directory.resolve("control-" + counter));
            assertEquals(counter, read(config).getProperty("i2p.nextPort"));
            assertEquals(1, occurrences(config, "i2p.nextPort"));
        }
        Path data = privateDirectory("shared");
        Path config = data.resolve("proxy.properties");
        privateFile(config, "isolation.key=" + "00".repeat(32) + "\ni2p.deviceIsolation=false\ni2p.nextPort=65536\n");
        supervisor(data).initialize(directory.resolve("shared-control"));
        assertEquals("false", read(config).getProperty("i2p.deviceIsolation"));
        assertEquals("65536", read(config).getProperty("i2p.nextPort"));
        assertEquals(1, occurrences(config, "i2p.nextPort"));
    }

    @Test void repeatedInitializationDoesNotGrowFullConfigurationWith129Profiles() throws Exception {
        Path data = privateDirectory("full");Path config = data.resolve("proxy.properties");
        privateFile(data.resolve("admin-token"), "b".repeat(43) + "\n");
        String enabled = System.getenv().getOrDefault("STARGATE_NYM_ENABLED", "false");
        var content = new StringBuilder("isolation.key=" + "00".repeat(32)
                + "\ni2p.host=127.0.0.1\ni2p.port=4447\ni2p.deviceIsolation=true\ni2p.nextPort=14447"
                + "\ni2p.lifecycleDirectory=/tmp/synthetic-lifecycle\nnym.host=127.0.0.1\nnym.port=1080\n");
        for (int i = 0; i < 129; i++) content.append("profile.device").append(i).append(".token=").append("a".repeat(43)).append('\n');
        String tail = "\nnym.enabled=" + enabled + "\n";
        int padding = 262144 - content.length() - tail.length() - 1;
        assertTrue(padding > 0);content.append('#').append("x".repeat(padding)).append(tail);
        privateFile(config, content.toString());assertEquals(262144, Files.size(config));
        var supervisor = supervisor(data);String previous = Files.readString(config);
        for (int i = 0; i < 3; i++) {
            supervisor.initialize(directory.resolve("full-control"));
            assertEquals(previous, Files.readString(config));assertEquals(262144, Files.size(config));
            assertEquals(129, app.zcat.stargate.proxy.ProxyConfig.load(config).profiles().size());
        }
    }

    @Test void repeatedRemoteInitializationDoesNotGrowFullConfiguration() throws Exception {
        Path data = privateDirectory("full-remote");Path config = data.resolve("proxy.properties");
        privateFile(data.resolve("admin-token"), "b".repeat(43) + "\n");
        String enabled = System.getenv().getOrDefault("STARGATE_NYM_ENABLED", "false");
        var content = new StringBuilder("isolation.key=" + "00".repeat(32)
                + "\ni2p.host=127.0.0.1\ni2p.port=4447\ni2p.deviceIsolation=true\ni2p.nextPort=14447"
                + "\ni2p.lifecycleDirectory=/tmp/synthetic-lifecycle\nnym.host=127.0.0.1\nnym.port=1080\n");
        for (int i = 0; i < 129; i++) content.append("profile.device").append(i).append(".token=").append("a".repeat(43)).append('\n');
        String tail = "\nnym.enabled=" + enabled + "\ntls.port=8882\ntls.certificate=/run/stargate-tls/server.crt\ntls.key=/run/stargate-tls/server.key\n";
        int padding = 262144 - content.length() - tail.length() - 1;
        assertTrue(padding > 0);content.append('#').append("x".repeat(padding)).append(tail);
        privateFile(config, content.toString());assertEquals(262144, Files.size(config));
        var supervisor = supervisor(data);String previous = Files.readString(config);
        for (int i = 0; i < 3; i++) {
            supervisor.initialize(directory.resolve("remote-control"), "https://gate.example");
            assertEquals(previous, Files.readString(config));assertEquals(262144, Files.size(config));
            var loaded = app.zcat.stargate.proxy.ProxyConfig.load(config);
            assertEquals(129, loaded.profiles().size());assertEquals(8882, loaded.tls().port());
            assertEquals(Path.of("/run/stargate-tls/server.crt"), loaded.tls().certificate());
            assertEquals(Path.of("/run/stargate-tls/server.key"), loaded.tls().key());
            assertEquals("https://gate.example", read(data.resolve("manager.properties")).getProperty("manager.public.origin"));
        }
    }

    @Test void oversizedInitializationDoesNotReplacePreviousConfiguration() throws Exception {
        Path config = directory.resolve("proxy.properties");
        Files.writeString(config, "previous configuration");
        var files = new Supervisor.ConfigFiles();
        var error = assertThrows(IOException.class, () -> files.replace(config, "x".repeat(262145)));
        assertEquals("CONFIGURATION_TOO_LARGE", error.getMessage());
        assertEquals("previous configuration", Files.readString(config));
        try (var paths = Files.list(directory)) {
            assertTrue(paths.noneMatch(path -> path.getFileName().toString().startsWith(".initialization-")));
        }
    }

    @Test void initializationWriteFailuresNeverPublishPartialConfigOrResetRecoveredCounter() throws Exception {
        for (String boundary : new String[]{"partial-write", "file-sync", "rename", "directory-sync"}) {
            for (int replacement = 1; replacement <= 4; replacement++) {
                Path data = privateDirectory(boundary + "-" + replacement);
                Path config = data.resolve("proxy.properties");
                privateFile(config, "isolation.key=" + "00".repeat(32) + "\ni2p.nextPort=65536\n");
                int failingReplacement = replacement;
                class FailingFiles extends Supervisor.ConfigFiles {
                    int replacements;
                    boolean fail;
                    String prior;
                    @Override void replace(Path target, String content) throws IOException {
                        fail = ++replacements == failingReplacement;
                        if (fail) prior = Files.readString(target);
                        super.replace(target, content);
                    }
                    @Override void write(Path temporary, String content) throws IOException {
                        if (fail && boundary.equals("partial-write")) {
                            Files.writeString(temporary, "isolation.key=");
                            throw new IOException("injected partial temporary write");
                        }
                        super.write(temporary, content);
                        if (fail && boundary.equals("file-sync")) throw new IOException("injected file sync failure");
                    }
                    @Override void move(Path source, Path target) throws IOException {
                        if (fail && boundary.equals("rename")) throw new java.nio.file.AtomicMoveNotSupportedException("", "", "injected");
                        super.move(source, target);
                    }
                    @Override void forceDirectory(Path path) throws IOException {
                        if (fail && boundary.equals("directory-sync")) throw new IOException("injected directory sync failure");
                        super.forceDirectory(path);
                    }
                }
                var files = new FailingFiles();
                var supervisor = supervisor(data, files);
                assertThrows(IOException.class, () -> supervisor.initialize(directory.resolve("failure-control")));
                assertEquals(failingReplacement, files.replacements);
                if (!boundary.equals("directory-sync")) assertEquals(files.prior, Files.readString(config));
                assertEquals("65536", read(config).getProperty("i2p.nextPort"));
                assertEquals(1, occurrences(config, "i2p.nextPort"));
                try (var paths = Files.list(data)) {
                    assertTrue(paths.noneMatch(path -> path.getFileName().toString().startsWith(".initialization-")));
                }
                supervisor(data).initialize(directory.resolve("rerun-control"));
                assertEquals("65536", read(config).getProperty("i2p.nextPort"));
                assertEquals("true", read(config).getProperty("i2p.deviceIsolation"));
                assertEquals(1, occurrences(config, "i2p.nextPort"));
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(config));
            }
        }
    }

    @Test void invalidConnectionEnvironmentDoesNotMutateConfigurationOrCreateRuntimeFiles() throws Exception {
        Path data = privateDirectory("invalid-limit");
        Path config = data.resolve("proxy.properties");
        String original = "isolation.key=" + "00".repeat(32) + "\nmaxConnections=41\ni2p.nextPort=65536\n";
        privateFile(config, original);
        String adminToken = "b".repeat(43) + "\n";
        privateFile(data.resolve("admin-token"), adminToken);
        var supervisor = supervisor(data);
        Path control = directory.resolve("invalid-limit-control");
        for (String bad : new String[]{"", "0", "-1", "+1", "01", "1.5", " 10", "10 ", "10\nother=value", "2147483648"}) {
            var error = assertThrows(IllegalArgumentException.class, () -> supervisor.initialize(control, null, bad));
            assertEquals("INVALID_MAX_CONNECTIONS", error.getMessage());
            assertEquals(original, Files.readString(config));
            assertEquals(adminToken, Files.readString(data.resolve("admin-token")));
            assertFalse(Files.exists(data.resolve("manager.properties")));
            assertFalse(Files.exists(data.resolveSibling("invalid-limit-run")));
            assertFalse(Files.exists(control));
        }
        Path fresh = directory.resolve("invalid-fresh-limit");
        var freshSupervisor = supervisor(fresh);
        assertThrows(IllegalArgumentException.class, () -> freshSupervisor.initialize(control, null, "0"));
        assertFalse(Files.exists(fresh));
    }

    @Test void invalidConnectionEnvironmentIsRejectedByActualSupervisorEntrypoint() throws Exception {
        Path app = directory.resolve("entrypoint-app"), data = directory.resolve("entrypoint-data"), run = directory.resolve("entrypoint-run");
        for (String bad : new String[]{"", "2147483648"}) {
            var builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                    "-XX:-UsePerfData", "-cp", System.getProperty("java.class.path"), Supervisor.class.getName(),
                    app.toString(), data.toString(), run.toString()).redirectErrorStream(true);
            builder.environment().put("STARGATE_MAX_CONNECTIONS", bad);
            Process process = builder.start();
            try {
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "invalid environment did not terminate startup");
                assertNotEquals(0, process.exitValue());
                assertTrue(readOutput(process).contains("INVALID_MAX_CONNECTIONS"));
            } finally { if (process.isAlive()) process.destroyForcibly().waitFor(); }
            assertFalse(Files.exists(app));assertFalse(Files.exists(data));assertFalse(Files.exists(run));
        }
    }

    @Test void unsetConnectionEnvironmentRetainsHistoricDefaultAndAcceptsIntBoundaries() throws Exception {
        Path data = directory.resolve("default-limit");
        var supervisor = supervisor(data);
        supervisor.initialize(directory.resolve("default-limit-control"), null, null);
        assertNull(read(data.resolve("proxy.properties")).getProperty("maxConnections"),
                "an unset environment variable must leave the proxy's historic fallback in effect");
        for (String limit : new String[]{"1", "2147483647"}) {
            supervisor.initialize(directory.resolve("default-limit-control"), null, limit);
            assertEquals(limit, read(data.resolve("proxy.properties")).getProperty("maxConnections"));
            supervisor.initialize(directory.resolve("default-limit-control"), null, null);
            assertEquals(limit, read(data.resolve("proxy.properties")).getProperty("maxConnections"),
                    "an unset environment variable must preserve the stored operator choice");
        }
    }

    @Test void operatorConnectionOverridePreservesCredentialsIsolationAndRecoveryCounter() throws Exception {
        Path data = privateDirectory("operator-limit");
        Path config = data.resolve("proxy.properties");
        String original = "isolation.key=" + "00".repeat(32)
                + "\nmaxConnections : 17\nmaxConnections=19\ni2p.host=127.0.0.1\nnym.host=127.0.0.1"
                + "\ni2p.deviceIsolation=true\ni2p.nextPort=65536"
                + "\nprofile.d_Work_browser_fixture.token=" + "a".repeat(20) + "\\\n  " + "a".repeat(23)
                + "\nprofile.d_Work_browser_fixture.i2pPort=14447\nprofile.d_Work_browser_fixture.i2pEnabled=false\n";
        privateFile(config, original);
        Properties previous = read(config);
        String adminToken = "b".repeat(43) + "\n";
        privateFile(data.resolve("admin-token"), adminToken);
        var supervisor = supervisor(data);
        Path control = directory.resolve("operator-limit-control");
        for (String limit : new String[]{"64", "256", null}) {
            supervisor.initialize(control, null, limit);
            Properties updated = read(config);
            assertEquals(limit == null ? "256" : limit, updated.getProperty("maxConnections"));
            var loaded = app.zcat.stargate.proxy.ProxyConfig.load(config);
            assertEquals(Integer.parseInt(limit == null ? "256" : limit), loaded.maxConnections());
            var profile = loaded.profiles().get("d_Work_browser_fixture");
            assertArrayEquals(java.security.MessageDigest.getInstance("SHA-256")
                    .digest("a".repeat(43).getBytes(java.nio.charset.StandardCharsets.US_ASCII)), profile.tokenDigest());
            assertEquals("sg2:7182de17cef2cc495feb50c5f0017800f22d5d52d53dd89ee723d8533dd94e8b", profile.partition());
            assertEquals(0, profile.i2pPort(), "disabled device remains unavailable after the override");
            assertEquals(1, occurrences(config, "maxConnections"));
            for (String key : previous.stringPropertyNames())
                if (!key.equals("maxConnections")) assertEquals(previous.getProperty(key), updated.getProperty(key), key);
            assertEquals(adminToken, Files.readString(data.resolve("admin-token")));
            assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(config));
        }
    }

    @Test void releaseMonitorConfigurationIsOptInAndBounded() {
        assertEquals("", Supervisor.releaseSettings(null));
        assertEquals("release.snapshot=/run/release-monitor-snapshot.json\nrelease.max-age-seconds=60\n", Supervisor.releaseSettings("60"));
        for (String bad : new String[]{"", "0", "-1", "31536001", "60\nother=value"})
            assertThrows(IllegalArgumentException.class, () -> Supervisor.releaseSettings(bad));
    }
    @Test void consumerMonitorConfigurationIsOptInAndBounded() {
        assertEquals("", Supervisor.consumerSettings(null));
        assertEquals("consumer.snapshot=/run/consumer-monitor-snapshot.json\nconsumer.max-age-seconds=60\n", Supervisor.consumerSettings("60"));
        for (String bad : new String[]{"", "0", "-1", "31536001", "60\nother=value"})
            assertThrows(IllegalArgumentException.class, () -> Supervisor.consumerSettings(bad));
    }
    private Supervisor supervisor(Path data) throws Exception {
        return supervisor(data, new Supervisor.ConfigFiles());
    }

    private Supervisor supervisor(Path data, Supervisor.ConfigFiles configFiles) throws Exception {
        Path app = directory.resolve("application");
        Files.createDirectories(app);
        Files.writeString(app.resolve("i2pd.conf"), "# synthetic template; no service is launched\n");
        return new Supervisor(app, data, data.resolveSibling(data.getFileName() + "-run"), configFiles);
    }
    private Path privateDirectory(String name) throws Exception {
        Path path = Files.createDirectory(directory.resolve(name));
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        return path;
    }
    private static void privateFile(Path path, String text) throws Exception {
        Files.writeString(path, text);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
    private static Properties read(Path config) throws Exception {
        Properties p = new Properties();
        try (var reader = Files.newBufferedReader(config)) { p.load(reader); }
        return p;
    }
    private static long occurrences(Path config, String key) throws Exception {
        try (var lines = Files.lines(config)) { return lines.filter(line -> line.startsWith(key + "=")).count(); }
    }
    private static String readOutput(Process process) {
        try { return new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8); }
        catch (java.io.IOException e) { return "RECOVERY_OUTPUT_UNAVAILABLE"; }
    }
}
