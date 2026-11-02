// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Bridges the real importer and offline commands to the supervisor, without starting services. */
class ImportedRecoveryInitializationTest {
    @TempDir Path directory;

    @Test void importedGatePrecedesInitializationAndPreparedStateSurvivesIt() throws Exception {
        Path source = privateDirectory(directory.resolve("source"));
        Path destination = privateDirectory(directory.resolve("destination"));
        String[] roles = {"app-data", "tor-data", "tor-control", "i2p-data", "i2p-control", "nym-data", "nym-secrets"};
        for (String role : roles) {
            privateDirectory(source.resolve(role));
            privateDirectory(destination.resolve(role));
            if (!role.equals("app-data") && !role.equals("i2p-control"))
                privateFile(source.resolve(role).resolve("fixture"), "synthetic-" + role + "\n");
        }
        Path original = source.resolve("app-data");
        privateFile(original.resolve("proxy.properties"), "isolation.key=" + "01".repeat(32)
                + "\ni2p.nextPort=15000\nprofile.old.token=" + "a".repeat(43) + "\n");
        privateFile(original.resolve("admin-token"), "b".repeat(43) + "\n");
        privateFile(original.resolve("proxy-desired"), "running\n");
        privateFile(source.resolve("i2p-control/tunnels.conf"), "[synthetic-old-fleet]\n");

        String java = Path.of(System.getProperty("java.home"), "bin/java").toString();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        assertTrue(command(java, "-XX:-UsePerfData", "--enable-native-access=ALL-UNNAMED", "-cp", classpath,
                "app.zcat.stargate.backup.VolumeImport", "--source", source.toString(),
                "--destination", destination.toString(), "--nym").contains("OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED"));
        Path data = destination.resolve("app-data"), control = destination.resolve("i2p-control");
        assertTrue(Files.isRegularFile(data.resolve("recovery-incomplete")));
        assertFalse(Files.exists(data.resolve("volume-import-incomplete")));
        Map<String, byte[]> before = files(destination);
        Path app = directory.resolve("application"), run = directory.resolve("run");
        IOException failure = assertThrows(IOException.class, () -> Supervisor.main(new String[]{
                app.toString(), data.toString(), run.toString()}));
        assertEquals("OFFLINE_RECOVERY_INCOMPLETE", failure.getMessage());
        assertFalse(Files.exists(run));
        assertFilesEqual(before, files(destination));

        assertTrue(command(java, "-XX:-UsePerfData", "-cp", classpath,
                "app.zcat.stargate.proxy.OfflineRecovery", "--discard-restored-credentials",
                "--staged-config", data.resolve("proxy.properties").toString()).contains("STAGED_RECOVERY_PREPARED"));
        assertTrue(command(java, "-XX:-UsePerfData", "-cp", classpath,
                "app.zcat.stargate.proxy.OfflineI2pFleetReset", "--staged-app", data.toString(),
                "--staged-i2p-control", control.toString(), "--ack-all-copies-and-services-offline").contains("I2P_FLEET_RESET:"));
        assertFalse(Files.exists(data.resolve("recovery-incomplete")));
        assertFalse(Files.exists(data.resolve("identity-recovery-incomplete")));
        assertEquals("", Files.readString(control.resolve("tunnels.conf")));
        String rotated = Files.readString(data.resolve("admin-token"));
        assertNotEquals(Files.readString(original.resolve("admin-token")), rotated);
        assertEquals("stopped\n", Files.readString(data.resolve("proxy-desired")));

        Files.createDirectory(app);
        Files.writeString(app.resolve("i2pd.conf"), "# synthetic template; no service is launched\n");
        new Supervisor(app, data, run).initialize(control, null);
        Properties config = new Properties();
        try (var reader = Files.newBufferedReader(data.resolve("proxy.properties"))) { config.load(reader); }
        assertEquals("65536", config.getProperty("i2p.nextPort"));
        assertEquals("true", config.getProperty("i2p.deviceIsolation"));
        assertEquals("01".repeat(32), config.getProperty("isolation.key"));
        assertTrue(config.stringPropertyNames().stream().noneMatch(key -> key.startsWith("profile.")));
        assertEquals(rotated, Files.readString(data.resolve("admin-token")));
        assertEquals("stopped\n", Files.readString(data.resolve("proxy-desired")));
        assertEquals("", Files.readString(control.resolve("tunnels.conf")));
        assertFalse(Files.exists(run.resolve("control.sock")));
        for (String role : roles) {
            if (!role.equals("app-data") && !role.equals("i2p-control"))
                assertArrayEquals(Files.readAllBytes(source.resolve(role).resolve("fixture")),
                        Files.readAllBytes(destination.resolve(role).resolve("fixture")));
        }
    }

    private static Path privateDirectory(Path path) throws IOException {
        Files.createDirectory(path);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"));
        return path;
    }

    private static void privateFile(Path path, String text) throws IOException {
        Files.writeString(path, text);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }

    private static String command(String... command) throws Exception {
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        int exit = process.waitFor();
        String output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, exit, output);
        return output;
    }

    private static Map<String, byte[]> files(Path root) throws IOException {
        Map<String, byte[]> result = new TreeMap<>();
        try (var paths = Files.walk(root)) {
            for (Path path : paths.toList()) {
                assertTrue(Files.isDirectory(path) || Files.isRegularFile(path), "unexpected fixture entry");
                result.put(root.relativize(path).toString(), Files.isDirectory(path) ? null : Files.readAllBytes(path));
            }
        }
        return result;
    }

    private static void assertFilesEqual(Map<String, byte[]> expected, Map<String, byte[]> actual) {
        assertEquals(expected.keySet(), actual.keySet());
        expected.forEach((name, bytes) -> {
            if (bytes == null) assertNull(actual.get(name), name);
            else assertArrayEquals(bytes, actual.get(name), name);
        });
    }
}
