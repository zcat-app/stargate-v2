// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OfflineRecoveryTest {
    @TempDir Path directory;
    private static final String TOKEN = "a".repeat(43);
    private static final String ADMIN = "b".repeat(43);
    private static final String CONFIG = "isolation.key=" + "01".repeat(32) + "\n"
            + "i2p.deviceIsolation=true\ni2p.nextPort=14450\ntor.host=127.0.0.1\n"
            + "profile.old.token=" + TOKEN + "\nprofile.old.i2pPort=14447\nprofile.old.i2pEnabled=false\n"
            + "profile.other.token=" + "c".repeat(43) + "\nprofile.other.i2pPort=14448\n"
            + "profile.orphan.i2pPort=14449\nprofile.orphan.i2pEnabled=false\n";

    @Test void removesEveryRestoredCredentialAndProfileSettingPreservingUnrelatedValues() throws Exception {
        Path config = fixture();
        String basic = "Basic " + Base64.getEncoder().encodeToString(("old:" + TOKEN).getBytes(StandardCharsets.US_ASCII));
        assertNotNull(ProxyConfig.load(config).authenticate(basic));
        Properties before = ProxyConfig.read(config);
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        Properties after = ProxyConfig.read(config);
        before.keySet().removeIf(key -> ((String) key).startsWith("profile."));
        before.setProperty("i2p.nextPort", "65536");
        assertEquals(before, after);
        assertTrue(after.stringPropertyNames().stream().noneMatch(key -> key.startsWith("profile.")));
        assertNull(ProxyConfig.load(config).authenticate(basic));
        assertEquals("65536", after.getProperty("i2p.nextPort"));
        assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
        assertFalse(Files.exists(directory.resolve("manager.properties")));
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        assertNotEquals(ADMIN, Files.readString(directory.resolve("admin-token")).trim());
        assertTrue(Files.readString(directory.resolve("admin-token")).matches("[A-Za-z0-9_-]{43}\n"));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(config));
    }

    @Test void identityGateCannotBeBypassedByCredentialReset() throws Exception {
        Path config = fixture();
        Path marker = directory.resolve("identity-recovery-incomplete");
        Files.writeString(marker, "incomplete\n");
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        assertEquals(CONFIG, Files.readString(config));
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void incompleteImportCannotBeBypassedByCredentialReset() throws Exception {
        Path config = fixture();
        Path marker = directory.resolve("volume-import-incomplete");
        for (String kind : new String[]{"partial-file", "directory", "dangling-link"}) {
            if (kind.equals("partial-file")) Files.writeString(marker, "");
            else if (kind.equals("directory")) Files.createDirectory(marker);
            else Files.createSymbolicLink(marker, directory.resolve("missing"));
            assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
            assertEquals(CONFIG, Files.readString(config));
            assertEquals(ADMIN, Files.readString(directory.resolve("admin-token")).trim());
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
            assertTrue(Files.exists(marker, java.nio.file.LinkOption.NOFOLLOW_LINKS));
            Files.delete(marker);
        }
    }

    @Test void identityPreparingFileCannotBeBypassedByCredentialReset() throws Exception {
        Path config = fixture();Path preparing = directory.resolve("identity-recovery-preparing");
        Files.writeString(preparing, "partial");
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        assertEquals(CONFIG, Files.readString(config));assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void completionCanBeRepeatedAndRotatesAdministratorAgain() throws Exception {
        Path config = fixture();
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        Properties first = ProxyConfig.read(config);
        assertEquals("65536", first.getProperty("i2p.nextPort"));
        String firstAdmin = Files.readString(directory.resolve("admin-token"));
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertEquals(first, ProxyConfig.read(config));
        assertNotEquals(firstAdmin, Files.readString(directory.resolve("admin-token")));
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void incompleteAndStoppedAreDurableBeforeCredentialChanges() throws Exception {
        Path config = fixture();
        var events = new ArrayList<String>();
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void move(Path source, Path target) throws IOException {
                String name = target.getFileName().toString();
                if (name.equals("proxy.properties")) {
                    assertEquals(java.util.List.of("recovery-incomplete", "sync", "proxy-desired", "sync"), events);
                    assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
                    assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
                    assertEquals(CONFIG, Files.readString(config));
                    Properties replacement = new Properties();
                    try (var reader = Files.newBufferedReader(source)) { replacement.load(reader); }
                    assertEquals("65536", replacement.getProperty("i2p.nextPort"));
                    assertTrue(ProxyConfig.profiles(replacement).isEmpty());
                }
                super.move(source, target);
                events.add(name);
            }
            @Override void forceDirectory(Path path) throws IOException { super.forceDirectory(path);events.add("sync"); }
        });
    }

    @Test void configReplacementFailureRetainsOriginalAndGateAndCanBeRerun() throws Exception {
        Path config = fixture();
        assertThrows(AtomicMoveNotSupportedException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void move(Path source, Path target) throws IOException {
                if (target.equals(config)) throw new AtomicMoveNotSupportedException("", "", "injected");
                super.move(source, target);
            }
        }));
        assertEquals(CONFIG, Files.readString(config));
        assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        assertNoTemporaryFiles();
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void initialGateSyncFailureLeavesCredentialsUntouchedAndCanBeRerun() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void forceDirectory(Path path) throws IOException { throw new IOException("injected"); }
        }));
        assertEquals(CONFIG, Files.readString(config));
        assertEquals("running\n", Files.readString(directory.resolve("proxy-desired")));
        assertEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        assertNoTemporaryFiles();
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void stoppedSyncFailureCannotProceedToCredentialMutation() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            int syncs;
            @Override void forceDirectory(Path path) throws IOException {
                if (++syncs == 2) throw new IOException("injected");
                super.forceDirectory(path);
            }
        }));
        assertEquals(CONFIG, Files.readString(config));
        assertEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void adminReplacementAndManagerRemovalFailuresKeepGateAndAllowRerun() throws Exception {
        for (String failingName : new String[]{"admin-token", "manager.properties"}) {
            Path config = fixture();
            assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
                @Override void move(Path source, Path target) throws IOException {
                    if (target.getFileName().toString().equals(failingName)) throw new IOException("injected");
                    super.move(source, target);
                }
                @Override void delete(Path path) throws IOException {
                    if (path.getFileName().toString().equals(failingName)) throw new IOException("injected");
                    super.delete(path);
                }
            }));
            assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
            assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
            OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        }
    }

    @Test void failedFinalSyncRecreatesGateAndReportsFailure() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            int syncs;
            @Override void forceDirectory(Path path) throws IOException {
                if (++syncs == 6) throw new IOException("injected");
                super.forceDirectory(path);
            }
        }));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void olderNonisolatedSnapshotsAndMissingCountersAreQuarantined() throws Exception {
        for (String isolation : new String[]{"false", null}) {
            Path config = fixture();
            String original = CONFIG.replace("i2p.deviceIsolation=true\n", isolation == null ? "" : "i2p.deviceIsolation=false\n")
                    .replace("i2p.nextPort=14450\n", "") + "i2p.host=127.0.0.1\nnym.enabled=true\n";
            Files.writeString(config, original);
            var before = ProxyConfig.load(config);
            OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
            var after = ProxyConfig.load(config);
            assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
            assertEquals(before.tor(), after.tor());
            assertEquals(before.i2p(), after.i2p());
            assertEquals(before.nym(), after.nym());
            assertEquals(isolation, ProxyConfig.read(config).getProperty("i2p.deviceIsolation"));
            assertTrue(after.profiles().isEmpty());
        }
    }

    @Test void configSyncFailureLeavesBothCredentialRemovalAndExhaustionBehindGate() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            int syncs;
            @Override void forceDirectory(Path path) throws IOException {
                if (++syncs == 3) throw new IOException("injected");
                super.forceDirectory(path);
            }
        }));
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        assertEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
    }

    @Test void verificationRejectsAnUnexhaustedCounterBeforeRemovingGate() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void delete(Path path) throws IOException {
                super.delete(path);
                if (path.getFileName().toString().equals("manager.properties"))
                    Files.writeString(config, Files.readString(config).replace("i2p.nextPort=65536", "i2p.nextPort=14450"));
            }
        }));
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
    }

    @Test void invalidConfigurationAndOversizedFilesDoNotBeginTransaction() throws Exception {
        Path config = fixture();
        for (String content : new String[]{"isolation.key=invalid\n", CONFIG + "unknown.setting=true\n", "x".repeat(262145)}) {
            Files.writeString(config, content);
            assertThrows(Exception.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
            assertEquals(content, Files.readString(config));
            assertEquals("running\n", Files.readString(directory.resolve("proxy-desired")));
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        }
    }

    @Test void malformedRestoredProfileValuesAreDiscardedRatherThanCarriedForward() throws Exception {
        Path config = fixture();
        Files.writeString(config, CONFIG + "profile.bad.token=bad\nprofile.unrecognized.secret=discard-me\n");
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        assertFalse(Files.readString(config).contains("discard-me"));
    }

    @Test void symlinkFilesAncestorsAndHardlinksAreRejected() throws Exception {
        Path config = fixture();
        Path original = directory.resolve("original");
        Files.move(config, original);
        Files.createSymbolicLink(config, original);
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        Files.delete(config);Files.move(original, config);
        Path alias = directory.resolve("alias");Files.createSymbolicLink(alias, directory);
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(alias.resolve("proxy.properties"), new OfflineRecovery.AtomicFiles()));
        Files.delete(alias);
        Files.createLink(original, config);
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        Files.delete(original);
        Path desired = directory.resolve("proxy-desired");Files.delete(desired);
        Files.createSymbolicLink(desired, directory.resolve("missing"));
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        assertEquals(CONFIG, Files.readString(config));
    }

    @Test void permissionsAndMissingFilesAreRejectedWithoutChangingCredentials() throws Exception {
        Path config = fixture();
        for (String name : new String[]{"proxy.properties", "admin-token", "proxy-desired", "manager.properties"}) {
            Path path = directory.resolve(name);
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
            assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-x---"));
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        Files.delete(directory.resolve("admin-token"));
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles()));
        assertEquals(CONFIG, Files.readString(config));
    }

    @Test void cliRequiresExplicitOptInAndAbsoluteNamedPathAndNeverPrintsSecrets() throws Exception {
        Path config = fixture();
        var output = new ByteArrayOutputStream();var stream = new PrintStream(output, true, StandardCharsets.UTF_8);
        assertEquals(2, OfflineRecovery.run(new String[]{"--staged-config", config.toString()}, stream, stream));
        assertEquals(1, OfflineRecovery.run(new String[]{"--discard-restored-credentials", "--staged-config", "proxy.properties"}, stream, stream));
        assertEquals(1, OfflineRecovery.run(new String[]{"--discard-restored-credentials", "--staged-config", directory.resolve("other.properties").toString()}, stream, stream));
        assertEquals(0, OfflineRecovery.run(new String[]{"--discard-restored-credentials", "--staged-config", config.toString()}, stream, stream));
        String text = output.toString(StandardCharsets.UTF_8);
        assertTrue(text.contains("automatic forwarding startup disabled"));
        assertTrue(text.contains("New isolated I2P device routes are blocked because later port history is unknown"));
        assertFalse(text.contains("proxy stopped"));
        assertFalse(text.contains(TOKEN));assertFalse(text.contains(ADMIN));
        assertFalse(text.contains(Files.readString(directory.resolve("admin-token")).trim()));
    }

    @Test void attestedHistoryBoundariesUseTheFullResetTransaction() throws Exception {
        for (int[] boundary : new int[][]{{14446, 14447}, {65534, 65535}, {65535, 65536}}) {
            Path config = fixture();
            if (boundary[0] == 14446) Files.writeString(config, "isolation.key=" + "01".repeat(32) + "\ni2p.nextPort=14447\n");
            var output = new ByteArrayOutputStream();var stream = new PrintStream(output, true, StandardCharsets.UTF_8);
            assertEquals(0, OfflineRecovery.run(new String[]{"--discard-restored-credentials", "--staged-config", config.toString(),
                    "--highest-allocated-i2p-port", Integer.toString(boundary[0]), "--ack-complete-i2p-port-history"}, stream, stream));
            assertEquals(Integer.toString(boundary[1]), ProxyConfig.read(config).getProperty("i2p.nextPort"));
            assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
            assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
            assertNotEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
            assertFalse(Files.exists(directory.resolve("manager.properties")));
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
            assertTrue(output.toString(StandardCharsets.UTF_8).contains("operator-attested and was not verified"));
        }
    }

    @Test void invalidOrIncompleteAttestationNeverStartsRecovery() throws Exception {
        Path config = fixture();
        var stream = new PrintStream(new ByteArrayOutputStream(), true, StandardCharsets.UTF_8);
        String[] base = {"--discard-restored-credentials", "--staged-config", config.toString()};
        for (String[] extra : new String[][]{
                {"--highest-allocated-i2p-port", "14446"}, {"--ack-complete-i2p-port-history"},
                {"--last-allocated-i2p-port", "14446", "--ack-complete-i2p-port-history"},
                {"--highest-allocated-i2p-port", "14445", "--ack-complete-i2p-port-history"},
                {"--highest-allocated-i2p-port", "65536", "--ack-complete-i2p-port-history"},
                {"--highest-allocated-i2p-port", "-1", "--ack-complete-i2p-port-history"},
                {"--highest-allocated-i2p-port", "100000000000000000000", "--ack-complete-i2p-port-history"},
                {"--highest-allocated-i2p-port", "abc", "--ack-complete-i2p-port-history"},
                {"--ack-complete-i2p-port-history", "--highest-allocated-i2p-port", "14446"},
                {"--highest-allocated-i2p-port", "14446", "--ack-complete-i2p-port-history", "--ack-complete-i2p-port-history"}}) {
            String[] args = java.util.stream.Stream.concat(java.util.Arrays.stream(base), java.util.Arrays.stream(extra)).toArray(String[]::new);
            assertEquals(2, OfflineRecovery.run(args, stream, stream));
            assertEquals(CONFIG, Files.readString(config));
            assertEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
            assertEquals("running\n", Files.readString(directory.resolve("proxy-desired")));
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        }
    }

    @Test void attestedHistoryRejectsContradictionsAndMalformedArchiveBeforeMutation() throws Exception {
        for (String archived : new String[]{
                "i2p.nextPort=15002\n", "i2p.nextPort=garbage\n", "i2p.nextPort=14446\n", "i2p.nextPort=65537\n",
                "i2p.nextPort=15001\nprofile.orphan.i2pPort=15001\n",
                "i2p.nextPort=15001\nprofile.orphan.i2pPort=bad\n",
                "i2p.nextPort=15001\nprofile.orphan.i2pPort=65536\n"}) {
            Path config = fixture();
            String input = "isolation.key=" + "01".repeat(32) + "\n" + archived;
            Files.writeString(config, input);
            assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles(), "15001"));
            assertEquals(input, Files.readString(config));
            assertEquals(ADMIN + "\n", Files.readString(directory.resolve("admin-token")));
            assertEquals("running\n", Files.readString(directory.resolve("proxy-desired")));
            assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
            OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
            assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
        }
    }

    @Test void priorExhaustedSentinelIsAmbiguousAndAttestationMustResolveIt() throws Exception {
        Path config = fixture();
        Files.writeString(config, "isolation.key=" + "01".repeat(32) + "\ni2p.nextPort=65536\n");
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles(), "15001");
        assertEquals("15001", ProxyConfig.read(config).getProperty("i2p.nextPort"));
    }

    @Test void attestedReplacementFailureKeepsGateAndRerunPerformsFullReset() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void move(Path source, Path target) throws IOException {
                if (target.equals(config)) throw new IOException("injected");
                super.move(source, target);
            }
        }, "15001"));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
        assertEquals(CONFIG, Files.readString(config));
        assertEquals("stopped\n", Files.readString(directory.resolve("proxy-desired")));
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles(), "15001");
        assertEquals("15001", ProxyConfig.read(config).getProperty("i2p.nextPort"));
        assertTrue(ProxyConfig.loadProfiles(config).isEmpty());
        assertFalse(Files.exists(directory.resolve("recovery-incomplete")));
        String previousAdmin = Files.readString(directory.resolve("admin-token"));
        OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles());
        assertEquals("65536", ProxyConfig.read(config).getProperty("i2p.nextPort"));
        assertNotEquals(previousAdmin, Files.readString(directory.resolve("admin-token")));
    }

    @Test void attestedReadbackMismatchKeepsRecoveryGate() throws Exception {
        Path config = fixture();
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(config, new OfflineRecovery.AtomicFiles() {
            @Override void delete(Path path) throws IOException {
                super.delete(path);
                if (path.getFileName().toString().equals("manager.properties"))
                    Files.writeString(config, Files.readString(config).replace("i2p.nextPort=15001", "i2p.nextPort=14447"));
            }
        }, "15001"));
        assertTrue(Files.exists(directory.resolve("recovery-incomplete")));
    }

    private Path fixture() throws Exception {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"));
        for (var entry : java.util.Map.of("proxy.properties", CONFIG, "admin-token", ADMIN + "\n",
                "proxy-desired", "running\n", "manager.properties", "manager.token=" + ADMIN + "\n").entrySet()) {
            Path path = directory.resolve(entry.getKey());Files.writeString(path, entry.getValue());
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        }
        return directory.resolve("proxy.properties");
    }

    private void assertNoTemporaryFiles() throws IOException {
        try (var paths = Files.list(directory)) { assertTrue(paths.noneMatch(path -> path.getFileName().toString().startsWith(".recovery-"))); }
    }
}
