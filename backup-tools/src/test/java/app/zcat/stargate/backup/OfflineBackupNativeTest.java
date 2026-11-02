// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Opt-in full commands use newly generated synthetic keys and temporary roots only. */
class OfflineBackupNativeTest {
    private static final String AGE_HASH = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c";
    private static final String KEYGEN_HASH = "0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899";
    @TempDir Path temp;
    Path age, keygen, source, output, stage, work, key;
    String recipient, javaCommand, classes;
    record Result(int code, String out, String err) {}
    @BeforeEach void setup() throws Exception {
        String a = System.getenv("STARGATE_TEST_AGE"), k = System.getenv("STARGATE_TEST_AGE_KEYGEN");
        assumeTrue(a != null && k != null, "Explicit pinned age and age-keygen binaries required");
        age = Path.of(a); keygen = Path.of(k); assertEquals(AGE_HASH, sha(age)); assertEquals(KEYGEN_HASH, sha(keygen));
        javaCommand = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        classes = Path.of(OfflineVerify.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        source = directory(temp.resolve("source")); output = directory(temp.resolve("output")); stage = directory(temp.resolve("stage")); work = directory(temp.resolve("work"));
        for (String root : ArchiveInspector.BASE) directory(source.resolve(root));
        Path file = Files.writeString(source.resolve("app-data/file"), "x".repeat(179200)); mode(file, "rw-------");
        key = temp.resolve("synthetic-key"); recipient = key(key);
    }
    private static Path directory(Path path) throws Exception { Files.createDirectory(path); mode(path, "rwx------"); return path; }
    private static void mode(Path path, String value) throws Exception { Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(value)); }
    private static String sha(Path path) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))); }
    private Result command(List<String> args) throws Exception {
        Path stdout = Files.createTempFile(temp, "out", ".txt"), stderr = Files.createTempFile(temp, "err", ".txt");
        ProcessBuilder b = new ProcessBuilder(args).redirectOutput(stdout.toFile()).redirectError(stderr.toFile());
        b.environment().clear(); b.environment().put("PATH", "/nonexistent"); b.environment().put("LANG", "C");
        Process p = b.start();
        try { assertTrue(p.waitFor(40, java.util.concurrent.TimeUnit.SECONDS)); return new Result(p.exitValue(), Files.readString(stdout), Files.readString(stderr)); }
        finally { if (p.isAlive()) { p.descendants().forEach(ProcessHandle::destroyForcibly); p.destroyForcibly(); } }
    }
    private String key(Path path) throws Exception {
        Result r = command(List.of(keygen.toString(), "--output", path.toString())); assertEquals(0, r.code, r.err);
        var m = Pattern.compile("age1[0-9a-z]{58}").matcher(r.err); assertTrue(m.find()); return m.group();
    }
    private Result backup(Path identity, String... args) throws Exception {
        var command = new ArrayList<>(List.of(javaCommand, "--enable-native-access=ALL-UNNAMED", "-cp", classes, OfflineVerify.class.getName(),
                "--age", age.toString(), "--age-sha256", AGE_HASH, "--identity", identity.toString()));
        command.addAll(List.of(args)); return command(command);
    }
    private List<String> probeCommand(String failure, Path sentinel, String... args) throws Exception {
        String tests = Path.of(OfflineFailureProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var command = new ArrayList<>(List.of(javaCommand, "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, OfflineFailureProbe.class.getName(), failure, sentinel.toString(),
                "--age", age.toString(), "--age-sha256", AGE_HASH, "--identity", key.toString()));
        command.addAll(List.of(args)); return command;
    }
    private Result probe(String failure, Path sentinel, String... args) throws Exception { return command(probeCommand(failure, sentinel, args)); }
    private Result pack(Path dest, String recipient, boolean nym) throws Exception {
        if (nym) return backup(key, "pack", "--source", source.toString(), "--output", dest.toString(), "--recipient", recipient, "--nym");
        return backup(key, "pack", "--source", source.toString(), "--output", dest.toString(), "--recipient", recipient);
    }
    private Result verify(Path archive) throws Exception { return backup(key, "verify", "--archive", archive.toString(), "--work-dir", work.toString()); }
    private Result stage(Path archive, Path dest) throws Exception { return backup(key, "stage", "--archive", archive.toString(), "--output", dest.toString()); }
    private static void empty(Path dir) throws Exception { try (var paths = Files.list(dir)) { assertEquals(0, paths.count()); } }
    @Test void packVerifyStageAndImportFiveAndSevenRoots() throws Exception {
        Path transaction = Files.writeString(source.resolve("app-data/identity-recovery-incomplete"), "identity transaction"); mode(transaction, "rw-------");
        Path oldGate = Files.writeString(source.resolve("app-data/recovery-incomplete"), "old marker"); mode(oldGate, "rw-------");
        for (boolean nym : List.of(false, true)) {
            if (nym) for (String root : List.of("nym-data", "nym-secrets")) directory(source.resolve(root));
            Path archive = output.resolve(nym ? "seven.age" : "five.age");
            Result packed = pack(archive, recipient, nym); assertEquals(0, packed.code, packed.err); assertTrue(packed.out.startsWith("ENCRYPTED_ARCHIVE_VERIFIED ")); assertEquals("", packed.err);
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(archive)));
            Result checked = verify(archive); assertEquals(0, checked.code, checked.err); assertEquals(packed.out, checked.out); empty(work);
            Path staged = stage.resolve(nym ? "seven" : "five");
            Result stagedResult = stage(archive, staged); assertEquals(0, stagedResult.code, stagedResult.err); assertTrue(stagedResult.out.startsWith("OFFLINE_STAGE_CREATED_RECOVERY_REQUIRED "));
            assertEquals("x".repeat(179200), Files.readString(staged.resolve("app-data/file")));
            assertEquals("identity transaction", Files.readString(staged.resolve("app-data/identity-recovery-incomplete")));
            assertEquals("Offline staged recovery incomplete; rerun before starting.\n", Files.readString(staged.resolve("app-data/recovery-incomplete")));
            Path dest = directory(temp.resolve(nym ? "dest-seven" : "dest-five"));
            for (String root : nym ? ArchiveInspector.ALL : ArchiveInspector.BASE) directory(dest.resolve(root));
            var command = new ArrayList<>(List.of(javaCommand, "--enable-native-access=ALL-UNNAMED", "-cp", classes, VolumeImport.class.getName(), "--source", staged.toString(), "--destination", dest.toString()));
            if (nym) command.add("--nym"); Result imported = command(command); assertEquals(0, imported.code, imported.err);
            assertEquals("x".repeat(179200), Files.readString(dest.resolve("app-data/file")));
            assertTrue(Files.exists(dest.resolve("app-data/recovery-incomplete"))); assertFalse(Files.exists(dest.resolve("app-data/volume-import-incomplete")));
        }
        try (var entries = Files.list(output)) { assertEquals(2, entries.count()); }
    }
    @Test void wrongRecipientAndExistingDestinationsNeverPublish() throws Exception {
        String wrong = key(temp.resolve("wrong-key")); Path bad = output.resolve("wrong.age");
        Result mismatch = pack(bad, wrong, false); assertNotEquals(0, mismatch.code); assertTrue(mismatch.out.isEmpty()); assertFalse(Files.exists(bad)); empty(output);
        Path archive = output.resolve("archive.age"); assertEquals(0, pack(archive, recipient, false).code);
        byte[] original = Files.readAllBytes(archive); assertNotEquals(0, pack(archive, recipient, false).code); assertArrayEquals(original, Files.readAllBytes(archive));
        Path staged = stage.resolve("existing"); Files.writeString(staged, "keep"); assertNotEquals(0, stage(archive, staged).code); assertEquals("keep", Files.readString(staged));
        Path missing = temp.resolve("must-not-be-created"), outputLink = output.resolve("link.age"), stageLink = stage.resolve("link");
        Files.createSymbolicLink(outputLink, missing); Files.createSymbolicLink(stageLink, missing);
        assertNotEquals(0, pack(outputLink, recipient, false).code); assertTrue(Files.isSymbolicLink(outputLink)); assertFalse(Files.exists(missing));
        assertNotEquals(0, stage(archive, stageLink).code); assertTrue(Files.isSymbolicLink(stageLink)); assertFalse(Files.exists(missing));
        try (var entries = Files.list(output)) { assertEquals(2, entries.count()); }
        try (var entries = Files.list(stage)) { assertEquals(2, entries.count()); }
    }
    @Test void lateAuthenticationFailureAndIncompleteImportAreNeverStaged() throws Exception {
        Path archive = output.resolve("archive.age"); assertEquals(0, pack(archive, recipient, false).code);
        byte[] ciphertext = Files.readAllBytes(archive); ciphertext[ciphertext.length - 1] ^= 1;
        Path altered = output.resolve("altered.age"); Files.write(altered, ciphertext);
        Result bad = stage(altered, stage.resolve("bad")); assertNotEquals(0, bad.code); assertTrue(bad.out.isEmpty()); empty(stage);
        Path marker = Files.writeString(source.resolve("app-data/volume-import-incomplete"), "partial"); mode(marker, "rw-------");
        Path incomplete = output.resolve("incomplete.age"); assertEquals(0, pack(incomplete, recipient, false).code);
        assertEquals(0, verify(incomplete).code); assertNotEquals(0, stage(incomplete, stage.resolve("incomplete")).code); empty(stage); empty(work);
    }
    @Test void stagingRejectsUnmappedOwnershipBeforeExtraction() throws Exception {
        int uid = ((Number) Files.getAttribute(temp, "unix:uid")).intValue();
        int gid = ((Number) Files.getAttribute(temp, "unix:gid")).intValue();
        int other = uid == 07777777 ? uid - 1 : uid + 1;
        var members = new ArrayList<ArchiveInspectorTest.Member>();
        for (String root : ArchiveInspector.BASE.stream().sorted().toList()) members.add(new ArchiveInspectorTest.Member(root, '5', 0700, other, gid, new byte[0]));
        Path tar = temp.resolve("other-owner.tar"), encrypted = output.resolve("other-owner.age");
        Files.write(tar, ArchiveInspectorTest.archive(members));
        Result made = command(List.of(age.toString(), "--encrypt", "--recipient", recipient, "--output", encrypted.toString(), tar.toString()));
        assertEquals(0, made.code, made.err); assertEquals(0, verify(encrypted).code);
        assertNotEquals(0, stage(encrypted, stage.resolve("other-owner")).code); empty(stage); empty(work);
    }
    @Test void verificationRemainsIndependentOfStageAndImportEligibility() throws Exception {
        int uid = ((Number) Files.getAttribute(temp, "unix:uid")).intValue();
        int gid = ((Number) Files.getAttribute(temp, "unix:gid")).intValue();
        for (String scenario : List.of("open-root", "unreadable")) {
            var members = new ArrayList<ArchiveInspectorTest.Member>();
            for (String root : ArchiveInspector.BASE.stream().sorted().toList())
                members.add(new ArchiveInspectorTest.Member(root, '5', scenario.equals("open-root") && root.equals("tor-data") ? 0755 : 0700, uid, gid, new byte[0]));
            members.add(new ArchiveInspectorTest.Member("tor-data/file", '0', scenario.equals("unreadable") ? 0200 : 0600, uid, gid, new byte[]{1}));
            Path tar = temp.resolve(scenario + ".tar"), encrypted = output.resolve(scenario + ".age");
            Files.write(tar, ArchiveInspectorTest.archive(members));
            Result made = command(List.of(age.toString(), "--encrypt", "--recipient", recipient, "--output", encrypted.toString(), tar.toString()));
            assertEquals(0, made.code, made.err);
            assertEquals(0, verify(encrypted).code, scenario);
            assertNotEquals(0, stage(encrypted, stage.resolve(scenario)).code, scenario); empty(stage); empty(work);
        }
        Path root = source.resolve("tor-data"); mode(root, "rwxr-xr-x");
        Path rejected = output.resolve("rejected.age"); assertNotEquals(0, pack(rejected, recipient, false).code); assertFalse(Files.exists(rejected));
        mode(root, "rwx------");
    }
    @Test void recoveryCommandAcceptsImportedSyntheticStage() throws Exception {
        String recovery = System.getenv("STARGATE_TEST_RECOVERY_JAR");
        assumeTrue(recovery != null, "Explicit matching recovery jar required");
        Path config = Files.writeString(source.resolve("app-data/proxy.properties"), "isolation.key=" + "01".repeat(32) + "\nprofile.old.token=" + "a".repeat(43) + "\n"); mode(config, "rw-------");
        Path token = Files.writeString(source.resolve("app-data/admin-token"), "b".repeat(43) + "\n"); mode(token, "rw-------");
        Path archive = output.resolve("archive.age"), staged = stage.resolve("staged");
        Result packed = pack(archive, recipient, false); assertEquals(0, packed.code, packed.err);
        Result extracted = stage(archive, staged); assertEquals(0, extracted.code, extracted.err);
        Path dest = directory(temp.resolve("destination")); for (String root : ArchiveInspector.BASE) directory(dest.resolve(root));
        Result imported = command(List.of(javaCommand, "--enable-native-access=ALL-UNNAMED", "-cp", classes, VolumeImport.class.getName(), "--source", staged.toString(), "--destination", dest.toString()));
        assertEquals(0, imported.code, imported.err);
        Path app = dest.resolve("app-data");
        Result prepared = command(List.of(javaCommand, "-cp", recovery, "app.zcat.stargate.proxy.OfflineRecovery", "--discard-restored-credentials", "--staged-config", app.resolve("proxy.properties").toString()));
        assertEquals(0, prepared.code, prepared.err); assertTrue(prepared.out.startsWith("STAGED_RECOVERY_PREPARED"));
        assertFalse(Files.exists(app.resolve("recovery-incomplete"))); assertFalse(Files.readString(app.resolve("proxy.properties")).contains("profile.old"));
        assertTrue(Files.readString(app.resolve("proxy.properties")).contains("i2p.nextPort=65536"));
        assertEquals("stopped\n", Files.readString(app.resolve("proxy-desired"))); assertNotEquals("b".repeat(43) + "\n", Files.readString(app.resolve("admin-token")));
    }
    @Test void identityAndArchiveMustBeOutsideWorkingDirectories() throws Exception {
        Path nested = Files.copy(key, source.resolve("app-data/key")); mode(nested, "rw-------");
        Path dest = output.resolve("archive.age");
        assertNotEquals(0, backup(nested, "pack", "--source", source.toString(), "--output", dest.toString(), "--recipient", recipient).code); assertFalse(Files.exists(dest));
        Files.delete(nested); Path insideOutput = Files.copy(key, output.resolve("key")); mode(insideOutput, "rw-------");
        assertNotEquals(0, backup(insideOutput, "pack", "--source", source.toString(), "--output", dest.toString(), "--recipient", recipient).code); assertFalse(Files.exists(dest));
    }
    @Test void failedAuthenticationAndTimeoutNeverInspectPartialPlaintext() throws Exception {
        Path archive = output.resolve("archive.age"); assertEquals(0, pack(archive, recipient, false).code);
        byte[] ciphertext = Files.readAllBytes(archive); ciphertext[ciphertext.length - 1] ^= 1;
        Path altered = output.resolve("tampered.age"); Files.write(altered, ciphertext); Path inspected = temp.resolve("inspected");
        Result bad = probe("observe-inspection", inspected, "stage", "--archive", altered.toString(), "--output", stage.resolve("bad").toString());
        assertNotEquals(0, bad.code); assertFalse(Files.exists(inspected)); empty(stage);
        Result timeout = probe("age-timeout", inspected, "verify", "--archive", archive.toString(), "--work-dir", work.toString());
        assertNotEquals(0, timeout.code); assertTrue(timeout.out.isEmpty()); assertFalse(Files.exists(inspected)); empty(work);
    }
    @Test void cleanupAndPublicationFailuresReportRetainedPrivateLocations() throws Exception {
        Path archive = output.resolve("archive.age"); assertEquals(0, pack(archive, recipient, false).code);
        for (String mode : List.of("cleanup-file", "cleanup-dir")) {
            Result failure = probe(mode, temp.resolve("unused"), "verify", "--archive", archive.toString(), "--work-dir", work.toString());
            assertNotEquals(0, failure.code); assertTrue(failure.out.isEmpty());
            Path retained; try (var paths = Files.list(work)) { retained = paths.findFirst().orElseThrow(); }
            assertTrue(failure.err.contains(retained.toString()));
            try (var children = Files.list(retained)) {
                List<Path> files = children.toList();
                if (mode.equals("cleanup-file")) assertEquals(List.of("verified.tar"), files.stream().map(p -> p.getFileName().toString()).toList());
                else assertTrue(files.isEmpty());
                for (Path file : files) Files.delete(file);
            }
            Files.delete(retained);
        }
        Path published = output.resolve("unconfirmed.age");
        Result linkFailure = probe("pack-publish", temp.resolve("unused"), "pack", "--source", source.toString(), "--output", published.toString(), "--recipient", recipient);
        assertNotEquals(0, linkFailure.code); assertTrue(linkFailure.out.isEmpty()); assertTrue(Files.exists(published));
        Path privateOutput; try (var paths = Files.list(output)) { privateOutput = paths.filter(p -> p.getFileName().toString().startsWith(".stargate-backup-")).findFirst().orElseThrow(); }
        assertTrue(linkFailure.err.contains(privateOutput.toString())); empty(privateOutput); Files.delete(privateOutput);
        Path staged = stage.resolve("unconfirmed");
        Result stageFailure = probe("stage-publish", temp.resolve("unused"), "stage", "--archive", archive.toString(), "--output", staged.toString());
        assertNotEquals(0, stageFailure.code); assertTrue(stageFailure.out.isEmpty());
        assertEquals("Offline staged recovery incomplete; rerun before starting.\n", Files.readString(staged.resolve("app-data/recovery-incomplete")));
        Path privateStage; try (var paths = Files.list(stage)) { privateStage = paths.filter(p -> p.getFileName().toString().startsWith(".stargate-backup-")).findFirst().orElseThrow(); }
        assertTrue(stageFailure.err.contains(privateStage.toString())); empty(privateStage); Files.delete(privateStage);
    }
    @Test void sigtermKillsTheAgeChildAndCleansPrivatePlaintext() throws Exception {
        Path archive = output.resolve("archive.age"); assertEquals(0, pack(archive, recipient, false).code);
        Path barrier = temp.resolve("signal-ready");
        Process p = new ProcessBuilder(probeCommand("signal", barrier, "verify", "--archive", archive.toString(), "--work-dir", work.toString()))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
            while (!Files.exists(barrier) && p.isAlive() && System.nanoTime() < deadline) Thread.sleep(20);
            assertTrue(Files.exists(barrier)); List<ProcessHandle> children = p.descendants().toList();
            p.destroy(); assertTrue(p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS));
            for (ProcessHandle child : children) assertFalse(child.isAlive());
            empty(work);
        } finally { if (p.isAlive()) { p.descendants().forEach(ProcessHandle::destroyForcibly); p.destroyForcibly(); } }
    }
}
