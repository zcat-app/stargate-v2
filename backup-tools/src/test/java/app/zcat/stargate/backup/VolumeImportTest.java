// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class VolumeImportTest {
    private static final String GATE = "Offline staged recovery incomplete; rerun before starting.\n";
    private static final String IMPORT = "Offline volume import incomplete; discard and recreate the entire destination set.\n";
    @TempDir Path temp;
    private static void mode(Path p, String mode) throws Exception { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(mode)); }
    private Path root(String name, boolean nym) throws Exception {
        Path root = Files.createDirectory(temp.resolve(name)); mode(root, "rwx------");
        for (String child : nym ? ArchiveInspector.ALL : ArchiveInspector.BASE) { Path p = Files.createDirectory(root.resolve(child)); mode(p, "rwx------"); }
        return root;
    }
    private record Result(int code, String out, String err) {}
    private Result process(Class<?> entry, String... args) throws Exception {
        String classes = Path.of(VolumeImport.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(ImportProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var command = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, entry.getName()));
        command.addAll(List.of(args));
        Process p = new ProcessBuilder(command).start(); assertTrue(p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS));
        return new Result(p.exitValue(), new String(p.getInputStream().readAllBytes()), new String(p.getErrorStream().readAllBytes()));
    }
    private Result run(Path src, Path dst, boolean nym) throws Exception {
        return nym ? process(VolumeImport.class, "--source", src.toString(), "--destination", dst.toString(), "--nym")
                : process(VolumeImport.class, "--source", src.toString(), "--destination", dst.toString());
    }
    private void sourceFile(Path src) throws Exception {
        Path file = Files.writeString(src.resolve("app-data/file"), "synthetic"); mode(file, "rw-------");
    }
    @Test void copiesAndKeepsCredentialGateWithMetadata() throws Exception {
        Path src = root("source", false), dst = root("destination", false); sourceFile(src);
        Path oldGate = Files.writeString(src.resolve("app-data/recovery-incomplete"), "old"); mode(oldGate, "rw-------");
        Path marker = Files.writeString(src.resolve("app-data/identity-recovery-incomplete"), "identity transaction"); mode(marker, "rw-------");
        Path nested = Files.createDirectory(src.resolve("tor-data/nested")); mode(nested, "rwxr-xr-x");
        Path file = Files.writeString(nested.resolve("data"), "payload"); mode(file, "rw-------");
        FileTime time = FileTime.fromMillis(1_500_000_000_123L);
        for (Path p : List.of(file, nested, src.resolve("tor-data"), src.resolve("app-data"))) Files.setLastModifiedTime(p, time);
        Result r = run(src, dst, false); assertEquals(0, r.code, r.err); assertEquals("OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED\n", r.out);
        assertEquals("synthetic", Files.readString(dst.resolve("app-data/file")));
        assertEquals(GATE, Files.readString(dst.resolve("app-data/recovery-incomplete")));
        assertFalse(Files.exists(dst.resolve("app-data/volume-import-incomplete")));
        assertEquals("identity transaction", Files.readString(dst.resolve("app-data/identity-recovery-incomplete")));
        assertEquals("rwxr-xr-x", PosixFilePermissions.toString(Files.getPosixFilePermissions(dst.resolve("tor-data/nested"))));
        for (Path p : List.of(dst.resolve("tor-data/nested/data"), dst.resolve("tor-data/nested"), dst.resolve("tor-data"), dst.resolve("app-data")))
            assertEquals(1_500_000_000_000L, Files.getLastModifiedTime(p).toMillis());
    }
    @Test void copiesSevenRoots() throws Exception {
        Path src = root("source", true), dst = root("destination", true); sourceFile(src);
        Path secret = Files.writeString(src.resolve("nym-secrets/key"), "synthetic nym"); mode(secret, "rw-------");
        assertEquals(0, run(src, dst, true).code); assertEquals("synthetic nym", Files.readString(dst.resolve("nym-secrets/key")));
    }
    @Test void preflightRejectsUnsafeSetsBeforeAnyWrite() throws Exception {
        Path src = root("source", false), dst = root("destination", false); sourceFile(src);
        Path keep = Files.writeString(dst.resolve("tor-data/keep"), "keep");
        assertNotEquals(0, run(src, dst, false).code); assertEquals("keep", Files.readString(keep)); assertFalse(Files.exists(dst.resolve("app-data/recovery-incomplete"))); Files.delete(keep);
        Path incomplete = Files.writeString(src.resolve("app-data/volume-import-incomplete"), "partial");
        assertNotEquals(0, run(src, dst, false).code); assertFalse(Files.exists(dst.resolve("app-data/recovery-incomplete"))); Files.delete(incomplete);
        Path link = src.resolve("tor-data/link"); Files.createSymbolicLink(link, src.resolve("app-data/file"));
        assertNotEquals(0, run(src, dst, false).code); assertFalse(Files.exists(dst.resolve("app-data/recovery-incomplete")));
    }
    @Test void injectedFailureOrMutationLeavesDurableImportGate() throws Exception {
        for (String phase : List.of("import-gate-synced", "before-copy", "before-rescan", "after-unlink", "before-final-sync", "interrupt-before-copy", "interrupt-after-unlink")) {
            Path caseDir = Files.createDirectory(temp.resolve(phase)); Path oldTemp = temp; temp = caseDir;
            Path src = root("source", false), dst = root("destination", false); sourceFile(src);
            Result result = process(ImportProbe.class, src.toString(), dst.toString(), phase);
            assertEquals(0, result.code, phase + ": " + result.err);
            assertEquals(IMPORT, Files.readString(dst.resolve("app-data/volume-import-incomplete")));
            if (!phase.equals("import-gate-synced")) assertEquals(GATE, Files.readString(dst.resolve("app-data/recovery-incomplete")));
            assertNotEquals(0, run(src, dst, false).code); temp = oldTemp;
        }
    }
    @Test void sigtermDuringCopyLeavesBothGates() throws Exception {
        Path src = root("source", false), dst = root("destination", false); sourceFile(src);
        String classes = Path.of(VolumeImport.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(ImportProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Process process = new ProcessBuilder(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, ImportProbe.class.getName(), src.toString(), dst.toString(), "signal"))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        try {
            long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(15);
            while (!Files.exists(temp.resolve("signal-ready")) && process.isAlive() && System.nanoTime() < deadline) Thread.sleep(20);
            assertTrue(Files.exists(temp.resolve("signal-ready")), "Importer did not reach the test barrier");
            process.destroy(); assertTrue(process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS));
            assertEquals(IMPORT, Files.readString(dst.resolve("app-data/volume-import-incomplete")));
            assertEquals(GATE, Files.readString(dst.resolve("app-data/recovery-incomplete")));
            assertFalse(Files.exists(dst.resolve("app-data/file")));
        } finally { if (process.isAlive()) process.destroyForcibly(); }
    }
}
