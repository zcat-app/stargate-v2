// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class VolumeSnapshotTest {
    @TempDir Path temp;
    private static void mode(Path p, String mode) throws Exception { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(mode)); }
    private Path source() throws Exception {
        Path root = Files.createDirectory(temp.resolve("source")); mode(root, "rwx------");
        for (String name : ArchiveInspector.BASE) { Path p = Files.createDirectory(root.resolve(name)); mode(p, "rwx------"); }
        Path file = Files.writeString(root.resolve("app-data/file"), "synthetic"); mode(file, "rw-------"); return root;
    }
    private int scan(Path root, boolean nym) throws Exception {
        String classes = Path.of(VolumeSnapshot.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(SnapshotProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        var args = new ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, SnapshotProbe.class.getName(), root.toString()));
        if (nym) args.add("--nym");
        Process p = new ProcessBuilder(args).redirectError(ProcessBuilder.Redirect.DISCARD).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(p.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)); return p.exitValue();
    }
    @Test void acceptsStoppedFiveAndSevenRootSets() throws Exception {
        Path root = source(); assertEquals(0, scan(root, false));
        for (String name : List.of("nym-data", "nym-secrets")) { Path p = Files.createDirectory(root.resolve(name)); mode(p, "rwx------"); }
        assertNotEquals(0, scan(root, false)); assertEquals(0, scan(root, true));
    }
    @Test void rejectsLinksUnsafeModesAndIncompleteGate() throws Exception {
        Path root = source(), item = root.resolve("tor-data/item");
        Files.createSymbolicLink(item, root.resolve("app-data/file")); assertNotEquals(0, scan(root, false)); Files.delete(item);
        Files.createLink(item, root.resolve("app-data/file")); assertNotEquals(0, scan(root, false)); Files.delete(item);
        mode(root.resolve("tor-data"), "rwxr-xr-x"); assertNotEquals(0, scan(root, false)); mode(root.resolve("tor-data"), "rwx------");
        Path nested = Files.createDirectory(item); mode(nested, "r-x------"); assertNotEquals(0, scan(root, false)); mode(nested, "rwx------"); Files.delete(nested);
        Path gate = Files.writeString(root.resolve("app-data/volume-import-incomplete"), "partial"); assertNotEquals(0, scan(root, false)); Files.delete(gate);
        Path old = Files.writeString(root.resolve("app-data/recovery-incomplete"), "old"); mode(old, "rw-r--r--"); assertNotEquals(0, scan(root, false)); mode(old, "rw-------"); assertEquals(0, scan(root, false));
    }
}
