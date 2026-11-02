// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ArchiveWriterTest {
    @TempDir Path temp;
    private static void mode(Path p, String value) throws Exception { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(value)); }
    private Path source(boolean nym) throws Exception {
        Path p = Files.createDirectory(temp.resolve("source")); mode(p, "rwx------");
        for (String name : nym ? ArchiveInspector.ALL : ArchiveInspector.BASE) { Path root = Files.createDirectory(p.resolve(name)); mode(root, "rwx------"); }
        Path file = Files.writeString(p.resolve("app-data/file"), "synthetic"); mode(file, "rw-------"); return p;
    }
    private int pack(Path source, String mode) throws Exception {
        Path output = temp.resolve("out-" + java.util.UUID.randomUUID());
        String classes = Path.of(ArchiveWriter.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(ArchiveWriterProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Process p = new ProcessBuilder(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, ArchiveWriterProbe.class.getName(), source.toString(), output.toString(), mode))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); return p.exitValue();
    }
    @Test void createsCanonicalValidatedArchiveWithLongUtf8Paths() throws Exception {
        Path source = source(false), nested = Files.createDirectory(source.resolve("app-data/" + "a".repeat(90))); mode(nested, "rwx------");
        Path file = Files.writeString(nested.resolve("café"), "payload"); mode(file, "rw-------");
        assertEquals(0, pack(source, "base"));
    }
    @Test void requiresBothNymRootsAndExplicitSelection() throws Exception {
        Path source = source(true); assertNotEquals(0, pack(source, "base")); assertEquals(0, pack(source, "nym"));
    }
    @Test void rejectsLinksUnsafeModesAndMutation() throws Exception {
        Path source = source(false), item = source.resolve("tor-data/item");
        Files.createSymbolicLink(item, source.resolve("app-data/file")); assertNotEquals(0, pack(source, "base")); Files.delete(item);
        Files.createLink(item, source.resolve("app-data/file")); assertNotEquals(0, pack(source, "base")); Files.delete(item);
        Files.setAttribute(source.resolve("app-data/file"), "unix:mode", 0104600); assertNotEquals(0, pack(source, "base")); mode(source.resolve("app-data/file"), "rw-------");
        assertNotEquals(0, pack(source, "mutate"));
    }
    @Test void requiresEverySourceRootPrivateAndCallerOwned() throws Exception {
        Path source = source(true);
        for (String name : ArchiveInspector.ALL) {
            Path root = source.resolve(name); mode(root, "rwxr-xr-x");
            assertNotEquals(0, pack(source, "nym"), name);
            mode(root, "rwx------");
        }
        assertEquals(0, pack(source, "nym"));
        Files.delete(source.resolve("nym-data")); Files.delete(source.resolve("nym-secrets"));
        assertNotEquals(0, pack(source, "other-uid"));
        assertNotEquals(0, pack(source, "other-gid"));
        assertEquals(0, pack(source, "base"));
    }
}
