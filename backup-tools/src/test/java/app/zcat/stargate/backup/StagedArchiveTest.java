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

class StagedArchiveTest {
    @TempDir Path temp;
    private Path dir(String name) throws Exception {
        Path p = Files.createDirectory(temp.resolve(name)); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------")); return p;
    }
    private int run(Path work, Path output, String scenario) throws Exception {
        String classes = Path.of(StagedArchive.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(StageProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Process p = new ProcessBuilder(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, StageProbe.class.getName(), work.toString(), output.toString(), scenario))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD).start();
        assertTrue(p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); return p.exitValue();
    }
    @Test void publishesOnlyCompleteGatedTree() throws Exception {
        Path work = dir("work"), out = dir("output"); assertEquals(0, run(work, out, "success"));
        assertEquals("synthetic", Files.readString(out.resolve("staged/app-data/file")));
        assertEquals("Offline staged recovery incomplete; rerun before starting.\n", Files.readString(out.resolve("staged/app-data/recovery-incomplete")));
        assertEquals("identity", Files.readString(out.resolve("staged/app-data/identity-recovery-incomplete")));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out.resolve("staged/app-data/recovery-incomplete"))));
        assertEquals(1_500_000_000_000L, Files.getLastModifiedTime(out.resolve("staged/app-data/file")).toMillis());
        try (var entries = Files.list(work)) { assertEquals(0, entries.count()); }
    }
    @Test void failuresCleanPrivateStageAndNeverReplaceExistingOutput() throws Exception {
        Path work = dir("work"), out = dir("output");
        for (String scenario : List.of("fail", "unsafe", "open-root", "unreadable", "before-publish")) {
            assertNotEquals(0, run(work, out, scenario)); assertFalse(Files.exists(out.resolve("staged")));
            try (var entries = Files.list(work)) { assertEquals(0, entries.count()); }
        }
        Files.writeString(out.resolve("staged"), "existing");
        assertNotEquals(0, run(work, out, "success")); assertEquals("existing", Files.readString(out.resolve("staged")));
        try (var entries = Files.list(work)) { assertEquals(0, entries.count()); }
    }
    @Test void failureAfterPublicationLeavesGatedTree() throws Exception {
        Path work = dir("work"), out = dir("output");
        assertNotEquals(0, run(work, out, "after-publish"));
        assertEquals("Offline staged recovery incomplete; rerun before starting.\n", Files.readString(out.resolve("staged/app-data/recovery-incomplete")));
        assertEquals("synthetic", Files.readString(out.resolve("staged/app-data/file")));
    }
    @Test void validatesThenStagesARealUstarStream() throws Exception {
        Path work = dir("work"), out = dir("output");
        int uid = ((Number) Files.getAttribute(temp, "unix:uid")).intValue();
        int gid = ((Number) Files.getAttribute(temp, "unix:gid")).intValue();
        var members = new java.util.ArrayList<ArchiveInspectorTest.Member>();
        for (String root : ArchiveInspector.BASE.stream().sorted().toList())
            members.add(new ArchiveInspectorTest.Member(root, '5', 0700, uid, gid, new byte[0]));
        members.add(new ArchiveInspectorTest.Member("app-data/file", '0', 0600, uid, gid, "data".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        Path archive = temp.resolve("synthetic.tar"); Files.write(archive, ArchiveInspectorTest.archive(members));
        String classes = Path.of(StagedArchive.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(StageProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Process p = new ProcessBuilder(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, StageProbe.class.getName(), work.toString(), out.toString(), "tar", archive.toString())).start();
        assertTrue(p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, p.exitValue(), new String(p.getErrorStream().readAllBytes()));
        assertEquals("data", Files.readString(out.resolve("staged/app-data/file")));
    }
}
