// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import static org.junit.jupiter.api.Assertions.*;

class DurableJournalTest {
    @TempDir Path temp;
    @Test void createsPrivateNoReplaceJournalAndRecordsIntent() throws Exception {
        Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rwx------"));
        int uid = Linux.uid("geteuid"), gid = Linux.uid("getegid"); String token = "a".repeat(32); Path file;
        try (var journal = new DurableJournal(temp, "stargate-import-", token, uid, gid)) {
            file = journal.path; journal.record("planned", Map.of("token", token)); journal.record("volume_create_intent", Map.of("role", "app-data"));
            assertThrows(Exception.class, () -> new DurableJournal(temp, "stargate-import-", token, uid, gid));
        }
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        var lines = Files.readAllLines(file); assertEquals(2, lines.size());
        assertEquals("planned", DockerPolicy.parse(lines.get(0)).path("event").asText());
        assertEquals("volume_create_intent", DockerPolicy.parse(lines.get(1)).path("event").asText());
    }
    @Test void rejectsSymlinkAndUnsafeJournalParents() throws Exception {
        Path target = Files.createDirectory(temp.resolve("real")), link = temp.resolve("link");
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rwx------")); Files.createSymbolicLink(link, target);
        assertThrows(Exception.class, () -> new DurableJournal(link, "stargate-import-", "a".repeat(32), Linux.uid("geteuid"), Linux.uid("getegid")));
        assertThrows(Exception.class, () -> DurableJournal.safePath("/tmp/unsafe,name"));
    }
}
