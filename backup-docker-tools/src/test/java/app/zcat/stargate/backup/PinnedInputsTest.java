// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class PinnedInputsTest {
    @TempDir Path temp;
    private static Path dir(Path p) throws Exception { Files.createDirectory(p); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rwx------")); return p; }
    @Test void detectsSnapshotOrDirectoryReplacementAndPinsSource() throws Exception {
        Path source = dir(temp.resolve("source")), journal = dir(temp.resolve("journal"));
        Path core = Files.writeString(temp.resolve("core.jar"), "synthetic core"), adapter = Files.writeString(temp.resolve("adapter.jar"), "synthetic adapter");
        int uid = Linux.uid("geteuid"), gid = Linux.uid("getegid");
        try (PinnedInputs inputs = new PinnedInputs(source,journal,"a".repeat(32),core,adapter,uid,gid,uid,gid)) {
            inputs.check(); assertEquals("r--r--r--", PosixFilePermissions.toString(Files.getPosixFilePermissions(inputs.core)));
            Files.setPosixFilePermissions(inputs.core, PosixFilePermissions.fromString("rw-------")); Files.writeString(inputs.core,"changed");
            Files.setPosixFilePermissions(inputs.core, PosixFilePermissions.fromString("r--r--r--"));
            assertThrows(Exception.class, inputs::check);
        }
        try (PinnedInputs inputs = new PinnedInputs(source,journal,"b".repeat(32),core,adapter,uid,gid,uid,gid)) {
            Path original = journal.resolve("moved"); Files.move(inputs.directory, original); dir(inputs.directory);
            assertThrows(Exception.class, inputs::check);
        }
        Path link = temp.resolve("linked"); Files.createSymbolicLink(link, source);
        assertThrows(Exception.class, () -> new PinnedInputs(link,journal,"c".repeat(32),core,adapter,uid,gid,uid,gid));
    }
}
