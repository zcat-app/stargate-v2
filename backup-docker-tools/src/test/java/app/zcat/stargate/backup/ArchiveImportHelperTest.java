// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class ArchiveImportHelperTest {
    @TempDir Path temp;
    private static Path directory(Path path) throws Exception { Files.createDirectory(path); Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rwx------")); return path; }
    @Test void stagesOnlyMatchingSpoolAndImportsWithCredentialGate() throws Exception {
        int uid=Linux.uid("geteuid"),gid=Linux.uid("getegid");
        Path scratch=directory(temp.resolve("scratch")),destination=directory(temp.resolve("destination"));
        for(String root:DockerPolicy.BASE) directory(destination.resolve(root));
        byte[] archive=ArchivePreflightTest.archive(uid,gid,0700,false); Path spool=temp.resolve("input.tar"); Files.write(spool,archive);
        Files.setPosixFilePermissions(spool,PosixFilePermissions.fromString("r--r--r--"));
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archive));
        assertThrows(Exception.class,()->ArchiveImportHelper.run(spool,scratch,destination,"0".repeat(64),false,uid,gid));
        try(var paths=Files.list(scratch)){assertEquals(0,paths.count());}
        try(var paths=Files.list(destination.resolve("app-data"))){assertEquals(0,paths.count());}
        ArchiveImportHelper.run(spool,scratch,destination,hash,false,uid,gid);
        assertTrue(Files.exists(destination.resolve("app-data/recovery-incomplete")));
        assertFalse(Files.exists(destination.resolve("app-data/volume-import-incomplete")));
    }
    @Test void refusesIncompleteImportMarkerBeforeCreatingStage() throws Exception {
        int uid=Linux.uid("geteuid"),gid=Linux.uid("getegid"); Path scratch=directory(temp.resolve("scratch")),destination=directory(temp.resolve("destination"));
        for(String root:DockerPolicy.BASE) directory(destination.resolve(root));
        byte[] archive=ArchivePreflightTest.archive(uid,gid,0700,true); Path spool=temp.resolve("input.tar"); Files.write(spool,archive);
        Files.setPosixFilePermissions(spool,PosixFilePermissions.fromString("r--r--r--"));
        String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(archive));
        assertThrows(Exception.class,()->ArchiveImportHelper.run(spool,scratch,destination,hash,false,uid,gid));
        try(var paths=Files.list(scratch)){assertEquals(0,paths.count());}
    }
}
