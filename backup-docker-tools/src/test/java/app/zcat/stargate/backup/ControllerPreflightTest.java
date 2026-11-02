// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

/** Only rejected inputs are passed to these entry points: no Docker client can be reached. */
class ControllerPreflightTest {
    @TempDir Path temp;
    private static Path dir(Path p)throws Exception{Files.createDirectory(p);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------"));return p;}
    @Test void captureRejectsUntrustedAgeBeforeJournalOrDocker() throws Exception {
        Path out=dir(temp.resolve("output")),journals=dir(temp.resolve("journals"));Path fake=Files.write(temp.resolve("age"),new byte[]{0x7f,'E','L','F',1});
        Files.setPosixFilePermissions(fake,PosixFilePermissions.fromString("rwx------"));Path identity=Files.writeString(temp.resolve("identity"),"synthetic");
        Path selection=temp.resolve("selection.json");Files.writeString(selection,"{\"version\":1,\"volumes\":{\"app-data\":\"a\",\"tor-data\":\"b\",\"tor-control\":\"c\",\"i2p-data\":\"d\",\"i2p-control\":\"e\"},\"containers\":[]}");
        Files.setPosixFilePermissions(selection,PosixFilePermissions.fromString("rw-------"));Path core=Files.writeString(temp.resolve("core.jar"),"core"),adapter=Files.writeString(temp.resolve("adapter.jar"),"adapter");
        int result=DockerCaptureMain.run(new String[]{"--source-config",selection.toString(),"--output",out.resolve("archive.age").toString(),"--journal-dir",journals.toString(),"--helper-image","sha256:"+"a".repeat(64),
                "--age",fake.toString(),"--age-sha256","0".repeat(64),"--identity",identity.toString(),"--recipient","age1"+"a".repeat(58),"--core-jar",core.toString(),"--adapter-jar",adapter.toString(),
                "--ack-writers-stopped","--ack-matching-set","--ack-exclusive-local-daemon","--ack-reviewed-helper-image"});
        assertEquals(1,result);try(var files=Files.list(journals)){assertEquals(0,files.count());}try(var files=Files.list(out)){assertEquals(0,files.count());}
    }
}
