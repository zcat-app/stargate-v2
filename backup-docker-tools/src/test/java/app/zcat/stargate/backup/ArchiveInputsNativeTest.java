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
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class ArchiveInputsNativeTest {
    private static final String AGE_HASH="eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c";
    private static final String KEY_HASH="0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899";
    @TempDir Path temp;
    @Test void authenticatesAndPinsSpoolBeforeAnyDockerTransportExists() throws Exception {
        String age=System.getenv("STARGATE_TEST_AGE"),keygen=System.getenv("STARGATE_TEST_AGE_KEYGEN"); assumeTrue(age!=null&&keygen!=null);
        assertEquals(AGE_HASH,sha(Path.of(age)));assertEquals(KEY_HASH,sha(Path.of(keygen)));
        Path base=Files.createDirectory(temp.resolve("private"));Files.setPosixFilePermissions(base,PosixFilePermissions.fromString("rwx------"));
        Path identity=temp.resolve("identity"),info=temp.resolve("info");Process key=new ProcessBuilder(keygen,"--output",identity.toString()).redirectError(info.toFile()).start();
        assertTrue(key.waitFor(10,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,key.exitValue());var m=Pattern.compile("age1[0-9a-z]{58}").matcher(Files.readString(info));assertTrue(m.find());
        Path tar=temp.resolve("data.tar"),archive=temp.resolve("data.age"),core=Files.writeString(temp.resolve("core.jar"),"synthetic"),adapter=Files.writeString(temp.resolve("adapter.jar"),"synthetic adapter");
        Files.write(tar,ArchivePreflightTest.archive(10001,0700,false));Process encrypt=new ProcessBuilder(age,"--encrypt","--recipient",m.group(),"--output",archive.toString(),tar.toString()).start();
        assertTrue(encrypt.waitFor(10,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,encrypt.exitValue());
        int uid=Linux.uid("geteuid"),gid=Linux.uid("getegid");
        try(ArchiveInputs inputs=new ArchiveInputs(base,"a".repeat(32),archive,identity,Path.of(age),AGE_HASH,core,adapter,uid,gid)) {
            assertFalse(inputs.nym);inputs.guardDigest();assertEquals("r--r--r--",PosixFilePermissions.toString(Files.getPosixFilePermissions(inputs.spool)));
            Files.setPosixFilePermissions(inputs.spool,PosixFilePermissions.fromString("rw-------"));Files.writeString(inputs.spool,"changed");
            Files.setPosixFilePermissions(inputs.spool,PosixFilePermissions.fromString("r--r--r--"));assertThrows(Exception.class,inputs::guardDigest);
        }
        byte[] changed=Files.readAllBytes(archive);changed[changed.length-1]^=1;Path bad=temp.resolve("bad.age");Files.write(bad,changed);
        assertThrows(Exception.class,()->new ArchiveInputs(base,"b".repeat(32),bad,identity,Path.of(age),AGE_HASH,core,adapter,uid,gid));
    }
    private static String sha(Path p)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
}
