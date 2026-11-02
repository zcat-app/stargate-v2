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

class CaptureWorkNativeTest {
    private static final String AGE="eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c", KEY="0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899";
    @TempDir Path temp;
    private static Path dir(Path p)throws Exception{Files.createDirectory(p);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------"));return p;}
    @Test void capturesEncryptsAndVerifiesBeforeNoReplacePublication() throws Exception {
        String age=System.getenv("STARGATE_TEST_AGE"),keygen=System.getenv("STARGATE_TEST_AGE_KEYGEN");assumeTrue(age!=null&&keygen!=null);
        assertEquals(AGE,sha(Path.of(age)));assertEquals(KEY,sha(Path.of(keygen)));Path key=temp.resolve("key"),info=temp.resolve("info");
        Process p=new ProcessBuilder(keygen,"--output",key.toString()).redirectError(info.toFile()).start();assertTrue(p.waitFor(10,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,p.exitValue());
        var match=Pattern.compile("age1[0-9a-z]{58}").matcher(Files.readString(info));assertTrue(match.find());
        Path source=dir(temp.resolve("source")),out=dir(temp.resolve("out"));for(String role:DockerPolicy.BASE)dir(source.resolve(role));
        Path file=Files.writeString(source.resolve("app-data/file"),"synthetic");Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));
        Path core=Files.writeString(temp.resolve("core.jar"),"core"),adapter=Files.writeString(temp.resolve("adapter.jar"),"adapter");int uid=Linux.uid("geteuid"),gid=Linux.uid("getegid");
        Path result=out.resolve("archive.age");
        try(AgeDecrypt.Session pinned=AgeDecrypt.open(Path.of(age),AGE,key,uid);CaptureWork work=new CaptureWork(result,"a".repeat(32),core,adapter,uid,gid)) {
            work.guard(true);CaptureHelper.capture(source,work.spool,false,uid);work.guard(false);work.prepare(pinned,match.group(),false);work.publish();
        }
        assertTrue(Files.size(result)>0);try(var entries=Files.list(out)){assertEquals(1,entries.count());}
        assertThrows(Exception.class,()->new CaptureWork(result,"b".repeat(32),core,adapter,uid,gid));
    }
    private static String sha(Path p)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p)));}
}
