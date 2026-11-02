// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class AgeDecryptNativeTest {
    private static final String AGE_HASH = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c";
    private static final String KEYGEN_HASH = "0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899";
    @TempDir Path temp;
    @Test void authenticatesBeforePreflightAndRejectsLateTampering() throws Exception {
        String age = System.getenv("STARGATE_TEST_AGE"), keygen = System.getenv("STARGATE_TEST_AGE_KEYGEN");
        assumeTrue(age != null && keygen != null, "Explicit pinned native binaries required");
        assertEquals(AGE_HASH,sha(Path.of(age))); assertEquals(KEYGEN_HASH,sha(Path.of(keygen)));
        Path identity=temp.resolve("identity"), info=temp.resolve("key-info");
        Process key = new ProcessBuilder(keygen,"--output",identity.toString()).redirectError(info.toFile()).start();
        assertTrue(key.waitFor(10,java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0,key.exitValue());
        var matcher=Pattern.compile("age1[0-9a-z]{58}").matcher(Files.readString(info)); assertTrue(matcher.find());
        Path tar=temp.resolve("synthetic.tar"), cipher=temp.resolve("archive.age"); Files.write(tar,ArchivePreflightTest.archive(10001,0700,false));
        Process encrypt=new ProcessBuilder(age,"--encrypt","--recipient",matcher.group(),"--output",cipher.toString(),tar.toString()).start();
        assertTrue(encrypt.waitFor(10,java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0,encrypt.exitValue());
        int uid=Linux.uid("geteuid"), input=Linux.openRegular(cipher,ArchiveInspector.MAX_ARCHIVE+32L*1024*1024,false,uid);
        Path spool=temp.resolve("spool"); int out=Linux.openAt(-100,spool.toString(),Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);
        try { AgeDecrypt.decrypt(Path.of(age),AGE_HASH,identity,input,out,uid); assertEquals(5,ArchivePreflight.inspect(out).summary().entries()); }
        finally {Linux.close(input);Linux.close(out);}
        int plain=Linux.openRegular(tar,ArchiveInspector.MAX_ARCHIVE,false,uid);
        Path produced=temp.resolve("produced.age"); int producedFd=Linux.openAt(-100,produced.toString(),Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);
        Path roundtrip=temp.resolve("roundtrip.tar"); int roundtripFd=Linux.openAt(-100,roundtrip.toString(),Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);
        try {
            AgeDecrypt.encrypt(Path.of(age),AGE_HASH,identity,plain,producedFd,uid,matcher.group());
            AgeDecrypt.decrypt(Path.of(age),AGE_HASH,identity,producedFd,roundtripFd,uid);
            assertEquals(5,ArchivePreflight.inspect(roundtripFd).summary().entries());
        } finally {Linux.close(plain);Linux.close(producedFd);Linux.close(roundtripFd);}
        byte[] changed=Files.readAllBytes(cipher); changed[changed.length-1]^=1; Path bad=temp.resolve("bad.age"); Files.write(bad,changed);
        int badFd=Linux.openRegular(bad,ArchiveInspector.MAX_ARCHIVE+32L*1024*1024,false,uid); Path partial=temp.resolve("partial");
        int partialFd=Linux.openAt(-100,partial.toString(),Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);
        try { assertThrows(Exception.class,()->AgeDecrypt.decrypt(Path.of(age),AGE_HASH,identity,badFd,partialFd,uid)); }
        finally {Linux.close(badFd);Linux.close(partialFd);}
    }
    private static String sha(Path path) throws Exception {return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path)));}
}
