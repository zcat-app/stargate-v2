// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.TimeUnit;
import static app.zcat.stargate.updater.UpdateFiles.*;
import static org.junit.jupiter.api.Assertions.*;

class UpdateFilePermissionsTest {
    @TempDir Path tmp;

    @Test void publicAndPrivatePublicationRespectModesWithServiceUmask()throws Exception {
        child("0077");
    }
    @Test void publicationRetainsPrivateModesWithOrdinaryUmask()throws Exception {
        child("0022");
    }
    void child(String umask)throws Exception {
        String classpath=System.getProperty("surefire.test.class.path",System.getProperty("java.class.path"));
        var process=new ProcessBuilder("/bin/bash","-c","umask "+umask+"; exec \"$@\"","stargate-file-mode-proof",
                Path.of(System.getProperty("java.home"),"bin/java").toString(),"-cp",classpath,
                ModeChild.class.getName(),tmp.toString()).redirectErrorStream(true).start();
        try {
            assertTrue(process.waitFor(20,TimeUnit.SECONDS),"Filesystem-only child timed out");
            String output=new String(process.getInputStream().readAllBytes());
            assertEquals(0,process.exitValue(),output);
            assertTrue(output.contains("PUBLIC_0644_PRIVATE_0600_REPLACEMENT_OK"),output);
        } finally {
            if(process.isAlive()){process.destroyForcibly();process.waitFor(10,TimeUnit.SECONDS);}
        }
    }
    public static class ModeChild {
        public static void main(String[] args)throws Exception {
            Path root=Path.of(args[0]),publicDir=root.resolve("public");
            directory(publicDir,"rwxr-xr-x");
            Path status=publicDir.resolve("status.json"),config=root.resolve("config.json");
            write(status,"first public observation".getBytes(),true);
            mode(status,"rw-r--r--");
            write(config,"synthetic private configuration".getBytes(),false);
            mode(config,"rw-------");
            // Replace a status file left at 0600 by the earlier implementation.
            Files.setPosixFilePermissions(status,PosixFilePermissions.fromString("rw-------"));
            write(status,"complete replacement".getBytes(),true);
            mode(status,"rw-r--r--");
            if(!Files.readString(status).equals("complete replacement"))throw new AssertionError("Replacement bytes differ");
            mode(config,"rw-------");
            try(var paths=Files.list(publicDir)){
                if(paths.anyMatch(p->p.getFileName().toString().startsWith(".publish-")))throw new AssertionError("Temporary publication retained");
            }
            System.out.println("PUBLIC_0644_PRIVATE_0600_REPLACEMENT_OK");
        }
        static void mode(Path p,String expected)throws Exception {
            String actual=PosixFilePermissions.toString(Files.getPosixFilePermissions(p));
            if(!actual.equals(expected))throw new AssertionError(p.getFileName()+": expected "+expected+", observed "+actual);
        }
    }
}
