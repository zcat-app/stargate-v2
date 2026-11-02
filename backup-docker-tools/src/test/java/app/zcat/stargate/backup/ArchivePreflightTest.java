// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import static org.junit.jupiter.api.Assertions.*;

class ArchivePreflightTest {
    @TempDir Path temp;
    private static void number(byte[] h,int offset,int length,long n) { byte[] s=String.format(java.util.Locale.ROOT,"%0"+(length-1)+"o",n).getBytes(StandardCharsets.US_ASCII); System.arraycopy(s,0,h,offset,s.length); }
    static byte[] archive(int uid,int mode,boolean gate) throws Exception {
        return archive(uid,10001,mode,gate);
    }
    static byte[] archive(int uid,int gid,int mode,boolean gate) throws Exception {
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        for(String root:DockerPolicy.roots(false)) {
            byte[] h=new byte[512]; byte[] name=(root+"/").getBytes(StandardCharsets.UTF_8); System.arraycopy(name,0,h,0,name.length);
            number(h,100,8,root.equals("tor-data")?mode:0700); number(h,108,8,uid); number(h,116,8,gid); number(h,124,12,0); number(h,136,12,1);
            Arrays.fill(h,148,156,(byte)' '); h[156]='5'; System.arraycopy(new byte[]{'u','s','t','a','r',0,'0','0'},0,h,257,8); checksum(h); out.write(h);
        }
        if(gate) { byte[] h=new byte[512], name="app-data/volume-import-incomplete".getBytes(StandardCharsets.UTF_8); System.arraycopy(name,0,h,0,name.length); number(h,100,8,0600); number(h,108,8,uid); number(h,116,8,gid); number(h,124,12,0); number(h,136,12,1); Arrays.fill(h,148,156,(byte)' '); h[156]='0'; System.arraycopy(new byte[]{'u','s','t','a','r',0,'0','0'},0,h,257,8); checksum(h); out.write(h); }
        out.write(new byte[1024]); return out.toByteArray();
    }
    private static void checksum(byte[] h) {int sum=0;for(byte b:h)sum+=b&255;byte[] s=String.format(java.util.Locale.ROOT,"%06o",sum).getBytes(StandardCharsets.US_ASCII);System.arraycopy(s,0,h,148,6);h[154]=0;}
    private ArchivePreflight.Result inspect(byte[] data) throws Exception {
        Path path=Files.createTempFile(temp,"spool", ".tar"); Files.write(path,data); int fd=Linux.openRegular(path,ArchiveInspector.MAX_ARCHIVE,false,Linux.uid("geteuid"));
        try { return ArchivePreflight.inspect(fd); } finally { Linux.close(fd); }
    }
    @Test void checksUidModesAndIncompleteGateBeforeAnyDaemonAccess() throws Exception {
        var result=inspect(archive(10001,0700,false)); assertEquals(5,result.summary().entries()); assertEquals(64,result.sha256().length());
        assertThrows(Exception.class,()->inspect(archive(10002,0700,false)));
        assertThrows(Exception.class,()->inspect(archive(10001,0755,false)));
        assertThrows(Exception.class,()->inspect(archive(10001,0700,true)));
    }
    @Test void detectsChangedSpool() throws Exception {
        Path path=Files.createTempFile(temp,"spool", ".tar"); Files.write(path,archive(10001,0700,false));
        int fd=Linux.openRegular(path,ArchiveInspector.MAX_ARCHIVE,false,Linux.uid("geteuid"));
        try { var result=ArchivePreflight.inspect(fd); Files.write(path,new byte[]{0}); assertThrows(Exception.class,()->ArchivePreflight.guard(fd,result.identity(),result.sha256())); }
        finally {Linux.close(fd);}
    }
}
