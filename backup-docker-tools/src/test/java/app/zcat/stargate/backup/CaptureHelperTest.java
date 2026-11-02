// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class CaptureHelperTest {
    @TempDir Path temp;
    private static Path directory(Path p) throws Exception {Files.createDirectory(p);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rwx------"));return p;}
    @Test void preservesSourceRootModesAndRejectsLinksOrChanges() throws Exception {
        Path source=directory(temp.resolve("source"));for(String role:DockerPolicy.BASE) directory(source.resolve(role));
        Files.setPosixFilePermissions(source.resolve("tor-data"),PosixFilePermissions.fromString("rwxr-xr-x"));
        Path file=Files.writeString(source.resolve("app-data/file"),"synthetic"); Files.setPosixFilePermissions(file,PosixFilePermissions.fromString("rw-------"));
        Path out=Files.createFile(temp.resolve("out.tar")); CaptureHelper.capture(source,out,false,Linux.uid("geteuid"));
        try(FileChannel channel=FileChannel.open(out,StandardOpenOption.READ)) {
            assertEquals(6,ArchiveInspector.inspect(channel,null).entries()); var reader=new StagedTarReader(channel); StagedArchive.Member member; boolean found=false;
            while((member=reader.next())!=null) {if(member.name().equals("tor-data")){assertEquals(0755,member.mode());found=true;} byte[] data=new byte[8192];long left=member.size();while(left>0){int n=reader.read(data,0,(int)Math.min(left,data.length));left-=n;}reader.finishMember();}
            assertTrue(found);
        }
        Path link=source.resolve("tor-data/link"); Files.createSymbolicLink(link,file); Path second=Files.createFile(temp.resolve("second.tar"));
        assertThrows(Exception.class,()->CaptureHelper.capture(source,second,false,Linux.uid("geteuid"))); Files.delete(link);
        CaptureWriter.faults=(phase,path)->{if(path.equals("app-data/file")) Files.writeString(file,"changed");};
        try {assertThrows(Exception.class,()->CaptureHelper.capture(source,second,false,Linux.uid("geteuid")));}
        finally {CaptureWriter.faults=(phase,path)->{};}
    }
}
