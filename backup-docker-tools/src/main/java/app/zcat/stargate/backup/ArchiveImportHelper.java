// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.util.HexFormat;

/** Container-only staging and import of a previously authenticated read-only spool. */
public final class ArchiveImportHelper {
    private ArchiveImportHelper() {}
    public static void main(String[] args) {
        try {
            if (args.length != 3 || !args[0].equals("stage") || !args[1].matches("[0-9a-f]{64}") || !(args[2].equals("0") || args[2].equals("1"))) throw DockerPolicy.failure();
            if (Linux.uid("getuid") != 10001 || Linux.uid("geteuid") != 10001 || Linux.uid("getgid") != 10001 || Linux.uid("getegid") != 10001) throw DockerPolicy.failure();
            String capabilities = null; for (String line : Files.readAllLines(Path.of("/proc/self/status"))) if (line.startsWith("CapEff:")) capabilities = line.substring(7).trim();
            if (capabilities == null || !new java.math.BigInteger(capabilities,16).equals(java.math.BigInteger.ZERO)) throw DockerPolicy.failure();
            umask(); run(Path.of("/input.tar"),Path.of("/scratch"),Path.of("/dest"),args[1],args[2].equals("1"),10001,10001);
            System.out.println("OFFLINE_ARCHIVE_STAGE_AND_IMPORT_FINISHED");
        } catch (Exception e) { System.err.println("ARCHIVE HELPER FAILED: retain and inspect all resources."); System.exit(1); }
    }
    static void run(Path spool, Path scratch, Path destination, String expected, boolean nym, int uid, int gid) throws Exception {
        if (!expected.matches("[0-9a-f]{64}")) throw DockerPolicy.failure();
        int fd = Linux.openRegular(Linux.absolute(spool.toString()),ArchiveInspector.MAX_ARCHIVE,false,uid);
        try {
            Linux.Stat before = Linux.stat(fd);
            if ((before.mode() & 07777) != 0444 || !ArchivePreflight.digest(fd,before).equals(expected)) throw DockerPolicy.failure();
            try (FileChannel input = FileChannel.open(Linux.fdPath(fd),StandardOpenOption.READ)) {
                ArchiveInspector.Summary result = ArchiveInspector.inspect(input,new ArchiveInspector.StagingOwner(uid,gid));
                if (result.nym()!=nym) throw DockerPolicy.failure();
                ArchivePreflight.guard(fd,before,expected);
                stage(input,scratch,uid,gid);
            }
            ArchivePreflight.guard(fd,before,expected);
        } finally { Linux.close(fd); }
        VolumeImport.importSet(scratch.resolve("staged").toString(),destination.toString(),nym);
    }
    private static void stage(FileChannel input, Path scratch, int uid, int gid) throws Exception {
        int parent = Linux.openDir(scratch.toString(),true,uid), work=-1; byte[] random = new byte[16]; new SecureRandom().nextBytes(random);
        String name = ".stargate-backup-" + HexFormat.of().formatHex(random); boolean created=false, retain=false;
        try {
            Linux.Stat parentInfo=Linux.stat(parent); if(parentInfo.gid()!=Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
            Linux.mkdir(parent,name); created=true; work=Linux.openAt(parent,name,Linux.RDONLY|Linux.DIRECTORY|Linux.NOFOLLOW|Linux.CLOEXEC,0);
            Linux.Stat info=Linux.stat(work);
            if(info.uid()!=Integer.toUnsignedLong(uid)||info.gid()!=Integer.toUnsignedLong(gid)||(info.mode()&07777)!=0700) throw DockerPolicy.failure();
            try { StagedArchive.stage(new StagedTarReader(input),work,parent,"staged",uid,gid); }
            catch(StagedArchive.Uncertain e) { retain=true; throw e; }
        } finally {
            if(work>=0) { try { Linux.sync(work); } catch(Exception e) { retain=true; } try {Linux.close(work);} catch(Exception e) {retain=true;} }
            if(created && !retain) {
                try { Linux.unlink(parent,name,true); Linux.sync(parent); }
                catch(Exception e) { retain=true; }
            }
            try { Linux.close(parent); } catch(Exception e) { retain=true; }
            if(retain) throw new java.io.IOException("Private staging outcome unconfirmed");
        }
    }
    private static void umask() throws Exception {
        Linker linker=Linker.nativeLinker(); var call=linker.downcallHandle(linker.defaultLookup().find("umask").orElseThrow(),FunctionDescriptor.of(ValueLayout.JAVA_INT,ValueLayout.JAVA_INT));
        try { int ignored=(int)call.invokeExact(0077); } catch(Throwable e) { throw new Exception("Cannot set private mask",e); }
    }
}
