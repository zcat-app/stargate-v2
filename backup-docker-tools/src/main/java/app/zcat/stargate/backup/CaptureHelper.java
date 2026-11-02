// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.math.BigInteger;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/** Container-only double-pass capture of a stopped, read-only volume set. */
public final class CaptureHelper {
    private CaptureHelper() {}
    public static void main(String[] args) {
        try {
            if (args.length != 1 || !(args[0].equals("0") || args[0].equals("1"))) throw DockerPolicy.failure();
            if (Linux.uid("getuid") != 0 || Linux.uid("geteuid") != 0 || Linux.uid("getgid") != 0 || Linux.uid("getegid") != 0) throw DockerPolicy.failure();
            String capabilities = null; for (String line : Files.readAllLines(Path.of("/proc/self/status"))) if (line.startsWith("CapEff:")) capabilities = line.substring(7).trim();
            if (capabilities == null || !new BigInteger(capabilities,16).equals(BigInteger.valueOf(2))) throw DockerPolicy.failure();
            capture(Path.of("/source"),Path.of("/capture.tar"),args[0].equals("1"),0);
            System.out.println("OFFLINE_CAPTURE_ARCHIVE_READY");
        } catch (Exception e) { System.err.println("CAPTURE HELPER FAILED: retain and inspect private work."); System.exit(1); }
    }
    static void capture(Path source, Path output, boolean nym, int uid) throws Exception {
        int sourceFd=Linux.openDir(Linux.absolute(source.toString()).toString(),true,uid);
        try {
            Set<String> roots=nym?ArchiveInspector.ALL:ArchiveInspector.BASE;
            Map<String,Linux.Stat> before=CaptureInventory.scan(sourceFd,roots);
            Path path=Linux.absolute(output.toString()); int initial=Linux.openRegular(path,ArchiveInspector.MAX_ARCHIVE,false,uid);
            Linux.Stat info;
            try { info=Linux.stat(initial); if(info.size()!=0) throw DockerPolicy.failure(); }
            finally {Linux.close(initial);}
            int parent=Linux.openDir(path.getParent().toString(),false,uid), out;
            try {out=Linux.openAt(parent,path.getFileName().toString(),Linux.RDWR|Linux.NONBLOCK|Linux.NOFOLLOW|Linux.CLOEXEC,0);} finally {Linux.close(parent);}
            try {
                if(!info.equals(Linux.stat(out))) throw DockerPolicy.failure();
                try(FileChannel channel=FileChannel.open(Linux.fdPath(out),StandardOpenOption.READ,StandardOpenOption.WRITE)) {
                    byte[] first=CaptureWriter.write(sourceFd,channel,nym); ArchiveInspector.Summary a=ArchiveInspector.inspect(channel,null);
                    byte[] second=CaptureWriter.write(sourceFd,channel,nym); ArchiveInspector.Summary b=ArchiveInspector.inspect(channel,null);
                    if(!Arrays.equals(first,second)||!a.equals(b)||!before.equals(CaptureInventory.scan(sourceFd,roots))) throw DockerPolicy.failure();
                    channel.force(true);
                }
            } finally {Linux.close(out);}
        } finally {Linux.close(sourceFd);}
    }
}
