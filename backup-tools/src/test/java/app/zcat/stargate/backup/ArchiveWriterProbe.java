// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;

/** Isolate native calls while packing a synthetic stopped fixture. */
public final class ArchiveWriterProbe {
    public static void main(String[] args) {
        int fd = -1;
        try {
            int uid = Linux.uid("geteuid"); Path source = Path.of(args[0]), output = Path.of(args[1]);
            fd = Linux.openDir(source.toString(), true, uid);
            if (args.length > 2 && args[2].equals("mutate")) ArchiveWriter.faults = (phase, path) -> {
                if (path.equals("app-data/file")) Files.writeString(source.resolve(path), "changed during packing");
            };
            try (FileChannel target = FileChannel.open(output, StandardOpenOption.CREATE_NEW, StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                String scenario = args.length > 2 ? args[2] : "base";
                int gid = Linux.uid("getegid");
                byte[] hash = scenario.equals("other-uid") || scenario.equals("other-gid")
                        ? ArchiveWriter.write(fd, target, false, scenario.equals("other-uid") ? uid + 1 : uid,
                                scenario.equals("other-gid") ? gid + 1 : gid)
                        : ArchiveWriter.write(fd, target, scenario.equals("nym"));
                ArchiveInspector.inspect(target, null);
                byte[] independentlyHashed = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(output));
                if (!MessageDigest.isEqual(hash, independentlyHashed)) throw new AssertionError("Digest differs");
            }
        } catch (Exception e) { System.exit(1); }
        finally { if (fd >= 0) try { Linux.close(fd); } catch (Exception e) { System.exit(1); } }
    }
}
