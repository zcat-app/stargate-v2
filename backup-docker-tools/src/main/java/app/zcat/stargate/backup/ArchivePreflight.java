// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HexFormat;

/** Host-side checks of a fully authenticated, held plaintext spool. */
final class ArchivePreflight {
    record Result(ArchiveInspector.Summary summary, String sha256, Linux.Stat identity) {}
    private ArchivePreflight() {}
    static Result inspect(int fd) throws Exception {
        Linux.Stat before = Linux.stat(fd);
        if (!VolumeSnapshot.regular(before) || before.links() != 1 || before.size() > ArchiveInspector.MAX_ARCHIVE) throw DockerPolicy.failure();
        ArchiveInspector.Summary summary;
        try (FileChannel input = FileChannel.open(Linux.fdPath(fd), StandardOpenOption.READ)) {
            summary = ArchiveInspector.inspect(input, new ArchiveInspector.StagingOwner(10001, 10001));
        }
        String digest = digest(fd, before);
        if (!before.equals(Linux.stat(fd))) throw DockerPolicy.failure();
        return new Result(summary, digest, before);
    }
    static String digest(int fd, Linux.Stat expected) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); byte[] buf = new byte[65536]; long size = 0;
        try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) {
            int n; while ((n = in.read(buf)) != -1) { size += n; if (size > ArchiveInspector.MAX_ARCHIVE) throw DockerPolicy.failure(); hash.update(buf, 0, n); }
        }
        if (size != expected.size() || !expected.equals(Linux.stat(fd))) throw DockerPolicy.failure();
        return HexFormat.of().formatHex(hash.digest());
    }
    static void guard(int fd, Linux.Stat expected, String sha256) throws Exception {
        if (!expected.equals(Linux.stat(fd)) || !sha256.equals(digest(fd, expected))) throw new IOException("Authenticated spool changed");
    }
}
