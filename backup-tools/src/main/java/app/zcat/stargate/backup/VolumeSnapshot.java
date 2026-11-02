// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Descriptor-relative, bounded source inventory for the future volume importer. */
final class VolumeSnapshot {
    private static final int MAX_DEPTH = 32, MAX_ENTRIES = 100_000;
    private static final long MAX_FILE = 2L * 1024 * 1024 * 1024, MAX_BYTES = 8L * 1024 * 1024 * 1024;
    private static final String IMPORT_GATE = "app-data/volume-import-incomplete";
    private static final String RECOVERY_GATE = "app-data/recovery-incomplete";
    private final int uid, gid;
    private final Map<String, Linux.Stat> entries = new HashMap<>();
    private final Set<Identity> inodes = new HashSet<>();
    private long bytes;
    private record Identity(long major, long minor, long inode) {}
    private VolumeSnapshot(int uid, int gid) { this.uid = uid; this.gid = gid; }

    static Map<String, Linux.Stat> scan(int sourceParent, Set<String> roots, int uid, int gid) throws IOException {
        VolumeSnapshot snapshot = new VolumeSnapshot(uid, gid);
        Linux.Stat parent = Linux.stat(sourceParent);
        if (!Set.copyOf(names(sourceParent)).equals(roots)) throw new IOException("Unexpected source roots");
        for (String name : roots.stream().sorted().toList()) {
            snapshot.visit(sourceParent, name, name, 1, null);
            if (!directory(snapshot.entries.get(name))) throw new IOException("Root is not a directory");
        }
        if (!parent.equals(Linux.stat(sourceParent))) throw new IOException("Source changed");
        return Map.copyOf(snapshot.entries);
    }
    private void visit(int parent, String name, String path, int depth, Identity root) throws IOException {
        if (path.equals(IMPORT_GATE) || depth > MAX_DEPTH || path.getBytes(StandardCharsets.UTF_8).length > 255
                || name.codePoints().anyMatch(c -> c < 32 || c == 127 || c == '\\')) throw new IOException("Unsupported source path");
        int fd = Linux.openAt(parent, name, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
        try {
            Linux.Stat s = Linux.stat(fd);
            Identity identity = new Identity(s.devMajor(), s.devMinor(), s.inode());
            if (!inodes.add(identity) || (root != null && (s.devMajor() != root.major || s.devMinor() != root.minor))) throw new IOException("Source alias or nested filesystem");
            if (s.uid() != Integer.toUnsignedLong(uid) || s.gid() != Integer.toUnsignedLong(gid) || (s.mode() & 07000) != 0) throw new IOException("Unsupported source metadata");
            if (directory(s)) {
                if ((depth == 1 && (s.mode() & 07777) != 0700) || (s.mode() & 0700) != 0700) throw new IOException("Unsupported directory mode");
            } else if (!regular(s) || s.links() != 1 || s.size() > MAX_FILE || (s.mode() & 0400) == 0) throw new IOException("Unsupported file");
            if (path.equals(RECOVERY_GATE) && (!regular(s) || (s.mode() & 07777) != 0600)) throw new IOException("Unsupported recovery marker");
            if (regular(s)) bytes += s.size();
            entries.put(path, s);
            if (entries.size() > MAX_ENTRIES || bytes > MAX_BYTES) throw new IOException("Source limit exceeded");
            if (directory(s)) {
                for (String child : names(fd)) visit(fd, child, path + "/" + child, depth + 1, root == null ? identity : root);
            }
            if (!s.equals(Linux.stat(fd))) throw new IOException("Source changed");
        } finally { Linux.close(fd); }
    }
    static List<String> names(int fd) throws IOException {
        List<String> result = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(Linux.fdPath(fd))) {
            for (Path item : stream) {
                if (result.size() >= MAX_ENTRIES) throw new IOException("Source limit exceeded");
                result.add(item.getFileName().toString());
            }
        }
        result.sort(String::compareTo);
        return result;
    }
    static boolean directory(Linux.Stat s) { return (s.mode() & 0170000) == 0040000; }
    static boolean regular(Linux.Stat s) { return (s.mode() & 0170000) == 0100000; }
}
