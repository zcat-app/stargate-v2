// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.charset.StandardCharsets;
import java.util.List;

/** Descriptor staging test with synthetic, prevalidated member streams. */
public final class StageProbe {
    private record Item(StagedArchive.Member member, byte[] bytes) {}
    private static final class Reader implements StagedArchive.Reader {
        final List<Item> items; final boolean fail; int index = -1, position;
        Reader(List<Item> items, boolean fail) { this.items = items; this.fail = fail; }
        public StagedArchive.Member next() { index++; position = 0; return index == items.size() ? null : items.get(index).member(); }
        public int read(byte[] buffer, int offset, int length) throws java.io.IOException {
            if (fail) throw new java.io.IOException("Injected read failure");
            byte[] data = items.get(index).bytes(); int n = Math.min(length, data.length - position);
            if (n == 0) return -1; System.arraycopy(data, position, buffer, offset, n); position += n; return n;
        }
        public void finishMember() { }
    }
    private static Item dir(String name, int uid, int gid) { return item(name, true, "", uid, gid); }
    private static Item item(String name, boolean dir, String data, int uid, int gid) {
        byte[] bytes = data.getBytes(StandardCharsets.UTF_8);
        return new Item(new StagedArchive.Member(name, dir, bytes.length, dir ? 0700 : 0600, uid, gid, 1_500_000_000), bytes);
    }
    public static void main(String[] args) {
        int work = -1, parent = -1;
        try {
            int uid = Linux.uid("geteuid"), gid = Linux.uid("getegid");
            work = Linux.openDir(args[0], true, uid); parent = Linux.openDir(args[1], true, uid);
            if (args.length > 2 && (args[2].equals("before-publish") || args[2].equals("after-publish"))) {
                StagedArchive.faults = phase -> {
                    if (phase.equals(args[2])) {
                        java.nio.file.Path gate = java.nio.file.Path.of(args[0], "stage", "app-data", "recovery-incomplete");
                        if (phase.equals("before-publish") && !java.nio.file.Files.isRegularFile(gate)) throw new AssertionError("Gate missing");
                        throw new java.io.IOException("Synthetic injected failure");
                    }
                };
            }
            if (args.length > 3 && args[2].equals("tar")) {
                try (var channel = java.nio.channels.FileChannel.open(java.nio.file.Path.of(args[3]), java.nio.file.StandardOpenOption.READ)) {
                    ArchiveInspector.inspect(channel, new ArchiveInspector.StagingOwner(uid, gid));
                    StagedArchive.stage(new StagedTarReader(channel), work, parent, "staged", uid, gid);
                }
                return;
            }
            String extra = args.length > 2 && args[2].equals("unsafe") ? "app-data/volume-import-incomplete" : "app-data/recovery-incomplete";
            boolean unreadable = args.length > 2 && args[2].equals("unreadable");
            Item file = item("app-data/file", false, "synthetic", uid, gid);
            if (unreadable) file = new Item(new StagedArchive.Member("app-data/file", false, file.bytes().length, 0200, uid, gid, 1_500_000_000), file.bytes());
            Item tor = dir("tor-data", uid, gid);
            if (args.length > 2 && args[2].equals("open-root")) tor = new Item(new StagedArchive.Member("tor-data", true, 0, 0755, uid, gid, 1_500_000_000), new byte[0]);
            List<Item> entries = List.of(dir("app-data", uid, gid), file, item(extra, false, "old", uid, gid),
                    item("app-data/identity-recovery-incomplete", false, "identity", uid, gid),
                    dir("i2p-control", uid, gid), dir("i2p-data", uid, gid), dir("tor-control", uid, gid), tor);
            StagedArchive.stage(new Reader(entries, args.length > 2 && args[2].equals("fail")), work, parent, "staged", uid, gid);
        } catch (Exception failure) { System.exit(1); }
        finally {
            try { if (work >= 0) Linux.close(work); if (parent >= 0) Linux.close(parent); } catch (Exception e) { System.exit(1); }
        }
    }
}
