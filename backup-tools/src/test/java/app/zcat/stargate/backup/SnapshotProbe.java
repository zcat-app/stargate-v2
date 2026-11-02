// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

/** Isolates native access in the synthetic scanner tests. */
public final class SnapshotProbe {
    public static void main(String[] args) {
        int fd = -1;
        try {
            int uid = Linux.uid("geteuid"), gid = Linux.uid("getegid");
            fd = Linux.openDir(args[0], true, uid);
            System.out.println(VolumeSnapshot.scan(fd, args.length == 2 ? ArchiveInspector.ALL : ArchiveInspector.BASE, uid, gid).size());
        } catch (Exception e) { System.exit(1); }
        finally { if (fd >= 0) try { Linux.close(fd); } catch (Exception e) { System.exit(1); } }
    }
}
