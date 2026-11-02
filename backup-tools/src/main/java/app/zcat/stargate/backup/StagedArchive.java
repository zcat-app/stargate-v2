// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Descriptor-relative extraction and publication of a fully validated stable archive. */
final class StagedArchive {
    private static final byte[] GATE = "Offline staged recovery incomplete; rerun before starting.\n".getBytes(StandardCharsets.US_ASCII);
    record Member(String name, boolean directory, long size, int mode, long uid, long gid, long mtime) {}
    /** Reader must refer to exactly the stable, fully authenticated and validated spool. */
    interface Reader {
        Member next() throws IOException;
        int read(byte[] buffer, int offset, int length) throws IOException;
        void finishMember() throws IOException;
    }
    static final class Uncertain extends IOException {
        Uncertain(String reason, Throwable cause) { super(reason, cause); }
    }
    interface Faults { void at(String phase) throws IOException; }
    static Faults faults = phase -> {};
    private record Created(String path, boolean directory) {}
    private record Directory(String path, int mode, long mtime) {}
    private StagedArchive() {}
    static void stage(Reader reader, int work, int parent, String output, int uid, int gid) throws Exception {
        if (output.isEmpty() || output.equals(".") || output.equals("..") || output.indexOf('/') >= 0 || output.indexOf('\0') >= 0) throw new IOException("Invalid output name");
        List<Created> created = new ArrayList<>(); List<Directory> directories = new ArrayList<>();
        Set<String> seen = new HashSet<>(), roots = new HashSet<>();
        int stage = -1; boolean published = false, stageCreated = false; long payloadBytes = 0; Throwable pending = null;
        try {
            Linux.mkdir(work, "stage"); stageCreated = true;
            stage = Linux.openAt(work, "stage", Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            Linux.chmod(stage, 0700); privateDirectory(Linux.stat(stage), uid, gid);
            Member member;
            while ((member = reader.next()) != null) {
                interrupted(); validate(member, seen, uid, gid);
                payloadBytes += member.size();
                if (payloadBytes > ArchiveInspector.MAX_ARCHIVE) throw new IOException("Staging limit exceeded");
                String name = member.name(); String[] parts = name.split("/", -1);
                if (parts.length == 1) { if (!member.directory()) throw new IOException("Invalid root"); roots.add(name); }
                else if (!seen.contains(name.substring(0, name.lastIndexOf('/')))) throw new IOException("Missing parent");
                boolean skip = name.equals("app-data/recovery-incomplete");
                if (skip) consume(reader, null, member.size());
                else {
                    int p = parentFd(stage, parts, parts.length - 1);
                    try {
                        if (member.directory()) {
                            Linux.mkdir(p, parts[parts.length - 1]); created.add(new Created(name, true));
                            int fd = Linux.openAt(p, parts[parts.length - 1], Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                            try {
                                checkOwner(Linux.stat(fd), uid, gid); Linux.chmod(fd, 0700);
                                directories.add(new Directory(name, member.mode(), member.mtime()));
                            } finally { Linux.close(fd); }
                        } else {
                            int fd = Linux.openAt(p, parts[parts.length - 1], Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
                            created.add(new Created(name, false));
                            try {
                                checkOwner(Linux.stat(fd), uid, gid); Linux.chmod(fd, 0600);
                                try (OutputStream out = Files.newOutputStream(Linux.fdPath(fd))) { consume(reader, out, member.size()); }
                                Linux.chmod(fd, member.mode()); StageNative.setTimes(fd, member.mtime());
                                if ((Linux.stat(fd).mode() & 07777) != member.mode()) throw new IOException("File mode not preserved");
                                Linux.sync(fd);
                            } finally { Linux.close(fd); }
                        }
                    } finally { Linux.close(p); }
                }
                reader.finishMember(); seen.add(name);
            }
            if (!roots.equals(ArchiveInspector.BASE) && !roots.equals(ArchiveInspector.ALL)) throw new IOException("Incomplete roots");
            int app = parentFd(stage, new String[]{"app-data"}, 1);
            try {
                int marker = Linux.openAt(app, "recovery-incomplete", Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
                created.add(new Created("app-data/recovery-incomplete", false));
                try {
                    checkOwner(Linux.stat(marker), uid, gid); Linux.chmod(marker, 0600);
                    if ((Linux.stat(marker).mode() & 07777) != 0600) throw new IOException("Gate mode not preserved");
                    try (OutputStream out = Files.newOutputStream(Linux.fdPath(marker))) { out.write(GATE); }
                    Linux.sync(marker);
                } finally { Linux.close(marker); }
            } finally { Linux.close(app); }
            Collections.reverse(directories);
            for (Directory dir : directories) {
                String[] parts = dir.path().split("/"); int fd = parentFd(stage, parts, parts.length);
                try {
                    Linux.chmod(fd, dir.mode()); StageNative.setTimes(fd, dir.mtime());
                    if ((Linux.stat(fd).mode() & 07777) != dir.mode()) throw new IOException("Directory mode not preserved");
                    Linux.sync(fd);
                } finally { Linux.close(fd); }
            }
            Linux.sync(stage); interrupted(); faults.at("before-publish");
            StageNative.renameNoReplace(work, "stage", parent, output); published = true;
            try { faults.at("after-publish"); Linux.sync(work); Linux.sync(parent); }
            catch (IOException e) { throw new Uncertain("Publication durability uncertain", e); }
        } catch (Throwable failure) {
            if (!published && stageCreated) {
                try { cleanup(work, stage, created); }
                catch (Throwable cleanup) {
                    cleanup.addSuppressed(failure); Uncertain uncertain = new Uncertain("Staging cleanup or publication uncertain", cleanup);
                    pending = uncertain; throw uncertain;
                }
            }
            pending = failure;
            throw failure;
        } finally {
            if (stage >= 0) try { Linux.close(stage); }
            catch (IOException failure) {
                if (pending != null) pending.addSuppressed(failure);
                else throw new Uncertain("Staging descriptor close uncertain", failure);
            }
        }
    }
    private static void validate(Member m, Set<String> seen, int uid, int gid) throws IOException {
        String name = m.name(); String[] parts = name.split("/", -1);
        if (seen.size() >= 100_000 || name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0 || parts.length > 32
                || name.getBytes(StandardCharsets.UTF_8).length > 255 || name.codePoints().anyMatch(c -> c < 32 || c == 127)
                || !ArchiveInspector.ALL.contains(parts[0]) || seen.contains(name) || name.equals("app-data/volume-import-incomplete")) throw new IOException("Invalid staging path");
        for (String part : parts) if (part.isEmpty() || part.equals(".") || part.equals("..")) throw new IOException("Invalid staging path");
        if (m.uid() != Integer.toUnsignedLong(uid) || m.gid() != Integer.toUnsignedLong(gid) || m.mode() < 0 || (m.mode() & ~0777) != 0
                || m.size() < 0 || m.size() > ArchiveInspector.MAX_FILE || m.mtime() < 0 || m.mtime() > 077777777777L
                || (m.directory() && (m.size() != 0 || (m.mode() & 0700) != 0700))
                || (parts.length == 1 && (!m.directory() || m.mode() != 0700))
                || (!m.directory() && (m.mode() & 0400) == 0)
                || (name.equals("app-data/recovery-incomplete") && (m.directory() || m.mode() != 0600))) throw new IOException("Invalid staging metadata");
    }
    private static void consume(Reader reader, OutputStream out, long size) throws IOException {
        byte[] buffer = new byte[65536]; long remaining = size;
        while (remaining > 0) {
            int n = reader.read(buffer, 0, (int) Math.min(buffer.length, remaining));
            if (n <= 0 || n > remaining) throw new IOException("Staging spool changed");
            if (out != null) out.write(buffer, 0, n); remaining -= n;
        }
    }
    private static int parentFd(int root, String[] parts, int count) throws IOException {
        int fd = Linux.openAt(root, ".", Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
        try {
            for (int i = 0; i < count; i++) {
                int child = Linux.openAt(fd, parts[i], Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                Linux.close(fd); fd = child;
            }
            return fd;
        } catch (Throwable failure) { Linux.close(fd); throw failure; }
    }
    private static void checkOwner(Linux.Stat s, int uid, int gid) throws IOException {
        if (s.uid() != Integer.toUnsignedLong(uid) || s.gid() != Integer.toUnsignedLong(gid)) throw new IOException("Unexpected staging ownership");
    }
    private static void privateDirectory(Linux.Stat s, int uid, int gid) throws IOException {
        checkOwner(s, uid, gid);
        if (!VolumeSnapshot.directory(s) || (s.mode() & 07777) != 0700) throw new IOException("Private staging required");
    }
    private static void cleanup(int work, int stage, List<Created> created) throws IOException {
        if (stage < 0) throw new IOException("Staging identity is unavailable");
        int named = Linux.openAt(work, "stage", Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
        try {
            Linux.Stat a = Linux.stat(stage), b = Linux.stat(named);
            if (a.devMajor() != b.devMajor() || a.devMinor() != b.devMinor() || a.inode() != b.inode()) throw new IOException("Staging identity changed");
        } finally { Linux.close(named); }
        IOException failure = null;
        for (int i = created.size() - 1; i >= 0; i--) {
            Created item = created.get(i); String[] parts = item.path().split("/");
            try {
                int p = parentFd(stage, parts, parts.length - 1);
                try { Linux.unlink(p, parts[parts.length - 1], item.directory()); } finally { Linux.close(p); }
            } catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        }
        try { Linux.sync(stage); } catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        if (failure != null) throw failure;
        Linux.unlink(work, "stage", true); Linux.sync(work);
    }
    private static void interrupted() throws InterruptedException { if (Thread.currentThread().isInterrupted()) throw new InterruptedException(); }
}
