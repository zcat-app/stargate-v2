// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;

/** Copy a stopped, private staged set into isolated empty volume roots. */
public final class VolumeImport {
    private static final String GATE = "recovery-incomplete", IMPORT_GATE = "volume-import-incomplete";
    private static final byte[] GATE_CONTENT = "Offline staged recovery incomplete; rerun before starting.\n".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] IMPORT_CONTENT = "Offline volume import incomplete; discard and recreate the entire destination set.\n".getBytes(StandardCharsets.US_ASCII);
    private static final AtomicBoolean SHUTDOWN = new AtomicBoolean();
    private static final CountDownLatch FINISHED = new CountDownLatch(1);
    interface Faults { void at(String phase) throws Exception; }
    static Faults faults = phase -> {};
    private VolumeImport() {}

    public static void main(String[] args) {
        Thread main = Thread.currentThread();
        Thread hook = new Thread(() -> {
            SHUTDOWN.set(true); main.interrupt();
            try { FINISHED.await(); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }, "volume-import-shutdown");
        Runtime.getRuntime().addShutdownHook(hook);
        int code;
        try { code = run(args); } finally { FINISHED.countDown(); }
        try { Runtime.getRuntime().removeShutdownHook(hook); } catch (IllegalStateException e) { return; }
        System.exit(code);
    }
    static int run(String[] args) {
        if ((args.length != 4 && args.length != 5) || !args[0].equals("--source") || !args[2].equals("--destination")
                || (args.length == 5 && !args[4].equals("--nym"))) {
            System.err.println("Requires --source DIR --destination DIR [--nym]"); return 2;
        }
        try {
            importSet(args[1], args[3], args.length == 5);
            interrupted();
            System.out.println("OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED"); return 0;
        } catch (Exception e) {
            System.err.println("IMPORT FAILED: file or process operation failed. Keep offline; discard and recreate the entire destination set before retrying."); return 1;
        }
    }
    static void importSet(String source, String destination, boolean nym) throws Exception {
        if (!"Linux".equals(System.getProperty("os.name"))) throw new IOException("Linux required");
        int uid = Linux.uid("getuid"), euid = Linux.uid("geteuid"), gid = Linux.uid("getgid"), egid = Linux.uid("getegid");
        if (euid == 0 || uid != euid || gid != egid) throw new IOException("Unprivileged invocation required");
        Path srcPath = Linux.absolute(source), dstPath = Linux.absolute(destination);
        if (srcPath.startsWith(dstPath) || dstPath.startsWith(srcPath)) throw new IOException("Separate paths required");
        Set<String> roots = nym ? ArchiveInspector.ALL : ArchiveInspector.BASE;
        int src = Linux.openDir(source, true, euid);
        try {
            checkPrivate(Linux.stat(src), euid, egid);
            int dst = Linux.openDir(destination, true, euid);
            try {
                checkPrivate(Linux.stat(dst), euid, egid);
                if (id(Linux.stat(src)).equals(id(Linux.stat(dst)))) throw new IOException("Source aliases destination");
                Map<String, Linux.Stat> entries = VolumeSnapshot.scan(src, roots, euid, egid);
                if (!Set.copyOf(VolumeSnapshot.names(dst)).equals(roots)) throw new IOException("Unexpected destination roots");
                Map<String, Integer> targets = new HashMap<>();
                try {
                    Set<Identity> used = new HashSet<>();
                    for (Linux.Stat value : entries.values()) used.add(id(value));
                    for (String name : roots.stream().sorted().toList()) {
                        int fd = Linux.openAt(dst, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                        targets.put(name, fd); Linux.Stat value = Linux.stat(fd);
                        checkPrivate(value, euid, egid);
                        if (!VolumeSnapshot.names(fd).isEmpty() || !used.add(id(value))) throw new IOException("Destination roots must be distinct and empty");
                    }
                    interrupted();
                    createGate(targets.get("app-data"), IMPORT_GATE, IMPORT_CONTENT, euid, egid);
                    faults.at("import-gate-synced");
                    createGate(targets.get("app-data"), GATE, GATE_CONTENT, euid, egid);
                    faults.at("before-copy");
                    for (String name : roots.stream().sorted().toList()) {
                        interrupted();
                        int sourceRoot = Linux.openAt(src, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                        try { copyDir(sourceRoot, targets.get(name), name, entries, euid, egid); }
                        finally { Linux.close(sourceRoot); }
                    }
                    Map<String, Set<String>> children = new HashMap<>();
                    for (String path : entries.keySet()) {
                        int slash = path.lastIndexOf('/'); String parent = slash < 0 ? "" : path.substring(0, slash);
                        String leaf = slash < 0 ? path : path.substring(slash + 1);
                        children.computeIfAbsent(parent, ignored -> new HashSet<>()).add(leaf);
                    }
                    for (String name : roots.stream().sorted().toList()) verifyTree(targets.get(name), name, entries, children, euid, egid);
                    faults.at("before-rescan");
                    if (!VolumeSnapshot.scan(src, roots, euid, egid).equals(entries)) throw new IOException("Source changed");
                    for (int fd : targets.values()) Linux.sync(fd);
                    Linux.sync(dst);
                    interrupted();
                    try {
                        Linux.unlink(targets.get("app-data"), IMPORT_GATE, false);
                        faults.at("after-unlink");
                        interrupted();
                        VolumeImportNative.setMtime(targets.get("app-data"), entries.get("app-data").mtimeSec());
                        faults.at("before-final-sync");
                        Linux.sync(targets.get("app-data"));
                    } catch (Exception | Error failure) {
                        try { createGate(targets.get("app-data"), IMPORT_GATE, IMPORT_CONTENT, euid, egid); }
                        catch (Exception ignored) { }
                        throw failure;
                    }
                } finally {
                    IOException closeFailure = null;
                    for (int fd : targets.values()) try { Linux.close(fd); } catch (IOException e) { if (closeFailure == null) closeFailure = e; else closeFailure.addSuppressed(e); }
                    if (closeFailure != null) throw closeFailure;
                }
            } finally { Linux.close(dst); }
        } finally { Linux.close(src); }
    }
    private record Identity(long major, long minor, long inode) {}
    private static Identity id(Linux.Stat s) { return new Identity(s.devMajor(), s.devMinor(), s.inode()); }
    private static void checkPrivate(Linux.Stat s, int uid, int gid) throws IOException {
        if (!VolumeSnapshot.directory(s) || s.uid() != Integer.toUnsignedLong(uid) || s.gid() != Integer.toUnsignedLong(gid) || (s.mode() & 07777) != 0700) throw new IOException("Private directory required");
    }
    private static void checkFileOwner(Linux.Stat s, int uid, int gid) throws IOException {
        if (!VolumeSnapshot.regular(s) || s.uid() != Integer.toUnsignedLong(uid) || s.gid() != Integer.toUnsignedLong(gid) || s.links() != 1) throw new IOException("Unexpected destination metadata");
    }
    private static void createGate(int dir, String name, byte[] content, int uid, int gid) throws Exception {
        int fd = Linux.openAt(dir, name, Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
        try {
            checkFileOwner(Linux.stat(fd), uid, gid); Linux.chmod(fd, 0600);
            try (OutputStream out = Files.newOutputStream(Linux.fdPath(fd))) { out.write(content); out.flush(); }
            Linux.sync(fd);
        } finally { Linux.close(fd); }
        Linux.sync(dir);
    }
    private static void copyDir(int src, int dst, String path, Map<String, Linux.Stat> entries, int uid, int gid) throws Exception {
        interrupted(); Linux.Stat original = entries.get(path);
        if (original == null || !original.equals(Linux.stat(src))) throw new IOException("Source changed");
        for (String name : VolumeSnapshot.names(src)) {
            interrupted(); String childPath = path + "/" + name; Linux.Stat expected = entries.get(childPath);
            if (expected == null) throw new IOException("Source changed");
            if (childPath.equals("app-data/" + GATE)) continue;
            int child = Linux.openAt(src, name, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try {
                if (!expected.equals(Linux.stat(child))) throw new IOException("Source changed");
                if (VolumeSnapshot.directory(expected)) {
                    Linux.mkdir(dst, name);
                    int target = Linux.openAt(dst, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                    try { checkPrivate(Linux.stat(target), uid, gid); copyDir(child, target, childPath, entries, uid, gid); Linux.sync(target); }
                    finally { Linux.close(target); }
                } else {
                    int target = Linux.openAt(dst, name, Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
                    try { copyFile(child, target, expected, uid, gid); }
                    finally { Linux.close(target); }
                }
            } finally { Linux.close(child); }
        }
        if (!original.equals(Linux.stat(src))) throw new IOException("Source changed");
        Linux.chmod(dst, (int) (original.mode() & 07777)); VolumeImportNative.setMtime(dst, original.mtimeSec()); Linux.sync(dst);
    }
    private static void copyFile(int src, int dst, Linux.Stat source, int uid, int gid) throws Exception {
        checkFileOwner(Linux.stat(dst), uid, gid); Linux.chmod(dst, 0600);
        MessageDigest original = MessageDigest.getInstance("SHA-256"), copied = MessageDigest.getInstance("SHA-256");
        byte[] buf = new byte[65536]; long remaining = source.size();
        try (InputStream in = Files.newInputStream(Linux.fdPath(src)); OutputStream out = Files.newOutputStream(Linux.fdPath(dst))) {
            while (remaining > 0) {
                interrupted(); int n = in.read(buf, 0, (int) Math.min(buf.length, remaining));
                if (n <= 0) throw new IOException("Source truncated");
                original.update(buf, 0, n); out.write(buf, 0, n); remaining -= n;
            }
            if (in.read() != -1 || !source.equals(Linux.stat(src))) throw new IOException("Source changed");
        }
        Linux.chmod(dst, (int) (source.mode() & 07777)); VolumeImportNative.setMtime(dst, source.mtimeSec()); Linux.sync(dst);
        try (InputStream in = Files.newInputStream(Linux.fdPath(dst))) { int n; while ((n = in.read(buf)) != -1) { interrupted(); copied.update(buf, 0, n); } }
        Linux.Stat target = Linux.stat(dst); checkFileOwner(target, uid, gid);
        if (!MessageDigest.isEqual(original.digest(), copied.digest()) || target.size() != source.size()
                || (target.mode() & 07777) != (source.mode() & 07777) || target.uid() != source.uid() || target.gid() != source.gid()
                || target.mtimeSec() != source.mtimeSec()) throw new IOException("Copy verification failed");
    }
    private static void verifyTree(int fd, String path, Map<String, Linux.Stat> entries, Map<String, Set<String>> children, int uid, int gid) throws Exception {
        interrupted(); Linux.Stat info = Linux.stat(fd), expected = entries.get(path);
        if (!VolumeSnapshot.directory(info) || info.uid() != Integer.toUnsignedLong(uid) || info.gid() != Integer.toUnsignedLong(gid)
                || (info.mode() & 07777) != (expected.mode() & 07777) || info.mtimeSec() != expected.mtimeSec()) throw new IOException("Destination directory mismatch");
        Set<String> names = new HashSet<>(children.getOrDefault(path, Set.of()));
        if (path.equals("app-data")) { names.add(GATE); names.add(IMPORT_GATE); }
        if (!Set.copyOf(VolumeSnapshot.names(fd)).equals(names)) throw new IOException("Destination inventory mismatch");
        for (String name : names) {
            String childPath = path + "/" + name;
            int child = Linux.openAt(fd, name, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try {
                Linux.Stat actual = Linux.stat(child);
                if (childPath.equals("app-data/" + GATE) || childPath.equals("app-data/" + IMPORT_GATE)) {
                    byte[] content = name.equals(GATE) ? GATE_CONTENT : IMPORT_CONTENT;
                    checkFileOwner(actual, uid, gid);
                    if ((actual.mode() & 07777) != 0600 || actual.size() != content.length) throw new IOException("Invalid recovery gate");
                    try (InputStream in = Files.newInputStream(Linux.fdPath(child))) { if (!Arrays.equals(in.readNBytes(content.length + 1), content)) throw new IOException("Invalid recovery gate"); }
                } else {
                    Linux.Stat want = entries.get(childPath);
                    if (want == null) throw new IOException("Unexpected destination entry");
                    if (VolumeSnapshot.directory(want)) verifyTree(child, childPath, entries, children, uid, gid);
                    else if (!VolumeSnapshot.regular(actual) || actual.links() != 1 || actual.uid() != want.uid() || actual.gid() != want.gid()
                            || actual.size() != want.size() || (actual.mode() & 07777) != (want.mode() & 07777) || actual.mtimeSec() != want.mtimeSec()) throw new IOException("Destination file mismatch");
                }
            } finally { Linux.close(child); }
        }
    }
    private static void interrupted() throws InterruptedException {
        if (SHUTDOWN.get() || Thread.currentThread().isInterrupted()) throw new InterruptedException();
    }
}
