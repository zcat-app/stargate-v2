// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

/** Linux libc descriptor operations; no native pathname is followed after validation. */
final class Linux {
    private static final Linker LINKER = Linker.nativeLinker();
    private static final Map<String, MethodHandle> METHODS = new HashMap<>();
    static final int RDONLY = 0, RDWR = 2, CREAT = 0100, EXCL = 0200, NONBLOCK = 04000,
            DIRECTORY = 0200000, NOFOLLOW = 0400000, CLOEXEC = 02000000;
    private static final int AT_FDCWD = -100, AT_EMPTY_PATH = 0x1000, STATX_BASIC_STATS = 0x7ff;
    private Linux() {}

    private static Object call(String name, FunctionDescriptor descriptor, Object... args) throws IOException {
        try {
            MethodHandle h = METHODS.computeIfAbsent(name, key -> LINKER.downcallHandle(
                    LINKER.defaultLookup().find(key).orElseThrow(), descriptor));
            return h.invokeWithArguments(args);
        } catch (Throwable t) { throw new IOException("Native operation failed", t); }
    }
    private static int integer(String name, FunctionDescriptor d, Object... args) throws IOException {
        return (int) call(name, d, args);
    }
    private static int checked(int result) throws IOException { if (result < 0) throw new IOException("Native operation failed"); return result; }
    static int uid(String name) throws IOException { return integer(name, FunctionDescriptor.of(ValueLayout.JAVA_INT)); }
    static int openAt(int parent, String name, int flags, int mode) throws IOException {
        try (Arena a = Arena.ofConfined()) {
            return checked(integer("openat", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), parent, a.allocateFrom(name), flags, mode));
        }
    }
    static int openDir(String value, boolean privateDir, int uid) throws IOException {
        Path path = absolute(value);
        int fd = openAt(AT_FDCWD, "/", RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC, 0);
        try {
            for (Path component : path) {
                int next = openAt(fd, component.toString(), RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC, 0);
                close(fd); fd = next;
            }
            Stat s = stat(fd);
            if (privateDir && (s.uid != Integer.toUnsignedLong(uid) || (s.mode & 07777) != 0700)) throw new IOException("Private directory required");
            return fd;
        } catch (Throwable t) { close(fd); throw t; }
    }
    static Path absolute(String s) throws IOException {
        if (!s.startsWith("/") || s.startsWith("//") || s.indexOf('\0') >= 0) throw new IOException("Absolute normalized path required");
        Path p = Path.of(s);
        if (!p.toString().equals(s) || !p.normalize().equals(p)) throw new IOException("Absolute normalized path required");
        return p;
    }
    static int openRegular(Path path, long limit, boolean privateFile, int uid) throws IOException {
        Path name = path.getFileName(); if (name == null) throw new IOException("File required");
        int parent = openDir(path.getParent().toString(), false, uid);
        int fd;
        try { fd = openAt(parent, name.toString(), RDONLY | NONBLOCK | NOFOLLOW | CLOEXEC, 0); }
        finally { close(parent); }
        try {
            Stat s = stat(fd);
            if ((s.mode & 0170000) != 0100000 || s.links != 1 || s.size > limit
                    || (privateFile && (s.uid != Integer.toUnsignedLong(uid) || (s.mode & 07777) != 0600))) throw new IOException("Invalid regular file");
            return fd;
        } catch (Throwable t) { close(fd); throw t; }
    }
    static void close(int fd) throws IOException { checked(integer("close", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), fd)); }
    static void sync(int fd) throws IOException { checked(integer("fsync", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), fd)); }
    static void chmod(int fd, int mode) throws IOException { checked(integer("fchmod", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), fd, mode)); }
    static void mkdir(int fd, String name) throws IOException {
        try (Arena a = Arena.ofConfined()) { checked(integer("mkdirat", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), fd, a.allocateFrom(name), 0700)); }
    }
    static void unlink(int fd, String name, boolean directory) throws IOException {
        try (Arena a = Arena.ofConfined()) { checked(integer("unlinkat", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), fd, a.allocateFrom(name), directory ? 0x200 : 0)); }
    }
    static void link(int from, String source, int to, String destination) throws IOException {
        try (Arena a = Arena.ofConfined()) {
            checked(integer("linkat", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), from, a.allocateFrom(source), to, a.allocateFrom(destination), 0));
        }
    }
    static void seekStart(int fd) throws IOException {
        long result = (long) call("lseek", FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_INT), fd, 0L, 0);
        if (result != 0) throw new IOException("Cannot rewind file");
    }
    record Stat(long devMajor, long devMinor, long inode, long mode, long uid, long gid, long links, long size,
                long mtimeSec, long mtimeNsec, long ctimeSec, long ctimeNsec) {}
    static Stat stat(int fd) throws IOException {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment data = a.allocate(256, 8);
            checked(integer("statx", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), fd, a.allocateFrom(""), AT_EMPTY_PATH, STATX_BASIC_STATS, data));
            int mask = data.get(ValueLayout.JAVA_INT, 0);
            if ((mask & STATX_BASIC_STATS) != STATX_BASIC_STATS) throw new IOException("Incomplete file metadata");
            return new Stat(u32(data, 136), u32(data, 140), data.get(ValueLayout.JAVA_LONG, 32), Short.toUnsignedLong(data.get(ValueLayout.JAVA_SHORT, 28)), u32(data, 20), u32(data, 24), u32(data, 16), data.get(ValueLayout.JAVA_LONG, 40), data.get(ValueLayout.JAVA_LONG, 112), u32(data, 120), data.get(ValueLayout.JAVA_LONG, 96), u32(data, 104));
        }
    }
    private static long u32(MemorySegment m, long off) { return Integer.toUnsignedLong(m.get(ValueLayout.JAVA_INT, off)); }
    static Path fdPath(int fd) { return Path.of("/proc/self/fd/" + fd); }

    /** Spawn with descriptor actions; all inputs are pinned before entering libc. */
    static int spawnAge(int binary, int identity, int source, int target, AtomicInteger active) throws IOException {
        return spawnAge(binary, identity, source, target, active, null);
    }
    static int spawnAge(int binary, int identity, int source, int target, AtomicInteger active, String recipient) throws IOException {
        // no_new_privs is per-thread and inherited by this same thread's posix_spawn child.
        checked(integer("prctl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG), 38, 1L, 0L, 0L, 0L));
        boundResource(1, recipient == null ? ArchiveInspector.MAX_ARCHIVE : ArchiveInspector.MAX_ARCHIVE + 32L * 1024 * 1024); // RLIMIT_FSIZE
        boundResource(4, 0); // RLIMIT_CORE
        int[] originals = {binary, identity, source, target};
        int[] copies = {-1, -1, -1, -1};
        int nullfd = -1, nullcopy = -1, child = -1;
        try (Arena a = Arena.ofConfined()) {
            for (int i = 0; i < copies.length; i++) copies[i] = checked(integer("fcntl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), originals[i], 1030, 10)); // F_DUPFD_CLOEXEC
            nullfd = openAt(AT_FDCWD, "/dev/null", RDWR | CLOEXEC, 0);
            nullcopy = checked(integer("fcntl", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), nullfd, 1030, 10));
            // glibc's opaque file-actions object is smaller than this aligned storage.
            MemorySegment actions = a.allocate(4096, 16), pid = a.allocate(ValueLayout.JAVA_INT);
            int initialized = integer("posix_spawn_file_actions_init", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS), actions);
            if (initialized != 0) throw new IOException("Spawn setup failed");
            try {
                int[] dest = {3, 4, 0, 1};
                for (int i = 0; i < copies.length; i++) actionDup(actions, copies[i], dest[i]);
                actionDup(actions, nullcopy, 2);
                // Match close_fds: the child inherits only stdin, stdout, stderr,
                // the pinned executable (3), and the native identity (4).
                if (integer("posix_spawn_file_actions_addclosefrom_np", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), actions, 5) != 0)
                    throw new IOException("Spawn setup failed");
                MemorySegment argv = recipient == null
                        ? strings(a, "/proc/self/fd/3", "--decrypt", "--identity", "/proc/self/fd/4")
                        : strings(a, "/proc/self/fd/3", "--encrypt", "--recipient", recipient);
                MemorySegment env = strings(a, "PATH=/nonexistent", "LANG=C");
                int rc = integer("posix_spawn", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS), pid, a.allocateFrom("/proc/self/fd/3"), actions, MemorySegment.NULL, argv, env);
                if (rc != 0) throw new IOException("Age launch failed");
                child = pid.get(ValueLayout.JAVA_INT, 0);
                active.set(child);
            } finally { integer("posix_spawn_file_actions_destroy", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS), actions); }
        } finally {
            IOException failure = null;
            int[] opened = {nullcopy, nullfd, copies[0], copies[1], copies[2], copies[3]};
            for (int fd : opened) if (fd >= 0) {
                try { close(fd); } catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
            }
            if (failure != null) {
                throw failure;
            }
        }
        return child;
    }
    private static void actionDup(MemorySegment actions, int from, int to) throws IOException {
        if (integer("posix_spawn_file_actions_adddup2", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), actions, from, to) != 0) throw new IOException("Spawn setup failed");
    }
    private static MemorySegment strings(Arena a, String... values) {
        MemorySegment array = a.allocate(ValueLayout.ADDRESS, values.length + 1);
        for (int i = 0; i < values.length; i++) array.setAtIndex(ValueLayout.ADDRESS, i, a.allocateFrom(values[i]));
        return array;
    }
    private static void boundResource(int resource, long maximum) throws IOException {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment limits = a.allocate(16, 8);
            checked(integer("getrlimit", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), resource, limits));
            long soft = limits.get(ValueLayout.JAVA_LONG, 0);
            long hard = limits.get(ValueLayout.JAVA_LONG, 8);
            if (hard < 0 || hard > maximum) hard = maximum;
            if (soft < 0 || soft > hard) soft = hard;
            limits.set(ValueLayout.JAVA_LONG, 0, soft);
            limits.set(ValueLayout.JAVA_LONG, 8, hard);
            checked(integer("setrlimit", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS), resource, limits));
        }
    }
    static int waitNoHang(int pid, MemorySegment status) throws IOException {
        return checked(integer("waitpid", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), pid, status, 1));
    }
    static void waitForDeath(int pid) throws IOException {
        try (Arena a = Arena.ofConfined()) {
            checked(integer("waitpid", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT), pid, a.allocate(ValueLayout.JAVA_INT), 0));
        }
    }
    static void kill(int pid) throws IOException { checked(integer("kill", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT), pid, 9)); }
}
