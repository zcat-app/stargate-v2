// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.ValueLayout;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

/** Container-only initialization of newly created, empty import roots. */
public final class InitRoots {
    interface Roots extends AutoCloseable {
        Set<String> names() throws Exception;
        void checkEmptyRoot(String name) throws Exception;
        void initialize(String name) throws Exception;
        void syncParent() throws Exception;
        void close() throws Exception;
    }
    private InitRoots() {}
    public static void main(String[] args) {
        try {
            if (Linux.uid("getuid") != 0 || Linux.uid("geteuid") != 0 || Linux.uid("getgid") != 0 || Linux.uid("getegid") != 0) throw DockerPolicy.failure();
            String caps = null;
            for (String line : Files.readAllLines(Path.of("/proc/self/status"))) if (line.startsWith("CapEff:")) caps = line.substring(7).trim();
            if (caps == null || !new BigInteger(caps, 16).equals(BigInteger.ONE)) throw DockerPolicy.failure();
            try (Roots roots = new NativeRoots()) { initialize(List.of(args), roots); }
            System.out.println("EMPTY_ROOTS_INITIALIZED");
        } catch (Exception e) { System.err.println("INITIALIZATION FAILED: retain and inspect all newly created volumes."); System.exit(1); }
    }
    static void initialize(List<String> requested, Roots roots) throws Exception {
        List<String> baseScratch = new java.util.ArrayList<>(DockerPolicy.roots(false)); baseScratch.add("scratch");
        List<String> nymScratch = new java.util.ArrayList<>(DockerPolicy.roots(true)); nymScratch.add("scratch");
        if (!requested.equals(DockerPolicy.roots(false)) && !requested.equals(DockerPolicy.roots(true))
                && !requested.equals(baseScratch) && !requested.equals(nymScratch)) throw DockerPolicy.failure();
        if (!roots.names().equals(Set.copyOf(requested))) throw DockerPolicy.failure();
        for (String name : requested) roots.checkEmptyRoot(name);
        for (String name : requested) roots.initialize(name);
        roots.syncParent();
    }
    private static final class NativeRoots implements Roots {
        private final int parent;
        NativeRoots() throws IOException {
            parent = Linux.openDir("/dest", false, 0); Linux.Stat s = Linux.stat(parent);
            if (!VolumeSnapshot.directory(s) || s.uid() != 0 || s.gid() != 0 || (s.mode() & 07777) != 0700) throw DockerPolicy.failure();
        }
        public Set<String> names() throws IOException { return Set.copyOf(VolumeSnapshot.names(parent)); }
        public void checkEmptyRoot(String name) throws IOException {
            int fd = Linux.openAt(parent, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try { Linux.Stat s = Linux.stat(fd); if (!VolumeSnapshot.directory(s) || s.uid() != 0 || s.gid() != 0 || !VolumeSnapshot.names(fd).isEmpty()) throw DockerPolicy.failure(); }
            finally { Linux.close(fd); }
        }
        public void initialize(String name) throws Exception {
            int fd = Linux.openAt(parent, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try {
                Linux.Stat before = Linux.stat(fd);
                if (!VolumeSnapshot.directory(before) || before.uid() != 0 || before.gid() != 0 || !VolumeSnapshot.names(fd).isEmpty()) throw DockerPolicy.failure();
                // Keep the directory stream opened while root still owns the directory.
                // With only CAP_CHOWN, reopening /proc/self/fd after chown would
                // require DAC access to the new owner's private 0700 directory.
                try (var entries = Files.newDirectoryStream(Linux.fdPath(fd))) {
                    Linux.chmod(fd, 0700); chown(fd, 10001, 10001); Linux.Stat after = Linux.stat(fd);
                    if (after.uid() != 10001 || after.gid() != 10001 || (after.mode() & 07777) != 0700 || entries.iterator().hasNext()) throw DockerPolicy.failure();
                    Linux.sync(fd);
                }
            } finally { Linux.close(fd); }
        }
        public void syncParent() throws IOException { Linux.sync(parent); }
        public void close() throws IOException { Linux.close(parent); }
        private static void chown(int fd, int uid, int gid) throws IOException {
            try {
                Linker linker = Linker.nativeLinker(); var call = linker.downcallHandle(linker.defaultLookup().find("fchown").orElseThrow(),
                        FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
                if ((int) call.invokeExact(fd, uid, gid) != 0) throw DockerPolicy.failure();
            } catch (IOException e) { throw e; } catch (Throwable e) { throw new IOException("Root initialization failed", e); }
        }
    }
}
