// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicInteger;

/** Observe a synthetic blocked age child and its inherited Linux process state. */
public final class SpawnProbe {
    public static void main(String[] args) {
        int age = -1, key = -1, source = -1, target = -1, sentinel = -1, pid = -1, code = 0;
        try {
            int uid = Linux.uid("geteuid");
            age = Linux.openRegular(Linux.absolute(args[0]), 32L * 1024 * 1024, false, uid);
            key = Linux.openRegular(Linux.absolute(args[1]), 65536, true, uid);
            source = Linux.openAt(-100, args[2], Linux.RDWR | Linux.CLOEXEC, 0);
            target = Linux.openAt(-100, args[3], Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.CLOEXEC, 0600);
            // Deliberately omit CLOEXEC: spawn must close unrelated inherited fds.
            sentinel = Linux.openAt(-100, args[4], Linux.RDONLY, 0);
            String parentLimits = Files.readString(Path.of("/proc/self/limits"));
            var parentFileLimit = java.util.regex.Pattern.compile("(?m)^Max file size\\s+(\\S+)\\s+(\\S+)\\s+bytes").matcher(parentLimits);
            if (!parentFileLimit.find()) throw new AssertionError("Parent limit missing");
            long parentSoft = limit(parentFileLimit.group(1)), parentHard = limit(parentFileLimit.group(2));
            String recipient = args.length > 5 ? args[5] : null;
            long limit = ArchiveInspector.MAX_ARCHIVE + (recipient == null ? 0 : 32L * 1024 * 1024);
            long expectedHard = Math.min(parentHard, limit), expectedSoft = Math.min(parentSoft, expectedHard);
            AtomicInteger active = new AtomicInteger(-1); pid = Linux.spawnAge(age, key, source, target, active, recipient);
            Path proc = Path.of("/proc", Integer.toString(pid));
            String status = Files.readString(proc.resolve("status"));
            if (!status.matches("(?s).*\\nNoNewPrivs:\\s+1\\n.*")) throw new AssertionError("no_new_privs missing");
            String limits = Files.readString(proc.resolve("limits"));
            if (!limits.matches("(?s).*Max file size\\s+" + expectedSoft + "\\s+" + expectedHard + "\\s+bytes.*")) throw new AssertionError("Output limit missing");
            if (!limits.matches("(?s).*Max core file size\\s+0\\s+0\\s+bytes.*")) throw new AssertionError("Core limit missing");
            try (var fds = Files.list(proc.resolve("fd"))) {
                for (Path entry : fds.toList()) {
                    try { if (Files.readSymbolicLink(entry).toString().equals(args[4])) throw new AssertionError("Inherited unrelated descriptor"); }
                    catch (java.nio.file.NoSuchFileException ignored) { }
                }
            }
            System.out.println("SPAWN_CONSTRAINTS_CONFIRMED");
        } catch (Throwable failure) { failure.printStackTrace(); code = 1; }
        finally {
            if (pid > 0) { try { Linux.kill(pid); } catch (Exception ignored) { } try { Linux.waitForDeath(pid); } catch (Exception ignored) { } }
            for (int fd : new int[]{age, key, source, target, sentinel}) if (fd >= 0) try { Linux.close(fd); } catch (Exception ignored) { }
        }
        if (code != 0) System.exit(code);
    }
    private static long limit(String value) { return value.equals("unlimited") ? Long.MAX_VALUE : Long.parseLong(value); }
}
