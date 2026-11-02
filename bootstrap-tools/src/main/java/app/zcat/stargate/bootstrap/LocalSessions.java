/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;

/** Own a private local session so inherited pipes can be closed even after the leader exits. */
final class LocalSessions {
  static final class Session implements AutoCloseable {
    final Path directory, groupFile;
    final int uid;
    Process process;
    long group, startTicks;

    Session() throws IOException {
      directory =
          Files.createTempDirectory(
              "stargate-libc-process-",
              PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      groupFile = directory.resolve("group");
      uid =
          ((Number) Files.getAttribute(directory, "unix:uid", LinkOption.NOFOLLOW_LINKS))
              .intValue();
    }

    ProcessBuilder builder(List<String> command) throws IOException {
      IO.need(
          Files.isExecutable(Path.of("/usr/bin/setsid")) && Files.isExecutable(Path.of("/bin/sh")),
          "Local process isolation requires /usr/bin/setsid and /bin/sh");
      List<String> isolated =
          new ArrayList<>(
              List.of(
                  "/usr/bin/setsid",
                  "--wait",
                  "/bin/sh",
                  "-c",
                  "printf '%s\\n' \"$$\" > \"$1\"; shift; exec \"$@\"",
                  "stargate-local-process",
                  groupFile.toString()));
      isolated.addAll(command);
      return new ProcessBuilder(isolated);
    }

    void capture() throws Exception {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
      while (!readGroup()) {
        if (!process.isAlive() || System.nanoTime() >= deadline)
          throw new IOException("Local process session identity was not captured");
        Thread.sleep(2);
      }
    }

    boolean readGroup() throws IOException {
      if (group != 0) return true;
      if (!Files.isRegularFile(groupFile, LinkOption.NOFOLLOW_LINKS)) return false;
      String value = Files.readString(groupFile).strip();
      if (!value.matches("[0-9]+")) return false;
      long candidate = Long.parseLong(value);
      IO.need(
          candidate > 1 && candidate != ProcessHandle.current().pid(),
          "Invalid local process group identity");
      Proc info = proc(candidate);
      if (info != null) {
        IO.need(
            info.group == candidate && info.session == candidate && info.uid == uid,
            "Local process session identity mismatch");
        startTicks = info.start;
      }
      group = candidate;
      return true;
    }

    List<ProcessHandle> members() {
      if (group == 0) return List.of();
      Proc leader = proc(group);
      if (leader != null && startTicks != 0 && leader.start != startTicks) return List.of();
      List<ProcessHandle> members = new ArrayList<>();
      try (var processes = ProcessHandle.allProcesses()) {
        processes.forEach(
            handle -> {
              Proc info = proc(handle.pid());
              if (info != null
                  && info.uid == uid
                  && info.group == group
                  && info.session == group
                  && (startTicks == 0 || info.start >= startTicks)) members.add(handle);
            });
      }
      // Let waiting parents reap their children before stopping a surviving session leader.
      members.sort(Comparator.comparing(handle -> handle.pid() == group));
      return members;
    }

    public void close() {
      boolean interrupted = Thread.interrupted();
      try {
        if (process != null) {
          try {
            readGroup();
          } catch (Exception ignored) {
            /* fallback is only captured direct descendants */
          }
          Set<ProcessHandle> targets = new LinkedHashSet<>(members());
          process.descendants().forEach(targets::add);
          for (ProcessHandle handle : targets) {
            handle.destroyForcibly();
            try {
              handle.onExit().get(150, TimeUnit.MILLISECONDS);
            } catch (Exception ignored) {
            }
          }
          process.destroyForcibly();
          closeQuietly(process.getOutputStream());
          closeQuietly(process.getInputStream());
          closeQuietly(process.getErrorStream());
          try {
            process.waitFor(500, TimeUnit.MILLISECONDS);
          } catch (InterruptedException ignored) {
            interrupted = true;
          }
        }
      } finally {
        try {
          Files.deleteIfExists(groupFile);
          Files.deleteIfExists(directory);
        } catch (IOException ignored) {
        }
        if (interrupted) Thread.currentThread().interrupt();
      }
    }
  }

  private record Proc(long group, long session, long start, int uid) {}

  private static Proc proc(long pid) {
    try {
      Path root = Path.of("/proc/" + pid);
      String stat = Files.readString(root.resolve("stat"));
      String[] fields = stat.substring(stat.lastIndexOf(')') + 2).split(" ");
      return new Proc(
          Long.parseLong(fields[2]),
          Long.parseLong(fields[3]),
          Long.parseLong(fields[19]),
          ((Number) Files.getAttribute(root, "unix:uid")).intValue());
    } catch (Exception unavailable) {
      return null;
    }
  }

  private static void closeQuietly(Closeable stream) {
    try {
      stream.close();
    } catch (IOException ignored) {
    }
  }

  static void stopReaders(ExecutorService readers) {
    boolean interrupted = Thread.interrupted();
    readers.shutdownNow();
    try {
      readers.awaitTermination(1, TimeUnit.SECONDS);
    } catch (InterruptedException ignored) {
      interrupted = true;
    }
    if (interrupted) Thread.currentThread().interrupt();
  }
}
