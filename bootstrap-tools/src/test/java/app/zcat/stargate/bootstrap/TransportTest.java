/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TransportTest {
  @TempDir Path root;
  int sequence;

  Transport.Request request(List<String> args, int seconds, long limit, int mask) {
    String name = "run-" + (++sequence);
    return new Transport.Request(
        args,
        root,
        root.resolve(name + ".out"),
        root.resolve(name + ".err"),
        null,
        seconds,
        limit,
        limit + 1024,
        TOOL_ENV,
        mask,
        false);
  }

  @Test
  void binaryStderrAndFailingExitArePreservedWithPrivateLogs() throws Exception {
    var request =
        request(
            List.of("sh", "-c", "printf '\\000\\377'; printf error >&2; exit 7"), 5, 1024, 0077);
    assertEquals(7, new Transport.Processes().run(request));
    assertArrayEquals(new byte[] {0, (byte) 255}, Files.readAllBytes(request.out()));
    assertEquals("error", Files.readString(request.err()));
    assertEquals(0600, mode(request.out()));
    assertEquals(0600, mode(request.err()));
  }

  @Test
  void outputLimitsAreEnforcedBeforeOversizeWrites() throws Exception {
    var request = request(List.of("sh", "-c", "head -c 10000 /dev/zero"), 5, 100, 0077);
    assertThrows(Transport.Uncertain.class, () -> new Transport.Processes().run(request));
    assertTrue(Files.size(request.out()) <= 100);
  }

  @Test
  void perChildUmaskAndClearedEnvironmentDoNotAlterHost() throws Exception {
    for (int mask : List.of(0022, 0077)) {
      Path created = root.resolve("child-" + mask);
      var request =
          request(
              List.of(
                  "sh", "-c", "test -z \"${HOME+x}\"; : > \"$1\"", "literal", created.toString()),
              5,
              1024,
              mask);
      assertEquals(0, new Transport.Processes().run(request));
      assertEquals(mask == 0022 ? 0644 : 0600, mode(created));
    }
  }

  @Test
  void timeoutTerminatesOwnedDescendantsBeforeReaderShutdown() throws Exception {
    Path pid = root.resolve("child.pid");
    var request =
        request(
            List.of(
                "sh",
                "-c",
                "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait",
                "owned",
                pid.toString()),
            1,
            1024,
            0077);
    assertTimeoutPreemptively(
        java.time.Duration.ofSeconds(5),
        () ->
            assertThrows(Transport.Uncertain.class, () -> new Transport.Processes().run(request)));
    stopped(pid);
  }

  @Test
  void exitedLeaderWithInheritedPipesCannotHangOrLeaveChildRunning() throws Exception {
    Path pid = root.resolve("child.pid");
    var request =
        request(
            List.of(
                "sh",
                "-c",
                "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 0",
                "owned",
                pid.toString()),
            1,
            1024,
            0077);
    assertTimeoutPreemptively(
        java.time.Duration.ofSeconds(5),
        () -> {
          try {
            new Transport.Processes().run(request);
          } catch (Transport.Uncertain expected) {
          }
        });
    stopped(pid);
  }

  @Test
  void interruptionIsUncertainAndUnblocksAllReaders() throws Exception {
    Path pid = root.resolve("child.pid");
    var request =
        request(
            List.of(
                "sh",
                "-c",
                "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait",
                "owned",
                pid.toString()),
            30,
            1024,
            0077);
    AtomicReference<Throwable> error = new AtomicReference<>();
    Thread worker =
        Thread.ofPlatform()
            .start(
                () -> {
                  try {
                    new Transport.Processes().run(request);
                  } catch (Throwable failure) {
                    error.set(failure);
                  }
                });
    ready(pid);
    worker.interrupt();
    worker.join(3000);
    assertFalse(worker.isAlive());
    assertInstanceOf(Transport.Uncertain.class, error.get());
    stopped(pid);
  }

  static void ready(Path file) throws Exception {
    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (!Files.exists(file)) {
      if (System.nanoTime() > end) fail("Missing readiness: " + file);
      Thread.sleep(5);
    }
  }

  static void stopped(Path file) throws Exception {
    ready(file);
    long pid = Long.parseLong(Files.readString(file).strip());
    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
    while (ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
      try {
        String stat = Files.readString(Path.of("/proc/" + pid + "/stat"));
        if (stat.substring(stat.lastIndexOf(')') + 2).startsWith("Z ")) return;
      } catch (NoSuchFileException gone) {
        return;
      }
      if (System.nanoTime() > end) fail("Owned child still active: " + pid);
      Thread.sleep(5);
    }
  }
}
