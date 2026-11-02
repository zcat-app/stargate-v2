/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SignalTest {
  @TempDir Path root;

  static String output(Path proof) throws Exception {
    return "\nstdout:\n"
        + Files.readString(proof.resolve("stdout"))
        + "\nstderr:\n"
        + Files.readString(proof.resolve("stderr"));
  }

  void signal(String name, String mode) throws Exception {
    Path proof = privateDirectory(root.resolve(name + "-" + mode));
    String classpath =
        System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
    Process child =
        new ProcessBuilder(
                Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "--enable-native-access=ALL-UNNAMED",
                "-cp",
                classpath,
                SignalChild.class.getName(),
                proof.toString(),
                mode)
            .directory(Path.of(System.getProperty("user.dir")).toFile())
            .redirectOutput(proof.resolve("stdout").toFile())
            .redirectError(proof.resolve("stderr").toFile())
            .start();
    try {
      // Real fsync calls in the synthetic setup can outlast five seconds on a busy disk.
      // Bound setup separately from the unchanged six-second post-signal cancellation limit.
      long started = System.nanoTime();
      long deadline = started + TimeUnit.SECONDS.toNanos(30);
      while (!Files.exists(proof.resolve("ready"))) {
        if (!child.isAlive() || System.nanoTime() > deadline)
          fail(
              "Signal child failed before readiness: "
                  + proof
                  + "; state="
                  + (child.isAlive() ? "running" : "exit " + child.exitValue())
                  + output(proof));
        Thread.sleep(5);
      }
      System.out.println(
          "Signal fixture ready: "
              + name
              + " "
              + mode
              + " after "
              + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)
              + " ms");
      long signalled = System.nanoTime();
      Process kill =
          new ProcessBuilder("/bin/kill", "-" + name, Long.toString(child.pid())).start();
      assertTrue(kill.waitFor(2, TimeUnit.SECONDS));
      assertEquals(0, kill.exitValue());
      if (!child.waitFor(6, TimeUnit.SECONDS))
        fail("Controlled cancellation must finish within six seconds" + output(proof));
      System.out.println(
          "Signal fixture exited: "
              + name
              + " "
              + mode
              + " after signal "
              + TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - signalled)
              + " ms");
      assertEquals(name.equals("INT") ? 130 : 143, child.exitValue(), output(proof));
      var result = json(proof.resolve("signal-result.json"));
      assertEquals("failed", result.path("status").asText());
      if (mode.equals("source")) {
        var status = json(Path.of(result.path("workspace").asText()).resolve("status.json"));
        assertEquals("incomplete", status.path("status").asText());
        assertEquals("download", status.path("stage").asText());
        assertEquals(1, status.path("artifacts").size());
      } else
        assertTrue(result.path("cleanup").asText().contains("retain"), result.toPrettyString());
      if (mode.equals("critical")) assertTrue(Files.exists(proof.resolve("critical-complete")));
      else TransportTest.stopped(proof.resolve("child.pid"));
    } finally {
      if (child.isAlive()) child.destroyForcibly();
    }
  }

  @Test
  void actualSignalsDeferUntilCriticalLocalCleanupCompletes() throws Exception {
    signal("INT", "critical");
    signal("TERM", "critical");
  }

  @Test
  void actualSigintAndSigtermRetainOwnedSeedAfterUncertainClientCancellation() throws Exception {
    signal("INT", "seed");
    signal("TERM", "seed");
  }

  @Test
  void actualSignalRetainsBuilderSeedAndImageDuringRootCopy() throws Exception {
    signal("TERM", "builder");
  }

  @Test
  void actualSourceSignalRetainsIncompleteWorkspaceWithoutLaterDownloads() throws Exception {
    signal("INT", "source");
  }
}
