/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;

class CancellationTest {
    @TempDir Path root;
    static void ready(Path file) throws Exception {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (!Files.isRegularFile(file)) { if (System.nanoTime() > deadline) fail("Timed out waiting for " + file); Thread.sleep(5); }
    }
    static void stopped(Path pidFile) throws Exception {
        long pid = Long.parseLong(Files.readString(pidFile).strip());
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
        while (ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
            Path stat = Path.of("/proc/" + pid + "/stat");
            if (Files.exists(stat)) {
                String data = Files.readString(stat); String state = data.substring(data.lastIndexOf(')') + 2).split(" ")[0];
                if (state.equals("Z")) return; // exited; no process or inherited pipe remains active
            }
            if (System.nanoTime() > deadline) fail("Owned descendant still running: " + pid);
            Thread.sleep(5);
        }
    }
    @Test void timeoutIncludesPipesHeldByOrphanedDescendant() throws Exception {
        Path pid = root.resolve("descendant.pid");
        assertTimeoutPreemptively(Duration.ofSeconds(5), () -> {
            try {
                // A finished leader's streams may drain before the deadline.
                // Both that path and a timeout must stop the owned orphan.
                assertEquals(0, new Processes().run(List.of("sh", "-c", "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 0", "owned-command", pid.toString()), null, Duration.ofMillis(300)).status());
            } catch (TimeoutException | java.io.IOException deadline) {
                assertTrue(deadline instanceof TimeoutException || deadline.getMessage().startsWith("Command timed out:"), deadline.toString());
            }
        });
        ready(pid); stopped(pid);
    }
    @Test void interruptStopsCommandDescendantsBeforeJoiningReaders() throws Exception {
        Path pid = root.resolve("descendant.pid"); AtomicReference<Throwable> error = new AtomicReference<>();
        Thread worker = Thread.ofPlatform().start(() -> {
            try { new Processes().run(List.of("sh", "-c", "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait", "owned-command", pid.toString()), null, null); }
            catch (Throwable failure) { error.set(failure); }
        });
        ready(pid); worker.interrupt(); worker.join(3000);
        assertFalse(worker.isAlive(), "reader shutdown must finish after interruption"); assertNotNull(error.get()); stopped(pid);
    }
    @Test void interruptedPipelineStopsBothSessionsBeforeJoiningReaders() throws Exception {
        Path pid = root.resolve("descendant.pid"); AtomicReference<Throwable> error = new AtomicReference<>();
        Thread worker = Thread.ofPlatform().start(() -> {
            try { new Processes().pipeline(List.of("sh", "-c", "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; wait", "owned-command", pid.toString()), List.of("cat")); }
            catch (Throwable failure) { error.set(failure); }
        });
        ready(pid); worker.interrupt(); worker.join(3000);
        assertFalse(worker.isAlive(), "pipeline cleanup must precede reader joins"); assertNotNull(error.get()); stopped(pid);
    }
    @Test void pipelineCleansDescendantPipesWhenLeadersExitBeforeCancellation() throws Exception {
        Path pid = root.resolve("descendant.pid"); AtomicReference<Throwable> error = new AtomicReference<>();
        Thread worker = Thread.ofPlatform().start(() -> {
            try { new Processes().pipeline(List.of("sh", "-c", "printf payload"), List.of("sh", "-c", "cat >/dev/null; sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; exit 0", "owned-command", pid.toString())); }
            catch (Throwable failure) { error.set(failure); }
        });
        ready(pid); worker.interrupt(); worker.join(3000);
        // The JDK may finish draining/reaping both exited leaders before this
        // interrupt arrives. Either completion path must stop the owned orphan;
        // a late interrupt cannot retroactively fail an already finished call.
        assertFalse(worker.isAlive()); stopped(pid);
    }
    private void signal(String signal, String mode) throws Exception {
        Path proof = Files.createDirectory(root.resolve(signal + "-" + mode));
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        Process child = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-cp", classpath, CancellationChild.class.getName(), proof.toString(), mode)
            .redirectOutput(proof.resolve("stdout").toFile()).redirectError(proof.resolve("stderr").toFile()).start();
        try {
            ready(proof.resolve("ready"));
            Process delivered = new ProcessBuilder("/bin/kill", "-" + signal, Long.toString(child.pid())).start();
            assertTrue(delivered.waitFor(2, TimeUnit.SECONDS)); assertEquals(0, delivered.exitValue());
            assertTrue(child.waitFor(5, TimeUnit.SECONDS), () -> "Signal cleanup hung: " + proof);
            assertEquals(signal.equals("INT") ? 130 : 143, child.exitValue(), Files.readString(proof.resolve("stderr")));
            assertFalse(Files.exists(proof.resolve("unexpected-success")));
            List<String> trace = Files.readAllLines(proof.resolve("cleanup.trace"));
            if (mode.equals("mismatch")) {
                assertEquals(2, trace.stream().filter(line -> line.startsWith("inspect:")).count());
                assertFalse(trace.stream().anyMatch(line -> line.startsWith("unmount:") || line.startsWith("remove:")));
                assertTrue(Files.readString(proof.resolve("stderr")).contains("mismatch"));
            } else {
                assertEquals(List.of("inspect:" + Fixtures.HELPER_ID, "inspect:" + Fixtures.HELPER_ID, "unmount:" + Fixtures.HELPER_ID, "remove:" + Fixtures.HELPER_ID), trace);
            }
            stopped(proof.resolve("descendant.pid"));
            if (mode.equals("cleanup")) assertTrue(Files.exists(proof.resolve("cleanup-complete")), "signal must not abort an in-flight cleanup command");
        } finally { if (child.isAlive()) child.destroyForcibly(); }
    }
    @Test void actualSigintAndSigtermUnwindThroughVerifiedMountCleanup() throws Exception { signal("INT", "helper"); signal("TERM", "helper"); }
    @Test void actualSignalDuringPipelineStillCleansVerifiedMountHelper() throws Exception { signal("TERM", "pipeline"); }
    @Test void actualSignalNeverCleansHelperWhoseIdentityChanged() throws Exception { signal("TERM", "mismatch"); }
    @Test void actualSignalsDuringCleanupFinishVerifiedUnmountAndRemoval() throws Exception { signal("INT", "cleanup"); signal("TERM", "cleanup"); }
}
