// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.concurrent.TimeUnit;
import static org.junit.jupiter.api.Assertions.*;

/** Separate JVMs exercise the platform's process-wide POSIX record locks. */
public final class SnapshotLockProcess {
    static Process start(String operation, Path file) throws Exception {
        return new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("surefire.test.class.path", System.getProperty("java.class.path")),
                SnapshotLockProcess.class.getName(), operation, file.toString())
                .redirectError(ProcessBuilder.Redirect.INHERIT).start();
    }

    static int run(String operation, Path file) throws Exception {
        Process process = start(operation, file);
        try {
            assertTrue(process.waitFor(5, TimeUnit.SECONDS), "lock probe timed out");
            String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            assertTrue(process.exitValue() == 0 || operation.equals("probe") && process.exitValue() == 3, output);
            return process.exitValue();
        } finally { process.destroyForcibly(); }
    }

    static HeldLock hold(Path file) throws Exception { return new HeldLock(file); }

    static final class HeldLock implements AutoCloseable {
        private final Process process;
        HeldLock(Path file) throws Exception {
            process = start("hold", file);
            try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
                var ready = executor.submit(() -> new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8)).readLine());
                try { assertEquals("ready", ready.get(5, TimeUnit.SECONDS)); }
                catch (Exception | AssertionError e) { process.destroyForcibly(); throw e; }
            }
        }
        @Override public void close() throws Exception {
            try {
                process.getOutputStream().close();
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "lock holder timed out");
                assertEquals(0, process.exitValue());
            } finally { process.destroyForcibly(); }
        }
    }

    public static void main(String[] args) throws Exception {
        try (var channel = FileChannel.open(Path.of(args[1]), StandardOpenOption.READ, StandardOpenOption.WRITE);
             var lock = channel.tryLock()) {
            if (lock == null) { System.exit(3); return; }
            switch (args[0]) {
                case "probe" -> { }
                case "hold" -> { System.out.println("ready"); System.out.flush(); System.in.read(); }
                case "tear" -> { channel.truncate(0); channel.write(ByteBuffer.wrap(new byte[]{'{'})); channel.force(true); }
                default -> throw new IllegalArgumentException("unknown lock operation");
            }
        }
    }
}
