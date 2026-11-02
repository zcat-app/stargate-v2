/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import java.io.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

@FunctionalInterface
interface Transport {
  record Request(
      List<String> argv,
      Path cwd,
      Path out,
      Path err,
      byte[] stdin,
      int timeout,
      long outLimit,
      long combinedLimit,
      Map<String, String> env,
      int umask,
      boolean mergeError) {}

  int run(Request request) throws Exception;

  class Uncertain extends IOException {
    Uncertain(String message) {
      super(message);
    }

    Uncertain(String message, Throwable cause) {
      super(message, cause);
    }
  }

  final class Processes implements Transport {
    public int run(Request request) throws Exception {
      Cancellation.checkpoint();
      trustedTool(Path.of("/usr/bin/setsid"));
      trustedTool(Path.of("/bin/sh"));
      ExecutorService workers = Executors.newVirtualThreadPerTaskExecutor();
      LocalSessions.Session owned = new LocalSessions.Session();
      FileChannel out = null, err = null;
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(request.timeout);
      try {
        out = create(request.out);
        err = create(request.err);
        List<String> command =
            new ArrayList<>(
                List.of(
                    "/bin/sh",
                    "-c",
                    "umask \"$1\"; shift; exec \"$@\"",
                    "stargate-private-tool",
                    String.format("%03o", request.umask)));
        command.addAll(request.argv);
        ProcessBuilder builder =
            owned
                .builder(command)
                .directory(request.cwd.toFile())
                .redirectErrorStream(request.mergeError);
        builder.environment().clear();
        builder.environment().putAll(request.env);
        owned.process = builder.start();
        owned.capture();
        Process process = owned.process;
        AtomicReference<Throwable> failure = new AtomicReference<>();
        AtomicLong combined = new AtomicLong();
        FileChannel stdoutFile = out, stderrFile = err;
        Runnable stop = process::destroyForcibly;
        Future<?> stdout =
            workers.submit(
                () ->
                    pump(
                        process.getInputStream(),
                        stdoutFile,
                        request.outLimit,
                        request.combinedLimit,
                        combined,
                        failure,
                        stop));
        Future<?> stderr =
            workers.submit(
                () ->
                    pump(
                        process.getErrorStream(),
                        stderrFile,
                        16L * 1024 * 1024,
                        request.combinedLimit,
                        combined,
                        failure,
                        stop));
        Future<?> stdin =
            workers.submit(
                () -> {
                  try (var stream = process.getOutputStream()) {
                    if (request.stdin != null) stream.write(request.stdin);
                  } catch (Exception error) {
                    failure.compareAndSet(null, error);
                    stop.run();
                  }
                });
        if (!process.waitFor(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
          throw new Uncertain(
              "Local client deadline exceeded; daemon operation may still be active");
        for (Future<?> future : List.of(stdout, stderr, stdin)) await(future, deadline, failure);
        if (failure.get() != null)
          throw new Uncertain("Local client input/output failure", failure.get());
        out.force(true);
        err.force(true);
        return process.exitValue();
      } catch (Exception error) {
        throw error instanceof Uncertain
            ? error
            : new Uncertain("Local client outcome uncertain", error);
      } finally {
        try (var cleanup = Cancellation.cleanup()) {
          owned.close();
          LocalSessions.stopReaders(workers);
          if (out != null) out.close();
          if (err != null) err.close();
        }
        Cancellation.checkpoint();
      }
    }

    static void await(Future<?> future, long deadline, AtomicReference<Throwable> failure)
        throws Exception {
      while (true) {
        if (failure.get() != null)
          throw new Uncertain("Local client input/output failure", failure.get());
        long left = deadline - System.nanoTime();
        if (left <= 0) throw new Uncertain("Local client deadline exceeded");
        try {
          future.get(Math.min(left, TimeUnit.MILLISECONDS.toNanos(50)), TimeUnit.NANOSECONDS);
          return;
        } catch (TimeoutException pending) {
        }
      }
    }

    static void pump(
        InputStream input,
        FileChannel output,
        long limit,
        long combinedLimit,
        AtomicLong combined,
        AtomicReference<Throwable> failure,
        Runnable stop) {
      try (input) {
        byte[] buffer = new byte[65536];
        long count = 0;
        for (int n; (n = input.read(buffer)) != -1; ) {
          count += n;
          need(
              count <= limit && combined.addAndGet(n) <= combinedLimit,
              "Local client output limit exceeded");
          write(output, Arrays.copyOf(buffer, n));
        }
      } catch (Exception error) {
        failure.compareAndSet(null, error);
        stop.run();
      }
    }
  }
}
