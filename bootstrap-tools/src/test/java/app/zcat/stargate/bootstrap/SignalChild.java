/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedExecutor.object;
import static app.zcat.stargate.bootstrap.SeedFixtures.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;

/** Actual OS signals; all Docker operations are deterministic synthetic fixture responses. */
public final class SignalChild {
  static Transport.Request blocking(Path root, Transport.Request original) {
    List<String> args =
        List.of(
            "sh",
            "-c",
            "sleep 30 & printf '%s\\n' \"$!\" > \"$1\"; printf ready > \"$2\"; wait",
            "owned",
            root.resolve("child.pid").toString(),
            root.resolve("ready").toString());
    return new Transport.Request(
        args,
        original.cwd(),
        original.out(),
        original.err(),
        null,
        30,
        1024,
        2048,
        TOOL_ENV,
        0077,
        false);
  }

  public static void main(String[] args) throws Exception {
    Path root = Path.of(args[0]);
    String mode = args[1];
    Cancellation cancellation = Cancellation.install();
    ObjectNode result = null;
    int status = 1;
    try {
      if (mode.equals("critical")) {
        try {
          try (var cleanup = Cancellation.cleanup()) {
            Files.writeString(root.resolve("ready"), "ready");
            Thread.sleep(300);
            Files.writeString(root.resolve("critical-complete"), "done");
          }
          Cancellation.checkpoint();
        } catch (Cancellation.Cancelled cancelled) {
          result =
              object("status", "failed", "cleanup", "retain; critical local cleanup completed");
        }
      } else if (mode.equals("source")) {
        System.out.println("Preparing synthetic source fixture");
        SourcePreparerTest fixture = new SourcePreparerTest();
        fixture.root = root;
        fixture.setup();
        SourcePreparer helper =
            new SourcePreparer(
                fixture.project,
                new Transport.Processes(),
                (name, path) -> {
                  bytes(root.resolve("download-attempt"), name.getBytes());
                  new Transport.Processes()
                      .run(
                          blocking(
                              root,
                              new Transport.Request(
                                  List.of(),
                                  path.getParent(),
                                  path.getParent().resolve("block.out"),
                                  path.getParent().resolve("block.err"),
                                  null,
                                  30,
                                  1024,
                                  2048,
                                  TOOL_ENV,
                                  0077,
                                  false)));
                });
        try {
          System.out.println("Starting source preparation");
          helper.prepare(fixture.parent);
        } catch (Exception error) {
          try (var work = Files.list(fixture.parent)) {
            result =
                object(
                    "status",
                    "failed",
                    "workspace",
                    work.findFirst().orElseThrow().toString(),
                    "error",
                    error.toString());
          }
        }
      } else {
        Path docker = root.resolve("docker");
        bytes(docker, "synthetic client".getBytes());
        ObjectNode plan = SeedContract.plan(inputs(), MARKER, root, null);
        save(root.resolve("plan.json"), plan);
        SeedExecutor.claim(root.resolve("plan.json"));
        FakeDocker fake = new FakeDocker(null);
        if (mode.equals("builder")) fake.seedState = "running";
        Transport transport =
            request -> {
              String name = request.err().getFileName().toString();
              System.out.println("Synthetic Docker stage: " + name);
              if (name.contains(mode.equals("builder") ? "-copy-root." : "-apt-update-seed."))
                return new Transport.Processes().run(blocking(root, request));
              return fake.run(request);
            };
        try (var journal = new SeedExecutor.Journal(root)) {
          var executor =
              new ProofExecutor(
                  plan, root, docker, sha(docker), DAEMON, journal, transport, (s, c) -> inputs());
          result =
              mode.equals("builder") ? new BuilderBootstrap(executor, CID).run() : executor.run();
        }
        for (List<String> call : fake.calls)
          need(
              !List.of("stop", "rm").contains(call.getFirst()),
              "Cancellation must retain exact-ID resources");
      }
    } finally {
      cancellation.close();
    }
    if (result != null) save(root.resolve("signal-result.json"), result);
    System.exit(cancellation.exitCode(status));
  }
}
