/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import java.nio.file.*;
import java.util.*;
import static app.zcat.stargate.libc.LibcIO.*;

/** Actual OS signals/local children; every Docker interaction is a synthetic fixture. */
public final class CancellationChild {
    public static void main(String[] args) throws Exception {
        Path root = Path.of(args[0]); String mode = args[1];
        Fixtures.Harness fixture = new Fixtures.Harness();
        if (mode.equals("mismatch")) fixture.wrongCleanup = true;
        LibcIO.Runner runner = (command, input, timeout) -> {
            if (mode.equals("cleanup") && command.getLast().contains("if mountpoint -q")) {
                new Processes().run(List.of("sh", "-c", "sleep 0.4 & child=$!; printf '%s\\n' \"$child\" > \"$1\"; printf ready > \"$2\"; wait \"$child\"; printf complete > \"$3\"", "cleanup-command", root.resolve("descendant.pid").toString(), root.resolve("ready").toString(), root.resolve("cleanup-complete").toString()), null, timeout);
            }
            if (command.contains("unshare")) {
                String script = "sleep 30 & child=$!; printf '%s\\n' \"$child\" > \"$1\"; printf ready > \"$2\"; wait";
                List<String> blocking = List.of("sh", "-c", script, "owned-command", root.resolve("descendant.pid").toString(), root.resolve("ready").toString());
                if (mode.equals("pipeline")) { new Processes().pipeline(blocking, List.of("cat")); return Result.text(0, ""); }
                return new Processes().run(blocking, null, null);
            }
            Result result = fixture.run(command, input, timeout);
            if (command.get(1).equals("inspect") && command.getLast().equals(Fixtures.HELPER_ID)) trace(root, "inspect:" + Fixtures.HELPER_ID);
            if (command.getLast().contains("if mountpoint -q")) trace(root, "unmount:" + Fixtures.HELPER_ID);
            if (command.get(1).equals("rm")) trace(root, "remove:" + command.getLast());
            return result;
        };
        int status = LibcTools.controlled(() -> {
            if (mode.equals("cleanup")) {
                try (var helper = new Ownership.Helper(new LibcIO(root, runner), Fixtures.BUILDER_ID, Fixtures.IMAGE)) { helper.start(); }
                Cancellation.checkpoint();
                return 0;
            }
            new LibcBuild(new LibcIO(root, runner)).build(new Target(Fixtures.BUILDER_ID, false), "2.39-test", Fixtures.IMAGE, true);
            Files.writeString(root.resolve("unexpected-success"), "must not be reached");
            return 0;
        });
        Files.writeString(root.resolve("status"), Integer.toString(status));
        System.exit(status);
    }
    private static void trace(Path root, String value) throws Exception {
        Files.writeString(root.resolve("cleanup.trace"), value + "\n", StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }
}
