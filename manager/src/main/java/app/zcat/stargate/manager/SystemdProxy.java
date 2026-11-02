// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Controls only the unit selected at manager startup; no HTTP-supplied commands. */
final class SystemdProxy implements ProxyControl {
    private record Result(int exit, String output, boolean timedOut) {}
    private final String unit;

    SystemdProxy(String unit) { this.unit = unit; }

    public Unit sample() {
        Result result = run(List.of("show", unit, "--property=LoadState,ActiveState,SubState,MainPID,InvocationID,Result,ExecMainStatus"), 3);
        if (result.exit != 0 || result.timedOut) return unknown(result.timedOut ? "SYSTEMD_TIMEOUT" : "SYSTEMD_UNAVAILABLE");
        Map<String, String> values = new HashMap<>();
        for (String line : result.output.split("\n")) {
            int at = line.indexOf('=');if (at > 0) values.put(line.substring(0, at), line.substring(at + 1));
        }
        try {
            if (!values.containsKey("ActiveState") || !values.containsKey("LoadState")) return unknown("INVALID_SYSTEMD_REPLY");
            return new Unit("OBSERVED", values.get("LoadState"), values.get("ActiveState"), values.get("SubState"),
                    Long.valueOf(values.get("MainPID")), values.get("InvocationID"), values.get("Result"),
                    Integer.valueOf(values.get("ExecMainStatus")), "not-found".equals(values.get("LoadState")) ? "UNIT_NOT_FOUND" : "SYSTEMD_OBSERVED");
        } catch (RuntimeException e) { return unknown("INVALID_SYSTEMD_REPLY"); }
    }

    public Command action(String action) {
        if (!List.of("start", "stop", "restart").contains(action)) throw new IllegalArgumentException("INVALID_ACTION");
        Result result = run(List.of(action, unit), 15);
        return new Command(result.exit == 0 && !result.timedOut,
                result.timedOut ? "COMMAND_TIMEOUT" : result.exit == 0 ? "COMMAND_COMPLETED" : "COMMAND_FAILED");
    }

    private static Unit unknown(String code) { return new Unit("UNAVAILABLE", null, null, null, null, null, null, null, code); }

    private static Result run(List<String> arguments, int seconds) {
        List<String> command = new ArrayList<>(List.of("/usr/bin/systemctl", "--user", "--no-pager", "--no-ask-password"));
        command.addAll(arguments);
        Process process = null;
        try (var readers = Executors.newVirtualThreadPerTaskExecutor()) {
            ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
            builder.environment().put("LC_ALL", "C");builder.environment().put("SYSTEMD_COLORS", "0");
            process = builder.start();Process running = process;
            var read = readers.submit(() -> {
                byte[] data = running.getInputStream().readNBytes(16385);
                if (data.length > 16384) { running.destroyForcibly();throw new IOException("OUTPUT_LIMIT"); }
                return new String(data, StandardCharsets.UTF_8);
            });
            if (!process.waitFor(seconds, TimeUnit.SECONDS)) { process.destroyForcibly();return new Result(-1, "", true); }
            return new Result(process.exitValue(), read.get(1, TimeUnit.SECONDS), false);
        } catch (InterruptedException e) { Thread.currentThread().interrupt();return new Result(-1, "", false); }
        catch (Exception e) { return new Result(-1, "", false); }
        finally { if (process != null && process.isAlive()) process.destroyForcibly(); }
    }
}
