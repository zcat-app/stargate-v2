/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.function.BooleanSupplier;
import static app.zcat.stargate.libc.LibcIO.*;

final class Diagnostic {
    record Check(String name, String state, String detail) {}
    final LibcIO io; final BooleanSupplier docker;
    Diagnostic(LibcIO io, BooleanSupplier docker) { this.io = io; this.docker = docker; }
    static boolean dockerAvailable() { for (String directory : System.getenv().getOrDefault("PATH", "").split(":")) if (!directory.isEmpty() && Files.isExecutable(Path.of(directory, "docker"))) return true; return false; }
    List<Check> check() {
        List<Check> checks = new ArrayList<>(); List<String> sourceNames = null;
        try {
            JsonNode inputs = io.inputs(); sourceNames = names(inputs.path("source_files_sha256"));
            boolean matches = sha(io.project.resolve("containers/native/patches/glibc-CVE-2026-18374.patch")).equals(inputs.path("patches").get(0).path("sha256").asText());
            checks.add(new Check("local patch", matches ? "present" : "invalid", matches ? "hash matches manifest" : "hash mismatch"));
        } catch (NoSuchFileException | java.io.FileNotFoundException missing) { checks.add(new Check("local inputs", "missing", missing.getMessage())); }
        catch (Exception unknown) { checks.add(new Check("local inputs", "unknown", unknown.getMessage())); }
        if (!docker.getAsBoolean()) { checks.add(new Check("Docker CLI", "missing", "not found in PATH")); checks.add(new Check("builder", "unknown", "Docker CLI unavailable")); return checks; }
        try {
            Result listed = io.runner.run(List.of("docker", "container", "ls", "--all", "--format", "{{.Names}}\t{{.State}}"), null, Duration.ofSeconds(15));
            if (listed.status() != 0) { checks.add(new Check("builder", "unknown", "Docker container listing failed")); return checks; }
            List<String[]> matches = new ArrayList<>();
            for (String line : listed.text().lines().toList()) {
                String[] fields = line.split("\t", -1);
                if (fields.length != 2) { checks.add(new Check("builder", "unknown", "unexpected Docker listing format")); return checks; }
                if (fields[0].equals(BUILDER)) matches.add(fields);
            }
            if (matches.isEmpty()) { checks.add(new Check("builder", "missing", "container not listed")); return checks; }
            if (matches.size() != 1) { checks.add(new Check("builder", "unknown", "ambiguous Docker listing")); return checks; }
            if (!matches.getFirst()[1].equals("running")) { checks.add(new Check("builder", "present", "container is not running")); checks.add(new Check("build prerequisites", "unknown", "container is not running")); return checks; }
            checks.add(new Check("builder", "present", "container is running"));
            if (sourceNames == null) { checks.add(new Check("build prerequisites", "unknown", "source manifest unavailable or unsupported")); return checks; }
            List<String> paths = new ArrayList<>(List.of(CHROOT, CHROOT + SRC)); for (String name : sourceNames) paths.add(CHROOT + SRC + "/../" + name);
            String script = paths.stream().map(path -> "if test -e " + quote(path) + "; then echo present; else echo unknown; fi").reduce((first, second) -> first + "; " + second).orElseThrow();
            Result probe = io.runner.run(List.of("docker", "exec", BUILDER, "/bin/sh", "-c", script), null, Duration.ofSeconds(15));
            List<String> states = probe.text().lines().toList();
            if (probe.status() != 0 || states.size() != paths.size() || states.stream().anyMatch(state -> !List.of("present", "unknown").contains(state))) { checks.add(new Check("build prerequisites", "unknown", "container path probe failed")); return checks; }
            for (int i = 0; i < paths.size(); i++) checks.add(new Check(paths.get(i), states.get(i), states.get(i).equals("present") ? "path exists" : "path absent or inaccessible"));
        } catch (Exception failure) { checks.add(new Check("builder inspection", "unknown", "Docker command unavailable or timed out")); }
        return checks;
    }
    int print() {
        List<Check> checks = check(); for (Check check : checks) System.out.println(check.name + ": " + check.state + " (" + check.detail + ")");
        System.out.println("Source hashes, applied patch, dependencies, and build results are not verified by this diagnostic.");
        System.out.println("Source/seed/bootstrap migration and clean-host verification are separate from this prepared-builder diagnostic.");
        return checks.stream().allMatch(check -> check.state.equals("present")) ? 0 : 1;
    }
}
