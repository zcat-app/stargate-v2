/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import static app.zcat.stargate.libc.LibcIO.*;

final class FopenRegression {
    static final List<String> CASES = List.of("overflow", "empty", "empty-comma", "spaces", "punctuation", "invalid", "utf8", "ascii", "normal", "read-utf8", "read-ascii", "read-latin1");
    static final String VG = "TMPDIR=/tmp VALGRIND_LIB=/tmp/tools/usr/libexec/valgrind /tmp/tools/usr/bin/valgrind";
    static final String RUNNER_IMAGE = "ubuntu:24.04";
    final LibcIO io;
    FopenRegression(LibcIO io) { this.io = io; }
    record Gate(boolean passed, List<String> reasons) {}
    static Gate gate(String label, JsonNode report) {
        List<String> reasons = new ArrayList<>(); JsonNode cases = report.path("cases");
        boolean complete = cases.isObject() && new HashSet<>(names(cases)).equals(new HashSet<>(CASES));
        boolean semantics = complete; long writes = 0, reads = 0;
        for (JsonNode record : cases) {
            semantics &= record.path("probe_semantics_ok").isBoolean() && record.path("probe_semantics_ok").asBoolean();
            if (!record.path("invalid_writes").isIntegralNumber() || !record.path("invalid_writes").canConvertToLong() || record.path("invalid_writes").asLong(-1) < 0 || !record.path("invalid_reads").isIntegralNumber() || !record.path("invalid_reads").canConvertToLong() || record.path("invalid_reads").asLong(-1) < 0) semantics = false;
            try { writes = Math.addExact(writes, record.path("invalid_writes").asLong()); reads = Math.addExact(reads, record.path("invalid_reads").asLong()); }
            catch (ArithmeticException overflow) { semantics = false; }
        }
        if (!complete) reasons.add("all twelve named cases must be recorded");
        if (!semantics) reasons.add(label + " cases did not all keep correct observable behavior");
        if (label.equals("control")) { if (writes < 1) reasons.add("control failed to demonstrate the invalid writes it must prove"); }
        else if (writes != 0 || reads != 0) reasons.add("patched libc still shows invalid accesses (writes=" + writes + ", reads=" + reads + ")");
        if (!report.path("build_id_match").isBoolean() || !report.path("build_id_match").asBoolean()) reasons.add("probe build ID does not match libc under test");
        boolean passed = reasons.isEmpty();
        if (label.equals("control")) reasons.add("invalid_writes=" + writes);
        return new Gate(passed, List.copyOf(reasons));
    }
    static int count(String regex, String text) { return (int)Pattern.compile(regex).matcher(text).results().count(); }
    static ObjectNode caseRecord(String name, int rc, String raw, String log) {
        ObjectNode record = JSON.createObjectNode().put("case", name).put("rc", rc).put("probe_stdout", raw);
        JsonNode probe = NullNode.instance;
        try { probe = JSON.readTree(raw); } catch (Exception ignored) { /* malformed probe output fails observable semantics below */ }
        if (probe == null) probe = NullNode.instance;
        record.set("probe", probe);
        record.put("probe_semantics_ok", probe.isObject() && probe.path("passed").isBoolean() && probe.path("passed").asBoolean() && probe.path("case").asText().equals(name) && (rc == 0 || rc == 97));
        record.put("invalid_writes", count("==[0-9]+== Invalid write", log)).put("invalid_reads", count("==[0-9]+== Invalid read", log)).put("uninitialised_reports", count("==[0-9]+== (?:Conditional jump|Uninitialised)", log));
        Matcher summary = Pattern.compile("ERROR SUMMARY:\\s*([0-9]+) errors").matcher(log);
        Integer last = null; while (summary.find()) last = Integer.parseInt(summary.group(1));
        if (last == null) record.putNull("error_summary"); else record.put("error_summary", last);
        return record;
    }
    static void validateRunner(JsonNode data, String id, String name, String image, String marker) throws Exception {
        JsonNode config = data.path("Config"), host = data.path("HostConfig");
        need(data.path("Id").asText().equals(id) && data.path("Name").asText().equals("/" + name) && data.path("Image").asText().equals(image) && image.matches("sha256:[0-9a-f]{64}") && config.path("Labels").path(Ownership.RUNNER_LABEL).asText().equals(marker) && config.path("User").asText().equals("0:0") && config.path("Entrypoint").equals(JSON.valueToTree(List.of("/bin/sleep"))) && config.path("Cmd").equals(JSON.valueToTree(List.of("infinity"))) && host.path("NetworkMode").asText().equals("none") && Ownership.privateResources(data, false, Set.of("", "private"), true), "Regression runner ownership/configuration mismatch; no cleanup attempted");
    }
    final class OwnedRunner implements AutoCloseable {
        final String marker = Ownership.token(), name = "stargate-v2-libc-vgtest-" + marker, id, image;
        final Target target;
        OwnedRunner() throws Exception {
            id = io.checked(List.of("docker", "create", "--privileged", "--network", "none", "--user", "0:0", "--name", name, "--label", Ownership.RUNNER_LABEL + "=" + marker, "--entrypoint", "/bin/sleep", RUNNER_IMAGE, "infinity")).text().strip();
            need(id.matches("[0-9a-f]{64}"), "Regression runner returned invalid ID; inspect only candidate " + name);
            JsonNode data = io.inspect(id); image = data.path("Image").asText();
            validateRunner(data, id, name, image, marker); target = new Target(id, false);
        }
        void start() throws Exception { System.out.println("Regression runner: id=" + id + " name=" + name + " label=" + Ownership.RUNNER_LABEL + "=" + marker); io.checked(List.of("docker", "start", id)); }
        public void close() throws Exception { try (var cleanup = Cancellation.cleanup()) { validateRunner(io.inspect(id), id, name, image, marker); io.checked(List.of("docker", "rm", "--force", id)); } }
    }
    ObjectNode identity(Target runner) throws Exception {
        String libc = "/lib/x86_64-linux-gnu/libc.so.6";
        Matcher match = Pattern.compile("Build ID:\\s*([0-9a-f]+)").matcher(io.shell(runner, "chroot " + CHROOT + " readelf -n " + libc + " 2>/dev/null || true"));
        String id = match.find() ? match.group(1) : "";
        String hash = io.shell(runner, "chroot " + CHROOT + " sha256sum " + libc).strip().split("\\s+")[0];
        need(id.matches("[0-9a-f]+") && hash.matches("[0-9a-f]{64}"), "Missing libc build ID or SHA256");
        return JSON.createObjectNode().put("path_in_chroot", libc).put("sha256", hash).put("build_id", id).put("dpkg_version", io.shell(runner, "awk '/^Package: libc6$/{p=1} p&&/^Version:/{print $2; exit}' " + CHROOT + "/var/lib/dpkg/status").strip());
    }
    static String caseScript(String label, String name) {
        return "mkdir -p /tmp/regress-" + label + "; " + VG + " -q --leak-check=no --num-callers=12 --error-exitcode=97 --log-file=/tmp/regress-" + label + "/vg-" + name + ".log /build/fopen-regression " + name + " > /tmp/regress-" + label + "/out-" + name + ".json 2> /tmp/regress-" + label + "/err-" + name + "; echo $? > /tmp/regress-" + label + "/rc-" + name;
    }
    ObjectNode executeLeg(Target runner, String label, List<Path> debs, Path logs) throws Exception {
        byte[] probeSource = Files.readAllBytes(io.project.resolve("containers/native/fopen-regression.c"));
        Result upload = io.exec(runner, probeSource, "/bin/sh", "-c", "cat > " + CHROOT + "/build/fopen-regression.c"); need(upload.status() == 0, "Probe upload failed");
        io.shell(runner, "chroot " + CHROOT + " gcc -O2 -Wall -Wextra -o /build/fopen-regression /build/fopen-regression.c -ldl");
        io.shell(runner, "mkdir -p " + CHROOT + "/tmp/regress-" + label);
        Files.createDirectories(logs);
        ObjectNode cases = JSON.createObjectNode(); Set<String> reported = new TreeSet<>();
        for (String name : CASES) {
            Result executed = io.shellResult(runner, "chroot " + CHROOT + " /bin/sh -c " + quote(caseScript(label, name)));
            need(executed.status() == 0, "Regression invocation failed for " + name);
            Map<String, byte[]> saved = new LinkedHashMap<>();
            for (String file : List.of("rc-" + name, "out-" + name + ".json", "err-" + name, "vg-" + name + ".log")) {
                Result fetched = io.shellResult(runner, "cat " + CHROOT + "/tmp/regress-" + label + "/" + file);
                need(fetched.status() == 0, "Missing regression evidence: " + file);
                saved.put(file, fetched.stdout()); RegressionEvidence.write(logs.resolve(file), fetched.stdout());
            }
            int rc = Integer.parseInt(new String(saved.get("rc-" + name), StandardCharsets.UTF_8).strip());
            ObjectNode record = caseRecord(name, rc, new String(saved.get("out-" + name + ".json"), StandardCharsets.UTF_8).strip(), new String(saved.get("vg-" + name + ".log"), StandardCharsets.UTF_8));
            String buildId = record.path("probe").path("libc_build_id").asText(); if (!buildId.isEmpty()) reported.add(buildId);
            cases.set(name, record);
        }
        ObjectNode identity = identity(runner);
        if (!debs.isEmpty()) identity.set("debs", JSON.valueToTree(debs.stream().map(Path::toString).toList()));
        boolean allMatch = reported.size() == 1 && reported.contains(identity.path("build_id").asText());
        for (JsonNode record : cases) allMatch &= record.path("probe").path("libc_build_id").asText().equals(identity.path("build_id").asText());
        ObjectNode report = JSON.createObjectNode().put("label", label).put("description", label.equals("control") ? "Unchanged Ubuntu-installed libc 2.39-0ubuntu8.9 in the build chroot." : "Local backport installed over the control chroot.").put("probeSourceSha256", sha(probeSource)).put("build_id_match", allMatch);
        report.set("libc_under_test", identity); report.set("probe_build_ids_seen", JSON.valueToTree(reported)); report.set("cases", cases);
        report.put("scope", "Native chroot execution with /proc mounted by an owned privileged runner; valgrind uses chroot libc at its standard path. Invalid accesses gate the verdict; uninitialised-value reports are recorded but do not gate.");
        return report;
    }
    ObjectNode compare(Path evidence) throws Exception {
        Path controlPath = evidence.resolve("fopen-valgrind-control.json"), patchedPath = evidence.resolve("fopen-valgrind-patched.json");
        need(Files.isRegularFile(controlPath) && Files.isRegularFile(patchedPath), "Both legs must be recorded before comparing");
        JsonNode control = JSON.readTree(controlPath.toFile()), patched = JSON.readTree(patchedPath.toFile());
        Gate controlGate = gate("control", control), patchedGate = gate("patched", patched);
        ObjectNode verdict = JSON.createObjectNode().put("control_build_id", control.path("libc_under_test").path("build_id").asText()).put("patched_build_id", patched.path("libc_under_test").path("build_id").asText()).put("demonstrates_cve_memory_safety", controlGate.passed && patchedGate.passed);
        verdict.set("control", JSON.createObjectNode().put("gate_passed", controlGate.passed).set("reasons", JSON.valueToTree(controlGate.reasons)));
        verdict.set("patched", JSON.createObjectNode().put("gate_passed", patchedGate.passed).set("reasons", JSON.valueToTree(patchedGate.reasons)));
        writeJson(evidence.resolve("fopen-valgrind-verdict.json"), verdict, false); return verdict;
    }
    boolean execute(String label, List<Path> debs, boolean compare, Path evidence) throws Exception {
        need(List.of("control", "patched").contains(label), "Label must be control or patched");
        need(!label.equals("patched") || !debs.isEmpty(), "Patched leg needs --libc-deb with built libc6 and libc-bin backports");
        for (Path deb : debs) need(Files.isRegularFile(deb, LinkOption.NOFOLLOW_LINKS), "Missing or symbolic libc package: " + deb);
        evidence = RegressionEvidence.prepare(io.project, evidence);
        Files.deleteIfExists(evidence.resolve("fopen-valgrind-" + label + ".json")); Files.deleteIfExists(evidence.resolve("fopen-valgrind-verdict.json"));
        JsonNode builder = io.inspect(BUILDER); String builderId = builder.path("Id").asText();
        need(builderId.matches("[0-9a-f]{64}") && builder.path("Name").asText().equals("/" + BUILDER) && builder.path("State").path("Running").asBoolean(false), "Prepared builder identity or running state mismatch");
        need(Ownership.privateResources(builder, true, Set.of("", "private"), false), "Prepared builder has host, shared or unexpected resources");
        ObjectNode report;
        try (var runner = new OwnedRunner()) {
            runner.start();
            io.shell(runner.target, "mkdir -p /work");
            io.runner.pipeline(List.of("docker", "exec", builderId, "tar", "-cf", "-", "-C", "/work", "root"), List.of("docker", "exec", "-i", runner.id, "tar", "-xf", "-", "-C", "/work"));
            io.shell(runner.target, "mkdir -p " + CHROOT + "/usr/lib/debug " + CHROOT + "/proc");
            io.shell(runner.target, "dpkg-deb -x " + CHROOT + "/tmp/libc6-dbg.deb /work/dbg");
            io.shell(runner.target, "cp -a /work/dbg/usr/lib/debug/. " + CHROOT + "/usr/lib/debug/");
            io.shell(runner.target, "test -x " + CHROOT + "/tmp/tools/usr/bin/valgrind");
            io.shell(runner.target, "mountpoint -q " + CHROOT + "/proc || mount -t proc proc " + CHROOT + "/proc");
            for (int index = 0; index < debs.size(); index++) {
                byte[] bytes = Files.readAllBytes(debs.get(index));
                Result upload = io.exec(runner.target, bytes, "/bin/sh", "-c", "cat > " + CHROOT + "/tmp/libc-local-" + index + ".deb");
                need(upload.status() == 0, "Deb upload failed: " + debs.get(index));
                need(io.shell(runner.target, "sha256sum " + CHROOT + "/tmp/libc-local-" + index + ".deb").strip().split("\\s+")[0].equals(sha(bytes)), "Uploaded deb hash mismatch");
            }
            if (label.equals("patched")) {
                List<String> names = new ArrayList<>(); for (int i = 0; i < debs.size(); i++) names.add("/tmp/libc-local-" + i + ".deb");
                io.shell(runner.target, "chroot " + CHROOT + " dpkg --install --force-confnew " + String.join(" ", names) + " || chroot " + CHROOT + " dpkg --configure -a");
            }
            report = executeLeg(runner.target, label, debs, RegressionEvidence.logs(evidence, label));
            report.put("runnerContainerId", runner.id).put("runnerImageId", runner.image).put("runnerImage", RUNNER_IMAGE);
        }
        Gate gate = gate(label, report); ObjectNode gateNode = JSON.createObjectNode().put("passed", gate.passed); gateNode.set("reasons", JSON.valueToTree(gate.reasons)); report.set("gate", gateNode);
        Path out = evidence.resolve("fopen-valgrind-" + label + ".json"); writeJson(out, report, false);
        System.out.println(label + ": gate " + (gate.passed ? "passed" : "FAILED") + " (" + String.join(", ", gate.reasons) + ")\nreport: " + out);
        if (compare) return compare(evidence).path("demonstrates_cve_memory_safety").asBoolean() && gate.passed;
        return gate.passed;
    }
}
