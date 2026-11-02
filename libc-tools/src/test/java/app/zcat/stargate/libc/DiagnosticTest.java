/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;

class DiagnosticTest {
    @TempDir Path root;
    @BeforeEach void setup() throws Exception { Fixtures.manifest(root); }
    boolean has(List<Diagnostic.Check> checks, String name, String state, String detail) { return checks.contains(new Diagnostic.Check(name, state, detail)); }
    @Test void missingCliNeverCallsDockerAndBuilderRemainsUnknown() {
        var checks = new Diagnostic(new LibcIO(root, (c, i, t) -> { fail("Docker unavailable"); return null; }), () -> false).check();
        assertTrue(has(checks, "Docker CLI", "missing", "not found in PATH")); assertTrue(has(checks, "builder", "unknown", "Docker CLI unavailable"));
    }
    @Test void absenceRequiresSuccessfulListingAndFailureStaysUnknown() {
        var absent = new Diagnostic(new LibcIO(root, (c, i, t) -> Result.text(0, "")), () -> true).check();
        assertTrue(has(absent, "builder", "missing", "container not listed"));
        var failed = new Diagnostic(new LibcIO(root, (c, i, t) -> Result.text(1, "")), () -> true).check();
        assertTrue(has(failed, "builder", "unknown", "Docker container listing failed"));
    }
    @Test void stoppedBuilderNeverRunsProbe() {
        List<List<String>> calls = new ArrayList<>();
        var checks = new Diagnostic(new LibcIO(root, (c, i, t) -> { calls.add(c); return Result.text(0, BUILDER + "\texited\n"); }), () -> true).check();
        assertEquals(1, calls.size()); assertTrue(has(checks, "build prerequisites", "unknown", "container is not running"));
    }
    @Test void pathsFollowManifestAndInaccessiblePathsAreUnknown() {
        List<List<String>> calls = new ArrayList<>();
        var checks = new Diagnostic(new LibcIO(root, (c, i, t) -> { calls.add(c); assertEquals(java.time.Duration.ofSeconds(15), t); return Result.text(0, c.get(1).equals("container") ? BUILDER + "\trunning\n" : "present\nunknown\npresent\n"); }), () -> true).check();
        assertTrue(has(checks, CHROOT + SRC, "unknown", "path absent or inaccessible")); assertTrue(calls.getLast().getLast().contains(CHROOT + SRC + "/../source.dsc"));
    }
    @Test void malformedListingAndFailedProbeAreUnknown() {
        var malformed = new Diagnostic(new LibcIO(root, (c, i, t) -> Result.text(0, "malformed\n")), () -> true).check();
        assertTrue(has(malformed, "builder", "unknown", "unexpected Docker listing format"));
        var failedProbe = new Diagnostic(new LibcIO(root, (c, i, t) -> c.get(1).equals("container") ? Result.text(0, BUILDER + "\trunning\n") : Result.text(1, "")), () -> true).check();
        assertTrue(has(failedProbe, "build prerequisites", "unknown", "container path probe failed"));
    }
    @Test void invalidSourceNameBlocksProbeAndTrailingJsonIsRejected() throws Exception {
        Path manifest = root.resolve("containers/native/glibc-inputs.json");
        var input = JSON.readTree(manifest.toFile()); ((com.fasterxml.jackson.databind.node.ObjectNode)input).set("source_files_sha256", JSON.createObjectNode().put("../bad;touch injected", "a".repeat(64))); writeJson(manifest, input, false);
        List<List<String>> calls = new ArrayList<>();
        var checks = new Diagnostic(new LibcIO(root, (c, i, t) -> { calls.add(c); return Result.text(0, BUILDER + "\trunning\n"); }), () -> true).check();
        assertEquals(1, calls.size()); assertTrue(has(checks, "build prerequisites", "unknown", "source manifest unavailable or unsupported"));
        Files.writeString(manifest, "{} {}"); assertThrows(Exception.class, () -> new LibcIO(root, null).inputs());
    }
    @Test void missingInputAndTimeoutHaveDifferentUnknownMeaning() throws Exception {
        Files.delete(root.resolve("containers/native/glibc-inputs.json"));
        var checks = new Diagnostic(new LibcIO(root, (c, i, t) -> { throw new java.io.IOException("timeout"); }), () -> true).check();
        assertTrue(checks.stream().anyMatch(c -> c.name().equals("local inputs") && c.state().equals("missing")));
        assertTrue(has(checks, "builder inspection", "unknown", "Docker command unavailable or timed out"));
    }
}
