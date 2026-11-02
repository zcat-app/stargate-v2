/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import static app.zcat.stargate.libc.LibcIO.*;

/** Reads retained native evidence only. It never invokes Docker or a native compiler. */
@EnabledIfSystemProperty(named = "libc.build.fixture.root", matches = ".+")
class SavedArtifactsTest {
    final Path fixtures = Path.of(System.getProperty("libc.build.fixture.root", ".")).toAbsolutePath();
    final Path project = Path.of("..").toAbsolutePath().normalize();
    @Test void retainedPackageBytesStillMatchAllThreePublishedLocalHashes() throws Exception {
        Path nativeDir = fixtures.resolve("target/native");
        JsonNode hashes = JSON.readTree(nativeDir.resolve("build-hashes.json").toFile()), inputs = JSON.readTree(project.resolve("containers/native/glibc-inputs.json").toFile());
        assertEquals(inputs.path("local_version"), hashes.path("local_version")); assertEquals(3, hashes.path("debs").size());
        for (var entry : hashes.path("debs").properties()) assertEquals(entry.getValue().asText(), sha(nativeDir.resolve(entry.getKey())));
        assertEquals(inputs.path("patches").get(0).path("sha256").asText(), sha(project.resolve("containers/native/patches/glibc-CVE-2026-18374.patch")));
    }
    @Test void actualSavedProbeOutputsAndMemcheckLogsReproduceBothGates() throws Exception {
        Path evidence = fixtures.resolve("scratch/research/container-minimal");
        for (String label : List.of("control", "patched")) {
            JsonNode report = JSON.readTree(evidence.resolve("fopen-valgrind-" + label + ".json").toFile());
            Path logs = evidence.resolve("valgrind-logs-" + label).resolve("regress-" + label);
            for (String name : FopenRegression.CASES) {
                int rc = Integer.parseInt(Files.readString(logs.resolve("rc-" + name)).strip());
                JsonNode rebuilt = FopenRegression.caseRecord(name, rc, Files.readString(logs.resolve("out-" + name + ".json")).strip(), Files.readString(logs.resolve("vg-" + name + ".log")));
                for (String field : List.of("probe", "probe_semantics_ok", "invalid_writes", "invalid_reads", "uninitialised_reports", "error_summary")) assertEquals(report.path("cases").path(name).path(field), rebuilt.path(field), label + "/" + name + "/" + field);
                assertEquals(report.path("libc_under_test").path("build_id").asText(), rebuilt.path("probe").path("libc_build_id").asText());
            }
            assertTrue(FopenRegression.gate(label, report).passed(), label);
        }
    }
    @Test void savedFreshBuildSuiteSummariesMatchRetainedResultBindings() throws Exception {
        Path proof = fixtures.resolve("scratch/research/build/libc-fresh-builder-final");
        JsonNode result = JSON.readTree(proof.resolve("result.json").toFile());
        assertEquals(0, result.path("tool_returncode").asInt(-1)); assertEquals("success", result.path("status").asText());
        for (var entry : Map.of("glibc-2.39/build-tree/amd64-libc/tests.sum", "glibc-2.39_build-tree_amd64-libc_tests.sum", "glibc-2.39/build-tree/amd64-i386/tests.sum", "glibc-2.39_build-tree_amd64-i386_tests.sum").entrySet()) {
            assertEquals(result.path("copied").path(entry.getKey()).path("sha256").asText(), sha(proof.resolve(entry.getValue())));
        }
        for (String name : List.of("glibc-2.39_build-tree_amd64-libc_tests.sum", "glibc-2.39_build-tree_amd64-i386_tests.sum")) {
            String summary = Files.readString(proof.resolve(name)); assertFalse(summary.lines().anyMatch(line -> line.startsWith("FAIL:"))); assertTrue(summary.contains("PASS:"));
        }
    }
}
