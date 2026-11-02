/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;
import static app.zcat.stargate.libc.Fixtures.*;

class FopenRegressionTest {
    @TempDir Path root;
    static ObjectNode report(int writes) {
        ObjectNode report = JSON.createObjectNode().put("build_id_match", true), cases = JSON.createObjectNode();
        for (String name : FopenRegression.CASES) cases.set(name, JSON.createObjectNode().put("probe_semantics_ok", true).put("invalid_writes", name.equals("overflow") ? writes : 0).put("invalid_reads", 0)); report.set("cases", cases); return report;
    }
    @Test void controlMustShowInvalidWritesAndPatchedMustShowNoInvalidAccess() {
        assertFalse(FopenRegression.gate("control", report(0)).passed()); assertTrue(FopenRegression.gate("control", report(1)).passed()); assertFalse(FopenRegression.gate("patched", report(1)).passed()); assertTrue(FopenRegression.gate("patched", report(0)).passed());
        var reads = report(0); ((ObjectNode)reads.path("cases").path("overflow")).put("invalid_reads", 1); assertFalse(FopenRegression.gate("patched", reads).passed());
    }
    @Test void incompleteCaseSetBadSemanticsAndWrongBuildIdsNeverPass() {
        var missing = report(0); ((ObjectNode)missing.path("cases")).remove("ascii"); assertFalse(FopenRegression.gate("patched", missing).passed());
        var bad = report(0); ((ObjectNode)bad.path("cases").path("ascii")).put("probe_semantics_ok", false); assertFalse(FopenRegression.gate("patched", bad).passed());
        bad = report(0); bad.remove("build_id_match"); assertFalse(FopenRegression.gate("patched", bad).passed());
        bad = report(1); bad.put("build_id_match", false); assertFalse(FopenRegression.gate("control", bad).passed());
        bad = report(0); ((ObjectNode)bad.path("cases").path("ascii")).put("invalid_writes", new java.math.BigInteger("18446744073709551616")); assertFalse(FopenRegression.gate("patched", bad).passed());
    }
    @Test void actualProbeParsingRequiresCaseTrueBooleanAndExpectedExitStatus() {
        String probe = "{\"case\":\"overflow\",\"passed\":true,\"libc_build_id\":\"abc\"}";
        assertTrue(FopenRegression.caseRecord("overflow", 97, probe, "==123== Invalid write of size 1\n==123== Invalid read of size 1\n").path("probe_semantics_ok").asBoolean());
        for (String bad : List.of(probe + " {}", probe.replace("true", "\"true\""), probe.replace("overflow", "other"), "")) assertFalse(FopenRegression.caseRecord("overflow", 0, bad, "").path("probe_semantics_ok").asBoolean());
        assertFalse(FopenRegression.caseRecord("overflow", 127, probe, "").path("probe_semantics_ok").asBoolean());
        var record = FopenRegression.caseRecord("overflow", 97, probe, "==123== Invalid write\n==123== Invalid read\n==123== Conditional jump\nERROR SUMMARY: 1 errors\nERROR SUMMARY: 2 errors\n"); assertEquals(1, record.path("invalid_writes").asInt()); assertEquals(1, record.path("invalid_reads").asInt()); assertEquals(1, record.path("uninitialised_reports").asInt()); assertEquals(2, record.path("error_summary").asInt());
    }
    @Test void valgrindCommandKeepsExactOptionsAndAllCases() {
        assertEquals(12, FopenRegression.CASES.size());
        for (String name : FopenRegression.CASES) {
            String command = FopenRegression.caseScript("patched", name);
            assertTrue(command.contains("TMPDIR=/tmp VALGRIND_LIB=/tmp/tools/usr/libexec/valgrind /tmp/tools/usr/bin/valgrind -q --leak-check=no --num-callers=12 --error-exitcode=97")); assertTrue(command.contains("/build/fopen-regression " + name)); assertTrue(command.endsWith("echo $? > /tmp/regress-patched/rc-" + name));
        }
    }
    @Test void malformedOrSharedPrivilegedRunnerFailsOwnershipGate() throws Exception {
        var data = base().put("Id", HELPER_ID).put("Name", "/owned").put("Image", IMAGE);
        ObjectNode config = (ObjectNode)data.path("Config"), host = (ObjectNode)data.path("HostConfig");
        ((ObjectNode)config.path("Labels")).put(Ownership.RUNNER_LABEL, MARKER); config.put("User", "0:0").set("Entrypoint", JSON.valueToTree(List.of("/bin/sleep"))); config.set("Cmd", JSON.valueToTree(List.of("infinity"))); host.put("Privileged", true).put("NetworkMode", "none");
        FopenRegression.validateRunner(data, HELPER_ID, "owned", IMAGE, MARKER);
        host.set("Binds", JSON.valueToTree(List.of("/host:/work"))); assertThrows(Exception.class, () -> FopenRegression.validateRunner(data, HELPER_ID, "owned", IMAGE, MARKER));
        host.remove("Binds"); host.put("PidMode", "host"); assertThrows(Exception.class, () -> FopenRegression.validateRunner(data, HELPER_ID, "owned", IMAGE, MARKER));
    }
    @Test void invalidLabelsAndMissingPatchedPackagesRunNoDocker() throws Exception {
        Runner forbidden = (c, i, t) -> { fail("No Docker permitted"); return null; };
        FopenRegression regression = new FopenRegression(new LibcIO(root, forbidden));
        assertThrows(Exception.class, () -> regression.execute("wrong", List.of(), false, root.resolve("proof"))); assertThrows(Exception.class, () -> regression.execute("patched", List.of(), false, root.resolve("proof"))); assertThrows(Exception.class, () -> regression.execute("patched", List.of(root.resolve("missing.deb")), false, root.resolve("proof")));
        assertFalse(Files.exists(root.resolve("proof")));
    }
    @Test void comparePublishesFailureForUncalibratedControlWithoutAnyDocker() throws Exception {
        Path evidence = Files.createDirectory(root.resolve("proof"));
        var control = report(0); control.set("libc_under_test", JSON.createObjectNode().put("build_id", "control"));
        var patched = report(0); patched.set("libc_under_test", JSON.createObjectNode().put("build_id", "patched"));
        writeJson(evidence.resolve("fopen-valgrind-control.json"), control, false); writeJson(evidence.resolve("fopen-valgrind-patched.json"), patched, false);
        var verdict = new FopenRegression(new LibcIO(root, null)).compare(evidence); assertFalse(verdict.path("demonstrates_cve_memory_safety").asBoolean()); assertFalse(verdict.path("control").path("gate_passed").asBoolean());
    }
    @Test void evidenceBoundaryRejectsSourceUnrelatedDirectoriesAndLinks() throws Exception {
        Path project = Files.createDirectory(root.resolve("project")), docs = Files.createDirectory(project.resolve("docs")); Files.writeString(docs.resolve("sentinel"), "unchanged");
        assertThrows(Exception.class, () -> RegressionEvidence.prepare(project, docs));
        Path unrelated = Files.createDirectory(root.resolve("unrelated")); Files.writeString(unrelated.resolve("sentinel"), "unchanged"); assertThrows(Exception.class, () -> RegressionEvidence.prepare(project, unrelated));
        Path evidence = RegressionEvidence.prepare(project, project.resolve("target/proof")); assertEquals(evidence, RegressionEvidence.prepare(project, evidence));
        Path alias = root.resolve("alias"); Files.createSymbolicLink(alias, evidence); assertThrows(Exception.class, () -> RegressionEvidence.prepare(project, alias));
        Files.createSymbolicLink(evidence.resolve("valgrind-logs-patched"), docs); assertThrows(Exception.class, () -> RegressionEvidence.logs(evidence, "patched"));
        Path link = evidence.resolve("out"); Files.createSymbolicLink(link, docs.resolve("sentinel")); assertThrows(Exception.class, () -> RegressionEvidence.write(link, new byte[]{1})); assertEquals("unchanged", Files.readString(docs.resolve("sentinel")));
    }
}
