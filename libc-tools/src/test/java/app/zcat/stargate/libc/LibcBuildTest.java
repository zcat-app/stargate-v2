/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;
import static app.zcat.stargate.libc.Fixtures.*;

class LibcBuildTest {
    @TempDir Path root;
    @BeforeEach void setup() throws Exception { Fixtures.manifest(root); }
    @Test void partialFreshArgumentsNeverFallBackOrInspect() throws Exception {
        Runner forbidden = (c, i, t) -> { fail("No commands allowed"); return null; };
        for (String[] args : List.of(new String[]{"--project", root.toString(), "build", "--fresh-builder-id", BUILDER_ID}, new String[]{"--project", root.toString(), "build", "--fresh-builder-id", ""})) assertThrows(Exception.class, () -> LibcTools.execute(args, forbidden));
    }
    @Test void privateOutputRejectsAliasesExistingRelativeAndDotPaths() throws Exception {
        Path output = LibcIO.privateOutput(root.resolve("output")); assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(output)));
        assertThrows(Exception.class, () -> LibcIO.privateOutput(output)); assertThrows(Exception.class, () -> LibcIO.privateOutput(Path.of("relative"))); assertThrows(Exception.class, () -> LibcIO.privateOutput(root.resolve("../escape")));
        Files.createSymbolicLink(root.resolve("alias"), output); assertThrows(Exception.class, () -> LibcIO.privateOutput(root.resolve("alias/new")));
    }
    @Test void resourcesRejectedBeforeOutputOrSourceMutation() throws Exception {
        var harness = new Harness(); ((com.fasterxml.jackson.databind.node.ObjectNode)harness.builder.path("HostConfig")).set("Binds", JSON.valueToTree(List.of("/host:/work")));
        Path output = root.resolve("never-created");
        assertThrows(Exception.class, () -> new LibcBuild(new LibcIO(root, harness)).execute(new LibcBuild.Options(BUILDER_ID, IMAGE, MARKER, output)));
        assertFalse(Files.exists(output)); assertEquals(1, harness.calls.size());
    }
    @Test void dirtyFreshStateRejectsBeforeChangelogOrBuild() throws Exception {
        var harness = new Harness(); harness.preflight = "dirty";
        assertThrows(Exception.class, () -> new LibcBuild(new LibcIO(root, harness)).execute(new LibcBuild.Options(BUILDER_ID, IMAGE, MARKER, root.resolve("out"))));
        assertFalse(harness.calls.stream().anyMatch(c -> c.get(1).equals("create") || c.getLast().contains("changelog")));
    }
    @Test void sourceHashAndPatchMismatchRejectBeforeChangelog() throws Exception {
        var harness = new Harness();
        LibcIO io = new LibcIO(root, (c, i, t) -> c.getLast().startsWith("sha256sum") ? Result.text(0, "f".repeat(64)) : harness.run(c, i, t));
        assertThrows(Exception.class, () -> new LibcBuild(io).verifyInputs(new Target(BUILDER_ID, false)));
        Files.writeString(root.resolve("containers/native/patches/glibc-CVE-2026-18374.patch"), "tampered");
        assertThrows(Exception.class, () -> new LibcBuild(new LibcIO(root, harness)).verifyInputs(new Target(BUILDER_ID, false)));
        assertFalse(harness.calls.stream().anyMatch(c -> c.getLast().contains("changelog")));
    }
    @Test void missingPatchMarkerFailsClosedEvenForLegacyBuilder() throws Exception {
        var harness = new Harness();
        LibcIO io = new LibcIO(root, (c, i, t) -> c.getLast().startsWith("grep -c") ? Result.text(0, "") : harness.run(c, i, t));
        assertThrows(Exception.class, () -> new LibcBuild(io).verifyInputs(new Target(BUILDER_ID, false)));
    }
    @Test void failedDpkgStatusIsNotPromotedToSuccessAndCommandsKeepRealChecks() throws Exception {
        var harness = new Harness(); harness.finalRc = "1";
        var build = new LibcBuild(new LibcIO(root, harness));
        assertTrue(assertThrows(Exception.class, () -> build.build(new Target(BUILDER_ID, false), "2.39-test", IMAGE, true)).getMessage().contains("dpkg-buildpackage failed"));
        String commands = harness.calls.toString();
        assertTrue(commands.contains("apt-get update -qq")); assertTrue(commands.contains("apt-get install -y -qq " + String.join(" ", LibcBuild.DEPS))); assertTrue(commands.contains("dh_prep")); assertTrue(commands.contains("if test -d /work/root/build/glibc-2.39/stamp-dir; then find")); assertTrue(commands.contains("check_*")); assertTrue(commands.contains("dpkg-buildpackage --no-pre-clean -us -uc -b -j4")); assertTrue(commands.contains("pivot_root")); assertFalse(commands.contains("nocheck"));
    }
    @Test void invocationFailureCleansOwnedHelperAndDoesNotReadSuccessfulRc() throws Exception {
        var harness = new Harness(); harness.buildResult = 9;
        assertThrows(Exception.class, () -> new LibcBuild(new LibcIO(root, harness)).build(new Target(BUILDER_ID, false), "2.39-test", IMAGE, true));
        assertEquals(1, harness.rcReads); assertTrue(harness.calls.stream().anyMatch(c -> c.equals(List.of("docker", "rm", "--force", HELPER_ID))));
    }
    @Test void freshReuseForbiddenAndLegacyCompletedReuseRetained() throws Exception {
        var harness = new Harness(); harness.existing = "0";
        var build = new LibcBuild(new LibcIO(root, harness));
        assertThrows(Exception.class, () -> build.build(new Target(BUILDER_ID, false), "2.39-test", IMAGE, true));
        harness.rcReads = 0; build.build(new Target(BUILDER_ID, false), "2.39-test", IMAGE, false);
        assertFalse(harness.calls.stream().anyMatch(c -> c.get(1).equals("create")));
    }
    @Test void collectionIncludesExactlyRuntimeAndDebugPackagesWithoutOverwrite() throws Exception {
        var harness = new Harness(); Path output = LibcIO.privateOutput(root.resolve("out"));
        var build = new LibcBuild(new LibcIO(root, harness)); build.collect(new Target(BUILDER_ID, false), "2.39-test", output, true);
        var hashes = JSON.readTree(output.resolve("build-hashes.json").toFile()); assertEquals(3, hashes.path("debs").size()); assertTrue(hashes.path("debs").has("libc6-dbg_2.39-test_amd64.deb")); assertFalse(Files.exists(root.resolve("target")));
        byte[] original = Files.readAllBytes(output.resolve("libc6_2.39-test_amd64.deb"));
        assertThrows(Exception.class, () -> build.collect(new Target(BUILDER_ID, false), "2.39-test", output, true)); assertArrayEquals(original, Files.readAllBytes(output.resolve("libc6_2.39-test_amd64.deb")));
    }
    @Test void failedTransferPublishesNeitherPartialPackageNorHashRecord() throws Exception {
        var harness = new Harness(); harness.packageStatus = 1; Path output = LibcIO.privateOutput(root.resolve("out"));
        assertThrows(Exception.class, () -> new LibcBuild(new LibcIO(root, harness)).collect(new Target(BUILDER_ID, false), "2.39-test", output, true));
        try (var files = Files.list(output)) { assertEquals(0, files.count()); }
    }
    @Test void defaultCollectionRejectsOutputAliasesAndLinkedPackageFiles() throws Exception {
        var harness = new Harness(); Path real = Files.createDirectory(root.resolve("real")), alias = root.resolve("alias"); Files.createSymbolicLink(alias, real);
        var build = new LibcBuild(new LibcIO(root, harness));
        assertThrows(Exception.class, () -> build.collect(new Target(BUILDER_ID, false), "2.39-test", alias, false));
        Path outside = root.resolve("outside"); Files.writeString(outside, "unchanged"); Files.createSymbolicLink(real.resolve("libc6_2.39-test_amd64.deb"), outside);
        assertThrows(Exception.class, () -> build.collect(new Target(BUILDER_ID, false), "2.39-test", real, false)); assertEquals("unchanged", Files.readString(outside));
    }
}
