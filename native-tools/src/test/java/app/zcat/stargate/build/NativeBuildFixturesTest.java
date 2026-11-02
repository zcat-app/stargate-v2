/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.build;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/** Opt-in read-only checks of existing native build outputs; never rebuilds native code. */
@EnabledIfSystemProperty(named = "native.build.fixture.root", matches = ".+")
class NativeBuildFixturesTest {
    @TempDir Path temporary;
    final Path fixtures = Path.of(System.getProperty("native.build.fixture.root", ".")).toAbsolutePath();
    final Path project = Path.of("..").toAbsolutePath().normalize();

    @Test void existingI2pArtifactSourcesMatchPinnedReconstructionAndRecordedBinaryHashes() throws Exception {
        Path work = fixtures.resolve("target/i2p-isolation-build");
        assertEquals(NativeBuild.I2P_ARCHIVE_SHA, NativeBuild.sha(work.resolve("source.tar.gz")));
        NativeBuild.Processes runner = new NativeBuild.Processes();
        checked(runner, temporary, List.of("tar", "-xzf", work.resolve("source.tar.gz").toString(), "--no-same-owner", "--no-same-permissions", "-C", temporary.toString()));
        Path expected = temporary.resolve("i2pd-" + NativeBuild.I2P_COMMIT);
        for (String patch : List.of("identity-fail-closed.patch", "lifecycle-ack.patch")) {
            checked(runner, expected, List.of("patch", "-p1", "--batch", "--input", project.resolve("containers/i2p/" + patch).toString()));
        }
        NativeBuild.compareTree(expected, work.resolve(expected.getFileName()));
        var record = NativeBuild.JSON.readTree(work.resolve("build-record.json").toFile());
        assertEquals(NativeBuild.I2P_COMMIT, record.path("sourceCommit").asText());
        assertEquals(NativeBuild.I2P_ARCHIVE_SHA, record.path("sourceArchiveSha256").asText());
        assertEquals(record.path("patchSha256").asText(), NativeBuild.sha(project.resolve("containers/i2p/identity-fail-closed.patch")));
        assertEquals(record.path("lifecyclePatchSha256").asText(), NativeBuild.sha(project.resolve("containers/i2p/lifecycle-ack.patch")));
        assertEquals(record.path("ownerSourceSha256").asText(), NativeBuild.sha(project.resolve("containers/i2p/owner.c")));
        assertEquals(record.path("builderDockerfileSha256").asText(), NativeBuild.sha(project.resolve("containers/i2p/Dockerfile.builder")));
        assertEquals(record.path("binarySha256").asText(), NativeBuild.sha(work.resolve(expected.getFileName()).resolve("i2pd")));
        assertEquals(record.path("ownerBinarySha256").asText(), NativeBuild.sha(work.resolve("stargate-i2p-owner")));
    }

    @Test void existingNymSourcesVerifierAndActualRegressionLogsPassUnchangedGates() throws Exception {
        Path work = fixtures.resolve("target/nym-shared/build");
        Path source = work.resolve("source");
        var lifecycle = NativeBuild.JSON.readTree(project.resolve("containers/nym/lifecycle-build.json").toFile());
        var shared = NativeBuild.JSON.readTree(project.resolve("containers/nym/shared-client-build.json").toFile());
        var security = NativeBuild.JSON.readTree(project.resolve("containers/nym/security-build.json").toFile());
        assertTrue(NativeBuild.sourceHashesMatch(source, lifecycle.path("sourceSha256")));
        assertTrue(NativeBuild.sourceHashesMatch(source, shared.path("sourceSha256")));
        assertEquals(security.path("cargoLockSha256").asText(), NativeBuild.sha(source.resolve("Cargo.lock")));
        Path verifier = NativeBuild.findVerifier(work.resolve("cache"));
        NativeBuild.compareTree(verifier.resolve("src"), work.resolve("webpki-tests/src"));
        NativeBuild.requireTests(Files.readString(work.resolve("shared-client-tests.log")), NativeBuild.SHARED_TESTS, "missing shared regression");
        NativeBuild.requireTests(Files.readString(work.resolve("tls-regression.log")), List.of("verify_cert::tests::distrusted_spki"), "missing TLS regression");
        var record = NativeBuild.JSON.readTree(work.resolve("build-record.json").toFile());
        assertEquals(security.path("sourceCommit"), record.path("sourceCommit"));
        assertEquals(security.path("builderBase"), record.path("builderBase"));
        assertEquals(security.path("verifierTestCommit"), record.path("verifierTestCommit"));
        assertEquals(lifecycle.path("sourceSha256"), record.path("lifecycleSourceSha256"));
        assertEquals(shared.path("sourceSha256"), record.path("sharedClientSourceSha256"));
        assertEquals(security.path("patchSha256").asText(), NativeBuild.sha(project.resolve("containers/nym/security-dependencies.patch")));
        assertEquals(lifecycle.path("patchSha256").asText(), NativeBuild.sha(project.resolve("containers/nym/lifecycle.patch")));
        assertEquals(shared.path("patchSha256").asText(), NativeBuild.sha(project.resolve("containers/nym/shared-client.patch")));
        assertEquals(record.path("binarySha256").asText(), NativeBuild.sha(source.resolve("target/release/nym-socks5-client")));
        assertFalse(NativeBuild.contains(source.resolve("target/release/nym-socks5-client"), "emSign ECC Root CA - G3".getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private static void checked(NativeBuild.Processes runner, Path cwd, List<String> command) throws Exception {
        var result = runner.run(cwd, command, true);
        assertEquals(0, result.status(), result.output());
    }
}
