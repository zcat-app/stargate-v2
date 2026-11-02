/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.build;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class NativeBuildTest {
    @TempDir Path temporary;

    @Test void i2pArchivePinIsUnchangedAndBadCacheFailsBeforeAnyCommands() throws Exception {
        assertEquals("137dde2f433b2142eec7a2307608d7d082be086f", NativeBuild.I2P_COMMIT);
        assertEquals("37c6e50c30841bed3d414ba9d6e910ee969596dd6f89723cefe7cfe764536cfb", NativeBuild.I2P_ARCHIVE_SHA);
        Path work = Files.createDirectories(temporary.resolve("target/i2p-isolation-build"));
        Files.writeString(work.resolve("source.tar.gz"), "tampered archive");
        Files.writeString(work.resolve("build-record.json"), "stale success");
        NativeBuild build = new NativeBuild(temporary, (cwd, command, capture) -> { fail("No command may run with a bad archive: " + command); return null; });
        assertTrue(assertThrows(IOException.class, build::i2p).getMessage().contains("Source checksum mismatch"));
        assertFalse(Files.exists(work.resolve("build-record.json")));
    }

    @Test void reconstructedI2pSourceRejectsEditsMissingFilesAndSymlinks() throws Exception {
        Path expected = Files.createDirectories(temporary.resolve("expected/sub"));
        Files.writeString(expected.resolve("source.cc"), "pinned source");
        Path actual = Files.createDirectories(temporary.resolve("actual/sub"));
        Files.writeString(actual.resolve("source.cc"), "pinned source");
        NativeBuild.compareTree(expected.getParent(), actual.getParent());
        Files.writeString(actual.resolve("source.cc"), "edited source");
        assertThrows(IOException.class, () -> NativeBuild.compareTree(expected.getParent(), actual.getParent()));
        Files.delete(actual.resolve("source.cc"));
        assertThrows(IOException.class, () -> NativeBuild.compareTree(expected.getParent(), actual.getParent()));
        Files.createSymbolicLink(actual.resolve("source.cc"), expected.resolve("source.cc"));
        assertThrows(IOException.class, () -> NativeBuild.compareTree(expected.getParent(), actual.getParent()));
    }

    @Test void declaredNymHashesRejectMissingModifiedAndEscapingInputs() throws Exception {
        Files.writeString(temporary.resolve("source.rs"), "pinned");
        var hashes = NativeBuild.JSON.createObjectNode().put("source.rs", NativeBuild.sha(temporary.resolve("source.rs")));
        assertTrue(NativeBuild.sourceHashesMatch(temporary, hashes));
        Files.writeString(temporary.resolve("source.rs"), "modified");
        assertFalse(NativeBuild.sourceHashesMatch(temporary, hashes));
        Files.delete(temporary.resolve("source.rs"));
        assertFalse(NativeBuild.sourceHashesMatch(temporary, hashes));
        hashes.put("../escape", "invalid");
        hashes.remove("source.rs");
        assertThrows(IOException.class, () -> NativeBuild.sourceHashesMatch(temporary, hashes));
    }

    @Test void exactArchiveDeclaredInternalLinksPassButSubstitutedLinksFail() throws Exception {
        Path expected = Files.createDirectories(temporary.resolve("expected"));
        Path actual = Files.createDirectories(temporary.resolve("actual"));
        for (Path root : List.of(expected, actual)) {
            Files.writeString(root.resolve("target"), "pinned source");
            Files.writeString(root.resolve("other"), "pinned source");
            Files.createSymbolicLink(root.resolve("link"), Path.of("target"));
        }
        NativeBuild.compareTree(expected, actual);
        Files.delete(actual.resolve("link"));
        Files.createSymbolicLink(actual.resolve("link"), Path.of("other"));
        assertThrows(IOException.class, () -> NativeBuild.compareTree(expected, actual));
        Files.delete(actual.resolve("link"));
        Files.writeString(actual.resolve("link"), "pinned source");
        NativeBuild.compareTree(expected, actual);
    }

    @Test void actualGitSourceAdmissionRejectsTrackedStagedAndUntrackedChanges() throws Exception {
        git("init", temporary.toString());
        git("-C", temporary.toString(), "config", "user.email", "build-test@example.invalid");
        git("-C", temporary.toString(), "config", "user.name", "Build fixture");
        Files.writeString(temporary.resolve("Cargo.lock"), "initial");
        Files.writeString(temporary.resolve("other.rs"), "initial");
        Files.writeString(temporary.resolve(" Cargo.lock"), "initial");
        git("-C", temporary.toString(), "add", ".");
        git("-C", temporary.toString(), "commit", "-m", "fixture");
        NativeBuild build = new NativeBuild(temporary, new NativeBuild.Processes());
        var empty = NativeBuild.JSON.createObjectNode();
        build.verifyChangedSources(temporary, empty, empty);
        Files.writeString(temporary.resolve("Cargo.lock"), "allowed patched lock");
        build.verifyChangedSources(temporary, empty, empty);
        Files.writeString(temporary.resolve("other.rs"), "unapproved");
        assertThrows(IOException.class, () -> build.verifyChangedSources(temporary, empty, empty));
        git("-C", temporary.toString(), "add", "other.rs");
        assertThrows(IOException.class, () -> build.verifyChangedSources(temporary, empty, empty));
        git("-C", temporary.toString(), "reset", "--hard", "HEAD");
        Files.writeString(temporary.resolve(" Cargo.lock"), "must not be confused with allowed Cargo.lock");
        assertThrows(IOException.class, () -> build.verifyChangedSources(temporary, empty, empty));
        git("-C", temporary.toString(), "reset", "--hard", "HEAD");
        Files.writeString(temporary.resolve("extra.rs"), "untracked");
        assertThrows(IOException.class, () -> build.verifyChangedSources(temporary, empty, empty));
    }

    @Test void sharedAndTlsGatesRejectZeroTestsIgnoredTestsPartialResultsAndPrintedNames() throws Exception {
        assertThrows(IOException.class, () -> NativeBuild.requireTests("test result: ok. 0 passed; 0 failed; 6 filtered out\n", NativeBuild.SHARED_TESTS, "missing"));
        String real = NativeBuild.SHARED_TESTS.stream().map(name -> "test shared_client_tests::" + name + " ... ok\n").reduce("", String::concat);
        NativeBuild.requireTests(real, NativeBuild.SHARED_TESTS, "missing");
        assertThrows(IOException.class, () -> NativeBuild.requireTests(real.replaceFirst(" \\.\\.\\. ok", " ... ignored"), NativeBuild.SHARED_TESTS, "missing"));
        assertThrows(IOException.class, () -> NativeBuild.requireTests(real.replace("test ", "echo "), NativeBuild.SHARED_TESTS, "missing"));
        assertThrows(IOException.class, () -> NativeBuild.requireTests(real.substring(real.indexOf('\n') + 1), NativeBuild.SHARED_TESTS, "missing"));
        List<String> tls = List.of("verify_cert::tests::distrusted_spki");
        assertThrows(IOException.class, () -> NativeBuild.requireTests("running 0 tests\n", tls, "missing"));
        assertThrows(IOException.class, () -> NativeBuild.requireTests("test unrelated::verify_cert::tests::distrusted_spki ... ok\n", tls, "missing"));
        NativeBuild.requireTests("test verify_cert::tests::distrusted_spki ... ok\n", tls, "missing");
    }

    @Test void originalI2pDockerCommandIsPreserved() {
        assertEquals(List.of("docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", "1000:1000", "-v", "/source:/source", "-v", "/inputs:/inputs:ro", "-v", "/work:/output", "stargate-v2-i2p-builder:local", "sh", "-ec", "make -j2 DEBUG=no USE_UPNP=yes; cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now /inputs/owner.c -o /output/stargate-i2p-owner"),
            NativeBuild.i2pCommand(Path.of("/source"), Path.of("/inputs"), Path.of("/work"), "1000:1000"));
    }

    @Test void originalNymDockerBuildAndRegressionCommandsArePreserved() {
        List<String> command = NativeBuild.nymCommand(Path.of("/source"), Path.of("/cache"), "1000:1000");
        assertEquals(List.of("docker", "run", "--rm", "--user", "1000:1000", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", "/source:/src", "-v", "/cache:/cargo-cache", "-e", "CARGO_HOME=/cargo-cache", "-w", "/src", "stargate-v2-nym-builder:local"), command);
        assertEquals(List.of("cargo", "test", "--locked", "--release", "-p", "nym-socks5-proxy-helpers", "-p", "nym-client-core", "--lib", "shared_client_tests", "-j", "4"), NativeBuild.sharedCommand(command, 4).subList(command.size(), NativeBuild.sharedCommand(command, 4).size()));
        List<String> verifier = NativeBuild.verifierCommand(command, Path.of("/tests"), 4);
        List<String> expected = new ArrayList<>(command.subList(0, command.size() - 1));
        expected.addAll(List.of("-v", "/tests:/verifier", "stargate-v2-nym-builder:local", "cargo", "test", "--manifest-path", "/verifier/Cargo.toml", "--target-dir", "/src/target", "--locked", "--release", "--features", "ring", "--lib", "distrusted_spki", "-j", "4"));
        assertEquals(expected, verifier);
    }

    @Test void nymPatchMismatchRejectsBeforeGitOrDockerAndRemovesStaleRecord() throws Exception {
        Path nym = Files.createDirectories(temporary.resolve("containers/nym"));
        Files.writeString(nym.resolve("security-build.json"), "{\"sourceCommit\":\"commit\",\"patchSha256\":\"bad\"}");
        Files.writeString(temporary.resolve("containers/nym-release.json"), "{}");
        Files.writeString(nym.resolve("lifecycle-build.json"), "{\"sourceCommit\":\"commit\",\"patchSha256\":\"bad\"}");
        Files.writeString(nym.resolve("shared-client-build.json"), "{\"sourceCommit\":\"commit\",\"patchSha256\":\"bad\"}");
        Files.writeString(nym.resolve("shared-client.patch"), "tampered");
        Path work = Files.createDirectories(temporary.resolve("work"));
        Files.writeString(work.resolve("build-record.json"), "stale success");
        NativeBuild build = new NativeBuild(temporary, (cwd, command, capture) -> { fail("No command permitted: " + command); return null; });
        assertTrue(assertThrows(IOException.class, () -> build.nym(work, 4)).getMessage().contains("Nym shared-client input mismatch"));
        assertFalse(Files.exists(work.resolve("build-record.json")));
    }

    @Test void appendedJsonOrJunkInManifestFailsBeforeAnyCommand() throws Exception {
        Path nym = Files.createDirectories(temporary.resolve("containers/nym"));
        Path work = Files.createDirectories(temporary.resolve("work"));
        NativeBuild build = new NativeBuild(temporary, (cwd, command, capture) -> { fail("No command permitted: " + command); return null; });
        for (String appended : List.of(" {\"extra\":true}", " junk")) {
            Files.writeString(nym.resolve("security-build.json"), "{\"sourceCommit\":\"commit\"}" + appended);
            Files.writeString(work.resolve("build-record.json"), "stale success");
            assertThrows(IOException.class, () -> build.nym(work, 4));
            assertFalse(Files.exists(work.resolve("build-record.json")));
        }
    }

    @Test void shippedVerifierAdmissionRejectsMissingOrAmbiguousCrates() throws Exception {
        Path registry = Files.createDirectories(temporary.resolve("registry/src"));
        assertThrows(IOException.class, () -> NativeBuild.findVerifier(temporary));
        Path crate = Files.createDirectories(registry.resolve("one/rustls-webpki-0.103.16"));
        assertEquals(crate, NativeBuild.findVerifier(temporary));
        Files.createDirectories(registry.resolve("two/rustls-webpki-0.103.16"));
        assertThrows(IOException.class, () -> NativeBuild.findVerifier(temporary));
    }

    @Test void distrustedRootBinaryGateReadsBinaryBytesIncludingBoundaryMatches() throws Exception {
        Path binary = temporary.resolve("binary");
        byte[] prefix = new byte[65530];
        Files.write(binary, prefix);
        Files.writeString(binary, "emSign ECC Root CA - G3", StandardOpenOption.APPEND);
        assertTrue(NativeBuild.contains(binary, "emSign ECC Root CA - G3".getBytes(StandardCharsets.UTF_8)));
        Files.write(binary, prefix);
        assertFalse(NativeBuild.contains(binary, "emSign ECC Root CA - G3".getBytes(StandardCharsets.UTF_8)));
    }

    @Test void nonzeroRegressionExitRejectsEvenWhenOutputContainsPassingTest() throws Exception {
        NativeBuild build = new NativeBuild(temporary, new NativeBuild.Processes());
        List<String> command = List.of("sh", "-c", "printf 'test verify_cert::tests::distrusted_spki ... ok\\n'; exit 7");
        assertThrows(IOException.class, () -> build.regression(temporary, "regression.log", command));
        assertTrue(Files.readString(temporary.resolve("regression.log")).contains("distrusted_spki ... ok"));
        assertFalse(Files.exists(temporary.resolve("build-record.json")));
    }

    private void git(String... args) throws Exception {
        List<String> command = new ArrayList<>(List.of("git")); command.addAll(List.of(args));
        var result = new NativeBuild.Processes().run(temporary, command, true);
        assertEquals(0, result.status(), result.output());
    }
}
