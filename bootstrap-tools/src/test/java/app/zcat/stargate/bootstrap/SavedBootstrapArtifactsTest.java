/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.api.io.TempDir;

/** Reread retained artifacts; never run Docker, APT, libc compilation, or native regressions. */
@EnabledIfSystemProperty(named = "bootstrap.fixture.plan", matches = ".+")
class SavedBootstrapArtifactsTest {
  @TempDir Path root;
  final Path planPath = Path.of(System.getProperty("bootstrap.fixture.plan", "."));

  @Test
  @EnabledIfSystemProperty(named = "bootstrap.full.source.proof", matches = "true")
  void cachedPinnedSourcesPrepareIntoExactAcceptedInventory() throws Exception {
    JsonNode retained = json(planPath).path("inputs");
    Path originals = Path.of(retained.path("source_workspace").asText());
    Path evidence = Path.of("target/bootstrap-verification").toAbsolutePath();
    if (!Files.exists(evidence, LinkOption.NOFOLLOW_LINKS)) privateDirectory(evidence);
    Path parent = temporary(evidence, "full-source-");
    SourcePreparer preparer =
        new SourcePreparer(
            Path.of("..").toAbsolutePath().normalize(),
            new Transport.Processes(),
            (name, output) ->
                bytes(output, read(originals.resolve(name), true, SourcePreparer.MAX_DOWNLOAD)));
    Path workspace = preparer.prepare(parent);
    ObjectNode verified =
        SeedContract.verifyInputs(workspace, Path.of(retained.path("ca_bundle").asText()));
    assertEquals(SeedContract.INVENTORY_SHA, verified.path("source_inventory_sha256").asText());
    assertEquals(retained.path("source_entry_count"), verified.path("source_entry_count"));
    save(
        parent.resolve("full-source-proof.json"),
        SeedExecutor.object(
            "status",
            "PASS",
            "source_workspace",
            workspace.toString(),
            "verification",
            verified,
            "network_downloads",
            false,
            "docker_operations",
            false,
            "native_compilation",
            false));
    System.out.println(
        "Full cached-source preparation proof: " + parent.resolve("full-source-proof.json"));
  }

  @Test
  void generatedPlanMatchesEverySavedCommandArgumentAndGate() throws Exception {
    ObjectNode saved = (ObjectNode) json(planPath);
    String quota = saved.path("layer_quota").isNull() ? null : saved.path("layer_quota").asText();
    assertEquals(
        saved,
        SeedContract.plan(
            (ObjectNode) saved.path("inputs"),
            saved.path("marker").asText(),
            planPath.getParent(),
            quota));
  }

  @Test
  void completeRetainedSourceWorkspacePassesAllProductionInputChecks() throws Exception {
    JsonNode saved = json(planPath).path("inputs");
    assertEquals(
        saved,
        SeedContract.verifyInputs(
            Path.of(saved.path("source_workspace").asText()),
            Path.of(saved.path("ca_bundle").asText())));
  }

  @Test
  void bothRetainedCopybackTarFilesMatchCompletePinnedInventory() throws Exception {
    for (String name : List.of("source-before.tar", "source-after.tar")) {
      ObjectNode inventory = Inventories.tar(planPath.getParent().resolve(name));
      assertEquals(SeedContract.INVENTORY_SHA, canonicalSha(inventory), name);
      assertEquals(
          json(planPath).path("inputs").path("source_entry_count").asInt(), inventory.size());
    }
  }

  @Test
  void retainedReleaseSignerAndPinnedDebReproduceExactCaBundle() throws Exception {
    Path workspace = Path.of(json(planPath).path("inputs").path("ca_bundle").asText()).getParent();
    byte[] release = read(workspace.resolve("InRelease"), true, 128L * 1024 * 1024);
    assertEquals(CaSeed.RELEASE_SHA, sha(release));
    assertEquals(CaSeed.DEB_SHA, sha(workspace.resolve("ca-certificates.deb")));
    assertEquals(CaSeed.KEYRING_SHA, sha(CaSeed.KEYRING));
    Path signed = root.resolve("InRelease");
    bytes(signed, release);
    Transport real = new Transport.Processes();
    Path sig = root.resolve("signature.out");
    int status =
        real.run(
            new Transport.Request(
                List.of(
                    "/usr/bin/gpgv",
                    "--homedir",
                    root.toString(),
                    "--status-fd",
                    "1",
                    "--keyring",
                    CaSeed.KEYRING.toString(),
                    signed.toString()),
                root,
                sig,
                root.resolve("signature.err"),
                null,
                180,
                16L * 1024 * 1024,
                32L * 1024 * 1024,
                TOOL_ENV,
                0077,
                false));
    CaSeed.signature(status, Files.readString(sig));
    Path archive = root.resolve("ca.tar");
    assertEquals(
        0,
        real.run(
            new Transport.Request(
                List.of(
                    "/usr/bin/dpkg-deb",
                    "--fsys-tarfile",
                    workspace.resolve("ca-certificates.deb").toString()),
                root,
                archive,
                root.resolve("unpack.err"),
                null,
                180,
                128L * 1024 * 1024,
                144L * 1024 * 1024,
                TOOL_ENV,
                0077,
                false)));
    byte[] bundle = CaSeed.bundle(archive);
    assertEquals(SeedContract.CA_SHA, sha(bundle));
    assertArrayEquals(read(workspace.resolve("bootstrap-ca.pem"), true, 16L * 1024 * 1024), bundle);
  }
}
