/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedExecutor.object;
import static app.zcat.stargate.bootstrap.SeedFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SeedExecutorTest {
  @TempDir Path root;
  int sequence;

  record Outcome(ObjectNode result, FakeDocker fake, Path output) {}

  Outcome run(String failure, String quota, boolean changed, boolean poison) throws Exception {
    Path output = privateDirectory(root.resolve("run-" + (++sequence))),
        docker = root.resolve("docker");
    if (!Files.exists(docker)) bytes(docker, "synthetic client, never executed".getBytes());
    ObjectNode definition = SeedContract.plan(inputs(), MARKER, output, quota);
    save(output.resolve("plan.json"), definition);
    SeedExecutor.claim(output.resolve("plan.json"));
    FakeDocker fake = new FakeDocker(failure);
    AtomicInteger observations = new AtomicInteger(), countAtPoison = new AtomicInteger(-1);
    try (var journal =
        new SeedExecutor.Journal(output) {
          @Override
          void record(String event, ObjectNode data) throws Exception {
            if (poison
                && event.equals("command_intent")
                && data.path("stage").asText().equals("apt-update-seed")) {
              poisoned = true;
              countAtPoison.set(fake.calls.size());
              throw new java.io.IOException("journal failure");
            }
            super.record(event, data);
          }
        }) {
      SeedContract.Inputs verifier =
          (s, c) ->
              changed && observations.incrementAndGet() >= 3
                  ? object("source_workspace", "/changed")
                  : inputs();
      var executor =
          new ProofExecutor(
              definition, output, docker, sha(docker), DAEMON, journal, fake, verifier);
      ObjectNode result = executor.run();
      save(output.resolve("result.json"), result);
      if (poison) assertEquals(countAtPoison.get(), fake.calls.size());
      return new Outcome(result, fake, output);
    }
  }

  @Test
  void successRunsAllStagesRetainsOnlyOwnedSeedAndCannotBeReclaimed() throws Exception {
    var out = run(null, null, false, false);
    assertEquals(
        "dependency-ready", out.result.path("status").asText(), out.result.toPrettyString());
    assertEquals(CID, out.result.path("container_id").asText());
    assertEquals("running", out.fake.seedState);
    assertEquals(3, out.result.path("disk_observations").size());
    assertEquals(
        1234, out.result.path("disk_observations").get(2).path("seed_writable_bytes").asInt());
    assertFalse(
        out.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())));
    assertThrows(Exception.class, () -> SeedExecutor.claim(out.output.resolve("plan.json")));
  }

  @Test
  void everyCopyOrExecHasImmediateDaemonAndOwnedIdentityChecks() throws Exception {
    var out = run(null, null, false, false);
    for (int i = 0; i < out.fake.calls.size(); i++) {
      var call = out.fake.calls.get(i);
      if (List.of("cp", "exec").contains(call.getFirst())) {
        assertTrue(i >= 2);
        assertEquals("info", out.fake.calls.get(i - 2).getFirst());
        assertEquals(
            List.of("inspect", "--type", "container"), out.fake.calls.get(i - 1).subList(0, 3));
        assertEquals(CID, out.fake.calls.get(i - 1).getLast());
      }
    }
  }

  @Test
  void completedApt100FailureRemovesOnlyReverifiedOwnedId() throws Exception {
    var out = run("normal-failure", null, false, false);
    assertEquals("failed", out.result.path("status").asText());
    assertEquals(
        "removed-and-absence-confirmed",
        out.result.path("cleanup").asText(),
        out.result.toPrettyString());
    assertTrue(out.fake.calls.contains(List.of("stop", "--timeout", "15", CID)));
    assertTrue(out.fake.calls.contains(List.of("rm", CID)));
    assertEquals("absent", out.fake.seedState);
  }

  @Test
  void stopDiagnosticNeverAcknowledgesRemoval() throws Exception {
    var out = run("stop-warning", null, false, false);
    assertEquals("failed-or-ambiguous-retained-for-review", out.result.path("cleanup").asText());
    assertFalse(out.fake.calls.contains(List.of("rm", CID)));
    assertEquals("exited", out.fake.seedState);
  }

  @Test
  void ambiguousCreateTimeoutIdentityDaemonAndCleanupChangesRetainResources() throws Exception {
    for (String failure :
        List.of(
            "ambiguous-create",
            "ambiguous-failure",
            "build-dep",
            "identity-mismatch",
            "daemon-changed",
            "cleanup-mismatch",
            "bad-disk-path")) {
      var out = run(failure, null, false, false);
      assertEquals("failed", out.result.path("status").asText(), failure);
      assertTrue(
          out.result.path("cleanup").asText().contains("review"), out.result.toPrettyString());
      assertFalse(
          out.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())),
          failure);
    }
  }

  @Test
  void sourceChangeOrBadCopiedTreeCannotPublishReadiness() throws Exception {
    for (boolean changed : List.of(false, true)) {
      var out = run(changed ? null : "bad-copyback", null, changed, false);
      assertEquals("failed", out.result.path("status").asText());
      assertEquals(
          "removed-and-absence-confirmed",
          out.result.path("cleanup").asText(),
          out.result.toPrettyString());
    }
  }

  @Test
  void unsupportedQuotaFailsOnceWithoutFallbackAndSuccessNeverClaimsEnforcement() throws Exception {
    var failed = run("unsupported-storage", "8G", false, false);
    assertEquals("failed", failed.result.path("status").asText());
    assertEquals("requested-not-verified", failed.result.path("hard_layer_quota").asText());
    assertEquals(1, failed.fake.calls.stream().filter(c -> c.getFirst().equals("create")).count());
    assertFalse(
        failed.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())));
    var success = run(null, "8G", false, false);
    assertEquals(
        "dependency-ready",
        success.result.path("status").asText(),
        success.result.toPrettyString());
    assertEquals(
        "configured-enforcement-not-independently-verified",
        success.result.path("hard_layer_quota").asText());
  }

  @Test
  void missingWritableSizeIsExplicitlyUnknownAndJournalFailureProhibitsFurtherDocker()
      throws Exception {
    var unknown = run("size-unavailable", null, false, false);
    assertEquals("dependency-ready", unknown.result.path("status").asText());
    assertTrue(
        unknown.result.path("disk_observations").get(2).path("seed_writable_bytes").isNull());
    assertEquals(
        "unavailable",
        unknown.result.path("disk_observations").get(2).path("seed_size_status").asText());
    var poisoned = run(null, null, false, true);
    assertEquals("failed", poisoned.result.path("status").asText());
    assertFalse(
        poisoned.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())));
  }

  @Test
  void exclusiveDaemonAcknowledgementAndTamperedOrNonfreshPlansFailBeforeDocker() throws Exception {
    Transport forbidden =
        r -> {
          fail("No Docker");
          return 0;
        };
    assertThrows(
        Exception.class,
        () ->
            BootstrapTools.execute(
                new String[] {
                  "--project",
                  root.toString(),
                  "seed",
                  "execute",
                  "--plan",
                  "/missing/plan.json",
                  "--docker-cli",
                  "/usr/bin/docker",
                  "--docker-sha256",
                  "a".repeat(64),
                  "--daemon-id",
                  DAEMON
                },
                forbidden,
                (n, p) -> {},
                (s, c) -> inputs()));
    Path output = privateDirectory(root.resolve("invalid"));
    ObjectNode plan = SeedContract.plan(inputs(), MARKER, output, null);
    ((ArrayNode) plan.path("stages").get(1).path("argv")).add("--privileged");
    save(output.resolve("plan.json"), plan);
    Path docker = Path.of("/usr/bin/docker");
    SeedExecutor.trustedDocker(docker, sha(docker));
    assertThrows(
        Exception.class,
        () ->
            SeedExecutor.execute(
                output.resolve("plan.json"),
                docker,
                sha(docker),
                DAEMON,
                forbidden,
                (s, c) -> inputs()));
    assertFalse(Files.exists(output.resolve("plan.once")));
    bytes(output.resolve("unexpected"), new byte[0]);
    assertThrows(
        Exception.class,
        () ->
            SeedExecutor.execute(
                output.resolve("plan.json"),
                docker,
                sha(docker),
                DAEMON,
                forbidden,
                (s, c) -> inputs()));
  }
}
