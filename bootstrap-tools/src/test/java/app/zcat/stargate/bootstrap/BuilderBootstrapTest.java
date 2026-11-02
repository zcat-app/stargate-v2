/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedExecutor.object;
import static app.zcat.stargate.bootstrap.SeedFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class BuilderBootstrapTest {
  @TempDir Path root;
  int sequence;

  record Outcome(ObjectNode result, FakeDocker fake, List<String> events) {}

  Outcome run(String failure) throws Exception {
    Path output = privateDirectory(root.resolve("bootstrap-" + (++sequence))),
        docker = root.resolve("docker");
    if (!Files.exists(docker)) bytes(docker, "synthetic Docker client".getBytes());
    ObjectNode definition = SeedContract.plan(inputs(), MARKER, output, null);
    FakeDocker fake = new FakeDocker(failure);
    fake.seedState = "running";
    List<String> events = new ArrayList<>();
    try (var journal =
        new SeedExecutor.Journal(output) {
          @Override
          void record(String event, ObjectNode fields) throws Exception {
            events.add(event);
            super.record(event, fields);
          }
        }) {
      var executor =
          new ProofExecutor(
              definition, output, docker, sha(docker), DAEMON, journal, fake, (s, c) -> inputs());
      ObjectNode result = new BuilderBootstrap(executor, CID).run();
      save(output.resolve("result.json"), result);
      return new Outcome(result, fake, events);
    }
  }

  @Test
  void fullHandoffRetainsSeedImageAndVerifiedFreshBuilder() throws Exception {
    var out = run(null);
    assertEquals(
        "bootstrap-ready", out.result.path("status").asText(), out.result.toPrettyString());
    assertEquals(BUILDER, out.result.path("builder_id").asText());
    assertEquals(IMAGE, out.result.path("image_id").asText());
    assertTrue(out.events.contains("bootstrap_ready"));
    for (String stage :
        List.of(
            "commit-owned-seed",
            "create-builder",
            "copy-root",
            "devices",
            "root-packages",
            "check-build-deps",
            "existing-preflight")) assertTrue(out.fake.stages.contains(stage), stage);
    assertFalse(
        out.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())));
    var create =
        out.fake.calls.stream()
            .filter(c -> c.getFirst().equals("create"))
            .findFirst()
            .orElseThrow();
    for (var entry :
        Map.of("--pid", "", "--uts", "", "--ipc", "private", "--cgroupns", "private").entrySet())
      assertEquals(entry.getValue(), create.get(create.indexOf(entry.getKey()) + 1));
  }

  @Test
  void commitDiagnosticNeverCountsAsImageAcknowledgement() throws Exception {
    var out = run("commit-warning");
    assertEquals("failed", out.result.path("status").asText());
    assertTrue(out.result.path("builder_id").isNull());
    assertEquals("commit-owned-seed", out.fake.stages.getLast());
    assertFalse(out.events.contains("bootstrap_ready"));
  }

  @Test
  void knownDirtyPreflightRemovesOnlyReinspectedBuilder() throws Exception {
    var out = run("dirty-root");
    assertEquals("failed", out.result.path("status").asText());
    assertTrue(
        out.result.path("cleanup").asText().contains("builder removed and absence confirmed"),
        out.result.toPrettyString());
    assertTrue(out.fake.calls.contains(List.of("stop", "--timeout", "15", BUILDER)));
    assertTrue(out.fake.calls.contains(List.of("rm", BUILDER)));
    assertFalse(out.fake.calls.contains(List.of("rm", CID)));
    assertTrue(out.events.contains("builder_removed"));
  }

  @Test
  void stopDiagnosticAndAmbiguousCopyNeverRemoveOwnedResources() throws Exception {
    var warned = run("builder-stop-warning");
    assertTrue(warned.result.path("cleanup").asText().contains("cleanup ambiguous"));
    assertEquals("stop-builder", warned.fake.stages.getLast());
    assertFalse(warned.fake.calls.contains(List.of("rm", BUILDER)));
    var ambiguous = run("copy-root");
    assertEquals("failed", ambiguous.result.path("status").asText());
    assertEquals("copy-root", ambiguous.fake.stages.getLast());
    assertFalse(
        ambiguous.fake.calls.stream().anyMatch(c -> List.of("stop", "rm").contains(c.getFirst())));
  }

  @Test
  void numericDnsIsCanonicalDeduplicatedAndCannotResolveNames() throws Exception {
    assertEquals(
        "nameserver 1.1.1.1\n",
        new String(BuilderBootstrap.dns("nameserver 1.1.1.1\nnameserver 1.1.1.1\n".getBytes())));
    assertEquals(
        "nameserver 127.0.0.11\nnameserver 2001:4860:4860::8888\n",
        new String(
            BuilderBootstrap.dns(
                "nameserver 127.0.0.11\nnameserver 2001:4860:4860:0:0:0:0:8888\n".getBytes())));
    for (String bad :
        List.of(
            "",
            "nameserver localhost",
            "nameserver 127.0.0.53",
            "nameserver ::",
            "nameserver ::1",
            "nameserver fe80::1%eth0",
            "nameserver 169.254.1.1",
            "nameserver ff02::1",
            "nameserver 224.0.0.1",
            "nameserver 1.1.1.1 junk",
            "nameserver 01.1.1.1",
            "nameserver 1.1.1.1\nnameserver 2.2.2.2\nnameserver 3.3.3.3\nnameserver 4.4.4.4"))
      assertThrows(Exception.class, () -> BuilderBootstrap.dns(bad.getBytes()), bad);
  }

  @Test
  void committedImageMustBindAllParentLayersAndLabelsWithoutTags() throws Exception {
    ObjectNode base = image();
    ObjectNode image =
        object(
            "Id",
            IMAGE,
            "Parent",
            SeedContract.IMAGE_ID,
            "Os",
            "linux",
            "Architecture",
            "amd64",
            "Config",
            Map.of(
                "Labels",
                Map.of("org.stargate.libc.seed-image", MARKER, SeedContract.LABEL, MARKER)),
            "RootFS",
            Map.of("Type", "layers", "Layers", List.of(BASE_LAYER, NEW_LAYER)));
    BuilderBootstrap.image(JSON.valueToTree(List.of(image)), IMAGE, base, MARKER);
    for (String key : List.of("Id", "Parent", "Architecture")) {
      ObjectNode bad = image.deepCopy();
      bad.put(key, "wrong");
      assertThrows(
          Exception.class,
          () -> BuilderBootstrap.image(JSON.valueToTree(List.of(bad)), IMAGE, base, MARKER));
    }
    ObjectNode tagged = image.deepCopy();
    tagged.set("RepoTags", JSON.valueToTree(List.of("foreign:tag")));
    assertThrows(
        Exception.class,
        () -> BuilderBootstrap.image(JSON.valueToTree(List.of(tagged)), IMAGE, base, MARKER));
  }

  @Test
  void builderOwnershipIsolationAndTmpfsContractAreStrict() throws Exception {
    BuilderBootstrap.builder(
        JSON.valueToTree(List.of(builder(MARKER, "running"))), BUILDER, MARKER, IMAGE, "running");
    for (var entry :
        Map.<String, Object>of(
                "Privileged",
                true,
                "Binds",
                List.of("/x:/y"),
                "NetworkMode",
                "host",
                "CgroupnsMode",
                "",
                "IpcMode",
                "",
                "PidMode",
                "private",
                "UTSMode",
                "private",
                "Memory",
                1024,
                "Tmpfs",
                Map.of("/work", "rw,exec,dev,size=9g,mode=0700"),
                "CapAdd",
                List.of("SYS_ADMIN"))
            .entrySet()) {
      ObjectNode bad = builder(MARKER, "running");
      ((ObjectNode) bad.path("HostConfig")).set(entry.getKey(), JSON.valueToTree(entry.getValue()));
      assertThrows(
          Exception.class,
          () ->
              BuilderBootstrap.builder(
                  JSON.valueToTree(List.of(bad)), BUILDER, MARKER, IMAGE, "running"),
          entry.getKey());
    }
  }

  @Test
  void mountCopyPrerequisitesAndExistingFreshPreflightArePreserved() throws Exception {
    BuilderBootstrap.mount("/work tmpfs rw,nosuid,size=9437184k,mode=700\n".getBytes());
    for (String bad :
        List.of(
            "/ tmpfs rw,nosuid,size=9437184k",
            "/work tmpfs rw,nodev,nosuid,size=9437184k",
            "/work tmpfs rw,nosuid,size=1024k",
            "/work overlay rw,nosuid,size=9437184k"))
      assertThrows(Exception.class, () -> BuilderBootstrap.mount(bad.getBytes()));
    assertThrows(Exception.class, () -> BuilderBootstrap.mount(new byte[] {(byte) 255}));
    for (String flag :
        List.of(
            "--numeric-owner",
            "--xattrs",
            "--acls",
            "--one-file-system",
            "--exclude=./dev",
            "--exclude=./work")) assertTrue(BuilderBootstrap.COPY.contains(flag));
    assertTrue(BuilderBootstrap.PREFLIGHT.contains("/work/root/build/build.rc"));
    assertTrue(BuilderBootstrap.PREFLIGHT.contains("/work/root/build/glibc-2.39/stamp-dir"));
  }
}
