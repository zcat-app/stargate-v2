/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SeedContractTest {
  @TempDir Path root;

  @Test
  void fixedPlanPreservesAllStagesResourcesHashesAndBuildSeparation() throws Exception {
    var plan = SeedContract.plan(inputs(), MARKER, root.resolve("output"), null);
    var stages = plan.path("stages");
    assertEquals(
        List.of("image-inspect", "create", "inspect-created", "start", "inspect-running"),
        java.util.stream.IntStream.range(0, 5)
            .mapToObj(i -> stages.get(i).path("stage").asText())
            .toList());
    var create = SeedExecutor.argv(stages.get(1));
    for (var pair :
        Map.of(
                "--memory",
                "4g",
                "--memory-swap",
                "4g",
                "--cpus",
                "2",
                "--pids-limit",
                "512",
                "--log-driver",
                "none",
                "--pid",
                "",
                "--uts",
                "",
                "--ipc",
                "private",
                "--cgroupns",
                "private")
            .entrySet())
      assertEquals(pair.getValue(), create.get(create.indexOf(pair.getKey()) + 1));
    assertFalse(create.contains("--storage-opt"));
    int before = 0, after = 0;
    for (var stage : stages) {
      if (stage.path("stage").asText().equals("check-hash-before")) before++;
      if (stage.path("stage").asText().equals("check-hash-after")) after++;
    }
    assertEquals(7, before);
    assertEquals(7, after);
    assertFalse(plan.toString().contains("dpkg-buildpackage"));
    assertFalse(plan.toString().contains("--privileged"));
    assertTrue(plan.toString().contains("DEB_BUILD_OPTIONS="));
    assertTrue(plan.toString().contains(SeedContract.PACKAGE_SHA));
  }

  @Test
  void quotaIsOptionalExactAndNeverFallsBack() throws Exception {
    var plan = SeedContract.plan(inputs(), MARKER, root.resolve("out"), "8G");
    var argv = SeedExecutor.argv(plan.path("stages").get(1));
    assertEquals("size=8G", argv.get(argv.indexOf("--storage-opt") + 1));
    assertThrows(
        Exception.class, () -> SeedContract.plan(inputs(), MARKER, root.resolve("bad"), "16G"));
  }

  @Test
  void imageRequiresExactDigestArchOsAndNoVolumes() throws Exception {
    SeedContract.image(JSON.valueToTree(List.of(image())));
    for (String field : List.of("Id", "Os", "Architecture")) {
      var image = image();
      image.put(field, "wrong");
      assertThrows(Exception.class, () -> SeedContract.image(JSON.valueToTree(List.of(image))));
    }
    var image = image();
    image.set("RepoDigests", JSON.createArrayNode());
    assertThrows(Exception.class, () -> SeedContract.image(JSON.valueToTree(List.of(image))));
  }

  @Test
  void seedIdentityStatesAndIsolationAreStrict() throws Exception {
    for (String state : List.of("created", "running", "exited"))
      SeedContract.container(
          JSON.valueToTree(List.of(seed(MARKER, state, null))), MARKER, CID, state, null);
    Map<String, Object> bad = new LinkedHashMap<>();
    bad.put("Memory", 0);
    bad.put("MemorySwap", -1);
    bad.put("NanoCpus", 0);
    bad.put("PidsLimit", 0);
    bad.put("StorageOpt", Map.of("size", "8G"));
    bad.put("Privileged", true);
    bad.put("NetworkMode", "host");
    bad.put("Binds", List.of("/host:/build"));
    bad.put("Devices", List.of(Map.of("PathOnHost", "/dev/sda")));
    bad.put("CapAdd", List.of("SYS_ADMIN"));
    bad.put("LogConfig", Map.of("Type", "json-file"));
    bad.put("PidMode", "private");
    bad.put("UTSMode", "private");
    bad.put("IpcMode", "");
    bad.put("CgroupnsMode", "");
    for (var entry : bad.entrySet()) {
      var data = seed(MARKER, "running", null);
      ((ObjectNode) data.path("HostConfig"))
          .set(entry.getKey(), JSON.valueToTree(entry.getValue()));
      assertThrows(
          Exception.class,
          () ->
              SeedContract.container(JSON.valueToTree(List.of(data)), MARKER, CID, "running", null),
          entry.getKey());
    }
    assertThrows(
        Exception.class,
        () -> SeedContract.container(JSON.createArrayNode(), MARKER, CID, "created", null));
  }

  @Test
  void planDirectoryIsNewPrivateAndOutsideInputs() throws Exception {
    Path source = Files.createDirectory(root.resolve("source")),
        ca = Files.createDirectory(root.resolve("ca")),
        output = root.resolve("out");
    SeedContract.prepare(source, ca.resolve("bootstrap-ca.pem"), output, null, (s, c) -> inputs());
    assertEquals(0700, mode(output));
    assertEquals(0600, mode(output.resolve("plan.json")));
    assertThrows(
        Exception.class,
        () ->
            SeedContract.prepare(
                source, ca.resolve("bootstrap-ca.pem"), output, null, (s, c) -> inputs()));
    for (Path bad : List.of(source.resolve("new"), ca.resolve("new")))
      assertThrows(
          Exception.class,
          () ->
              SeedContract.prepare(
                  source, ca.resolve("bootstrap-ca.pem"), bad, null, (s, c) -> inputs()));
  }

  @Test
  void failedPreparationRetainsWorkspaceWithoutPlanAndRejectsAliases() throws Exception {
    Path output = root.resolve("failed");
    assertThrows(
        Exception.class,
        () ->
            SeedContract.prepare(
                Path.of("/fake/source"),
                Path.of("/fake/ca/bootstrap-ca.pem"),
                output,
                null,
                (s, c) -> {
                  throw new java.io.IOException("mismatch");
                }));
    assertTrue(Files.isDirectory(output));
    assertFalse(Files.exists(output.resolve("plan.json")));
    Path alias = root.resolve("alias");
    Files.createSymbolicLink(alias, output);
    assertThrows(
        Exception.class,
        () ->
            SeedContract.prepare(
                Path.of("/fake/source"),
                Path.of("/fake/ca/bootstrap-ca.pem"),
                alias.resolve("new"),
                null,
                (s, c) -> inputs()));
  }

  @Test
  void ownedOneShotFenceCannotBeReusedEvenWhenIncomplete() throws Exception {
    Path output = privateDirectory(root.resolve("out"));
    var plan = SeedContract.plan(inputs(), MARKER, output, null);
    save(output.resolve("plan.json"), plan);
    String digest = SeedExecutor.claim(output.resolve("plan.json"));
    assertEquals(digest, json(output.resolve("plan.once")).path("plan_sha256").asText());
    assertThrows(Exception.class, () -> SeedExecutor.claim(output.resolve("plan.json")));
    Path second = privateDirectory(root.resolve("second"));
    save(second.resolve("plan.json"), plan);
    bytes(second.resolve("plan.once"), new byte[0]);
    assertThrows(Exception.class, () -> SeedExecutor.claim(second.resolve("plan.json")));
  }

  @Test
  void claimRejectsPublicPlanOrHardlinksBeforeFence() throws Exception {
    Path output = privateDirectory(root.resolve("out"));
    Path path = output.resolve("plan.json");
    save(path, SeedContract.plan(inputs(), MARKER, output, null));
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"));
    assertThrows(Exception.class, () -> SeedExecutor.claim(path));
    assertFalse(Files.exists(output.resolve("plan.once")));
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    Files.createLink(root.resolve("linked"), path);
    assertThrows(Exception.class, () -> SeedExecutor.claim(path));
  }

  @Test
  void sourceAndTarInventoriesRejectByteModeLinkAndTraversalChanges() throws Exception {
    Path source = Files.createDirectory(root.resolve("source"));
    Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rwxr-xr-x"));
    Path file = Files.writeString(source.resolve("file"), "abc");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
    String initial = canonicalSha(Inventories.source(source));
    Files.writeString(file, "xyz");
    assertNotEquals(initial, canonicalSha(Inventories.source(source)));
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    assertThrows(Exception.class, () -> Inventories.source(source));
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"));
    Files.createLink(source.resolve("hardlink"), file);
    assertThrows(Exception.class, () -> Inventories.source(source));
    Path tar = root.resolve("source.tar");
    SeedFixtures.sourceTar(tar, false);
    assertEquals(SeedFixtures.sourceSha(), canonicalSha(Inventories.tar(tar)));
    for (String bad : List.of("glibc-2.39/../outside", "other/file", "glibc-2.39//file")) {
      TestFiles.tar(
          tar, List.of(TestFiles.dir("glibc-2.39"), TestFiles.file(bad, "abc".getBytes())), false);
      assertThrows(Exception.class, () -> Inventories.tar(tar));
    }
  }

  @Test
  void badCaCannotReachSourceTransfer() throws Exception {
    Path source = Files.createDirectory(root.resolve("source")),
        ca = Files.writeString(root.resolve("bootstrap-ca.pem"), "bad");
    assertTrue(
        assertThrows(Exception.class, () -> SeedContract.verifyInputs(source, ca))
            .getMessage()
            .contains("CA bundle hash mismatch"));
  }

  @Test
  void symbolicTarMembersStayLinksAndSpecialMembersNeverBecomeRegularFiles() throws Exception {
    Path archive = root.resolve("links.tar");
    TestFiles.tar(
        archive,
        List.of(
            TestFiles.dir("glibc-2.39"),
            TestFiles.file("glibc-2.39/file", "abc".getBytes()),
            new TestFiles.Entry("glibc-2.39/link", new byte[0], 0777, "file")),
        false);
    assertEquals(
        JSON.valueToTree(List.of("symlink", "file")), Inventories.tar(archive).path("link"));
    for (byte type :
        new byte[] {
          org.apache.commons.compress.archivers.tar.TarConstants.LF_CHR,
          org.apache.commons.compress.archivers.tar.TarConstants.LF_BLK,
          org.apache.commons.compress.archivers.tar.TarConstants.LF_FIFO,
          org.apache.commons.compress.archivers.tar.TarConstants.LF_LINK,
          (byte) 'Z'
        }) {
      var member =
          new org.apache.commons.compress.archivers.tar.TarArchiveEntry("glibc-2.39/special", type);
      assertFalse(Inventories.regularMember(member));
    }
  }
}
