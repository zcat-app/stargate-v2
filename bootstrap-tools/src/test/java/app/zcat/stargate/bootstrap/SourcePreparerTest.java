/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class SourcePreparerTest {
  @TempDir Path root;
  Path project, artifacts, parent;
  byte[] patch, source;
  ObjectNode manifest;
  final Transport real = new Transport.Processes();

  @BeforeEach
  void setup() throws Exception {
    project = Files.createDirectory(root.resolve("project"));
    artifacts = Files.createDirectory(root.resolve("artifacts"));
    parent = Files.createDirectory(root.resolve("work"));
    Files.createDirectories(project.resolve("containers/native/patches"));
    Path actual =
        Path.of("../containers/native/patches/glibc-CVE-2026-18374.patch")
            .toAbsolutePath()
            .normalize();
    patch = Files.readAllBytes(actual);
    Files.write(project.resolve("containers/native/" + SourcePreparer.PATCH), patch);
    manifest =
        (ObjectNode) JSON.readTree(Path.of("../containers/native/glibc-inputs.json").toFile());
    source =
        ("/* fixture padding */\n".repeat(354) + SourcePreparer.images(patch).oldImage())
            .getBytes(StandardCharsets.ISO_8859_1);
    TestFiles.tar(
        artifacts.resolve(SourcePreparer.SOURCES.get(2)),
        List.of(
            TestFiles.file("glibc-2.39/libio/fileops.c", source),
            TestFiles.file("glibc-2.39/nss/fixture/data", "readable".getBytes()),
            new TestFiles.Entry(
                "glibc-2.39/scripts/tool", "#!/bin/sh\nexit 0\n".getBytes(), 0755, null),
            new TestFiles.Entry("glibc-2.39/nss/fixture/link", new byte[0], 0777, "data")),
        true);
    TestFiles.tar(
        artifacts.resolve(SourcePreparer.SOURCES.get(1)),
        List.of(TestFiles.file("debian/source/format", "3.0 (quilt)\n".getBytes())),
        true);
    Files.write(artifacts.resolve(SourcePreparer.AUX), new byte[SourcePreparer.AUX_SIZE]);
    dsc();
    pins();
  }

  void dsc() throws Exception {
    StringBuilder files = new StringBuilder(), hashes = new StringBuilder();
    for (String name :
        List.of(SourcePreparer.SOURCES.get(1), SourcePreparer.SOURCES.get(2), SourcePreparer.AUX)) {
      byte[] bytes = Files.readAllBytes(artifacts.resolve(name));
      files.append(
          " "
              + HexFormat.of().formatHex(MessageDigest.getInstance("MD5").digest(bytes))
              + " "
              + bytes.length
              + " "
              + name
              + "\n");
      hashes.append(" " + sha(bytes) + " " + bytes.length + " " + name + "\n");
    }
    Files.writeString(
        artifacts.resolve(SourcePreparer.SOURCES.getFirst()),
        "Format: 3.0 (quilt)\n"
            + "Source: glibc\n"
            + "Version: 2.39-0ubuntu8.9\n"
            + "Maintainer: Offline Test <test@example.invalid>\n"
            + "Files:\n"
            + files
            + "Checksums-Sha256:\n"
            + hashes);
  }

  void pins() throws Exception {
    ObjectNode sources = JSON.createObjectNode();
    for (String name : SourcePreparer.SOURCES) sources.put(name, sha(artifacts.resolve(name)));
    manifest.set("source_files_sha256", sources);
    manifest.set(
        "source_auxiliary_files_sha256",
        JSON.createObjectNode()
            .put(SourcePreparer.AUX, sha(artifacts.resolve(SourcePreparer.AUX))));
    Files.writeString(
        project.resolve("containers/native/glibc-inputs.json"), JSON.writeValueAsString(manifest));
  }

  SourcePreparer helper(Transport transport) {
    return new SourcePreparer(
        project,
        transport,
        (name, destination) -> bytes(destination, Files.readAllBytes(artifacts.resolve(name))));
  }

  Path workspace() throws Exception {
    try (var paths = Files.list(parent)) {
      return paths.findFirst().orElseThrow();
    }
  }

  ObjectNode status() throws Exception {
    return (ObjectNode) json(workspace().resolve("status.json"));
  }

  @Test
  void realOfflineExtractionAndExactPatchPreserveReadableModesAndPrivateEvidence()
      throws Exception {
    Path work = helper(real).prepare(parent);
    assertEquals("prepared", json(work.resolve("status.json")).path("status").asText());
    assertEquals(0700, mode(work));
    Path tree = work.resolve("glibc-2.39");
    SourcePreparer.permissions(tree);
    assertEquals(0755, mode(tree));
    assertEquals(0755, mode(tree.resolve("scripts/tool")));
    assertEquals("data", Files.readSymbolicLink(tree.resolve("nss/fixture/link")).toString());
    for (String file :
        List.of(
            "status.json", "backport.patch", "unpack.log", "patch-check.log", "patch-apply.log"))
      assertEquals(0600, mode(work.resolve(file)));
    assertFalse(Arrays.equals(source, Files.readAllBytes(tree.resolve(SourcePreparer.TARGET))));
    assertArrayEquals(
        patch, Files.readAllBytes(project.resolve("containers/native/" + SourcePreparer.PATCH)));
  }

  @Test
  void corruptPrimariesAreAllRecordedAndNoUnpackOccurs() throws Exception {
    for (String name : SourcePreparer.SOURCES)
      Files.writeString(artifacts.resolve(name), "corrupt");
    assertThrows(
        Exception.class,
        () ->
            helper(
                    r -> {
                      fail("No subprocess before input gates");
                      return 0;
                    })
                .prepare(parent));
    var state = status();
    assertEquals(4, state.path("artifacts").size());
    assertEquals("download", state.path("stage").asText());
    for (var entry : state.path("artifacts").properties())
      assertFalse(entry.getValue().path("verified").asBoolean());
  }

  @Test
  void missingOrCorruptAuxiliaryRetainsVerifiedPrimaryInputs() throws Exception {
    Files.delete(artifacts.resolve(SourcePreparer.AUX));
    assertThrows(
        Exception.class,
        () ->
            helper(
                    r -> {
                      fail("No unpack");
                      return 0;
                    })
                .prepare(parent));
    for (String name : SourcePreparer.SOURCES)
      assertTrue(status().path("artifacts").path(name).path("verified").asBoolean());
    assertFalse(status().path("artifacts").path(SourcePreparer.AUX).path("verified").asBoolean());
  }

  @Test
  void dscRejectsWrongHashSizePathAndDuplicates() throws Exception {
    Path dsc = artifacts.resolve(SourcePreparer.SOURCES.getFirst());
    String original = Files.readString(dsc);
    Map<String, String> hashes = helper(real).inputs().hashes();
    for (String changed :
        List.of(
            original.replace(" 833 ", " 834 "),
            original.replace(SourcePreparer.AUX, "../escape.asc"),
            original.replace(hashes.get(SourcePreparer.AUX), "a".repeat(64)),
            original
                + " "
                + hashes.get(SourcePreparer.AUX)
                + " 833 "
                + SourcePreparer.AUX
                + "\n")) {
      Files.writeString(dsc, changed);
      assertThrows(Exception.class, () -> SourcePreparer.verifyDsc(dsc, hashes));
    }
  }

  @Test
  void patchAndManifestChangesFailBeforeWorkspaceCreation() throws Exception {
    Files.write(
        project.resolve("containers/native/" + SourcePreparer.PATCH), "tampered".getBytes());
    assertThrows(Exception.class, () -> helper(real).prepare(parent));
    try (var files = Files.list(parent)) {
      assertEquals(0, files.count());
    }
    Files.write(project.resolve("containers/native/" + SourcePreparer.PATCH), patch);
    ((ObjectNode) manifest.path("source_files_sha256")).put("../escape", "a".repeat(64));
    Files.writeString(
        project.resolve("containers/native/glibc-inputs.json"), JSON.writeValueAsString(manifest));
    assertThrows(Exception.class, () -> helper(real).prepare(parent));
  }

  @Test
  void sourceAndPatchAliasesAndTargetHardlinksAreRejected() throws Exception {
    Path sourceRoot = Files.createDirectories(root.resolve("tree/libio")).getParent(),
        outside = root.resolve("outside");
    Files.write(outside, source);
    Path target = sourceRoot.resolve(SourcePreparer.TARGET);
    Files.createSymbolicLink(target, outside);
    assertThrows(Exception.class, () -> SourcePreparer.target(sourceRoot));
    Files.delete(target);
    Files.createLink(target, outside);
    assertThrows(Exception.class, () -> SourcePreparer.target(sourceRoot));
    Files.delete(target);
    Files.write(target, source);
    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-rw-rw-"));
    assertThrows(Exception.class, () -> SourcePreparer.target(sourceRoot));
    Path alias = root.resolve("alias");
    Files.createSymbolicLink(alias, parent);
    assertThrows(Exception.class, () -> helper(real).prepare(alias));
  }

  @Test
  void exactPreimageAllowsOffsetsButRejectsFuzzDuplicatesAndReapplication() throws Exception {
    for (String content :
        List.of(
            "/* offset */\n" + new String(source, StandardCharsets.ISO_8859_1),
            new String(source, StandardCharsets.ISO_8859_1)
                .replace("strip (ccs, ccs);", "strip (OTHER, ccs);"),
            new String(source, StandardCharsets.ISO_8859_1).repeat(2))) {
      Path work = temporary(root, "patch-");
      Path tree = Files.createDirectories(work.resolve("glibc-2.39/libio")).getParent();
      Path target = tree.resolve(SourcePreparer.TARGET);
      Files.writeString(target, content, StandardCharsets.ISO_8859_1);
      Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-r--r--"));
      Path input = work.resolve("backport.patch");
      Files.write(input, patch);
      if (content.startsWith("/* offset */")) {
        helper(real).apply(tree, input, work);
        assertThrows(Exception.class, () -> helper(real).apply(tree, input, work));
      } else {
        assertThrows(Exception.class, () -> helper(real).apply(tree, input, work));
        assertEquals(content, Files.readString(target, StandardCharsets.ISO_8859_1));
      }
    }
  }

  @Test
  void restrictiveExtractedOrPostpatchModesNeverPublishPreparedStatus() throws Exception {
    for (String point : List.of("unpack.log", "patch-apply.log")) {
      Path another = Files.createDirectory(root.resolve(point));
      Transport wrapped =
          r -> {
            int rc = real.run(r);
            if (r.out().getFileName().toString().equals(point))
              Files.setPosixFilePermissions(
                  r.cwd().resolve("glibc-2.39/libio/fileops.c"),
                  PosixFilePermissions.fromString("rw-------"));
            return rc;
          };
      assertThrows(Exception.class, () -> helper(wrapped).prepare(another));
      try (var files = Files.list(another)) {
        assertEquals(
            "incomplete",
            json(files.findFirst().orElseThrow().resolve("status.json")).path("status").asText());
      }
    }
  }

  @Test
  void permissionChecksDoNotRepairInvalidSourceModes() throws Exception {
    Path tree = Files.createDirectory(root.resolve("tree"));
    Files.setPosixFilePermissions(tree, PosixFilePermissions.fromString("rwxr-xr-x"));
    Path file = Files.writeString(tree.resolve("file"), "data");
    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
    assertThrows(Exception.class, () -> SourcePreparer.permissions(tree));
    assertEquals(0600, mode(file));
  }

  @Test
  void unpackTimeoutRetainsIncompleteStatusAndVerifiedArtifacts() throws Exception {
    assertThrows(
        Exception.class,
        () ->
            helper(
                    r -> {
                      throw new Transport.Uncertain("timeout");
                    })
                .prepare(parent));
    assertEquals("unpack", status().path("stage").asText());
    for (var entry : status().path("artifacts").properties())
      assertTrue(entry.getValue().path("verified").asBoolean());
  }

  @Test
  void sourceToolGetsFixedEnvironmentLiteralArgumentsAndUnpackUmask() throws Exception {
    List<Transport.Request> calls = new ArrayList<>();
    Transport wrapped =
        r -> {
          calls.add(r);
          return real.run(r);
        };
    helper(wrapped).prepare(parent);
    assertEquals(0022, calls.getFirst().umask());
    assertEquals("/usr/bin/dpkg-source", calls.getFirst().argv().getFirst());
    for (var call : calls) {
      assertEquals(TOOL_ENV, call.env());
      assertNull(call.stdin());
      assertEquals(180, call.timeout());
      if (call.argv().getFirst().equals("/usr/bin/patch")) assertEquals(0077, call.umask());
    }
  }

  @Test
  void unsupportedDownloadNameNeverCreatesFile() throws Exception {
    assertThrows(
        Exception.class,
        () -> new SourcePreparer.WebDownloader().download("../escape", root.resolve("out")));
    assertFalse(Files.exists(root.resolve("out")));
  }
}
