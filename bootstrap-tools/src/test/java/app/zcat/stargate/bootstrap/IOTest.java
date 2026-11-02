/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class IOTest {
  @TempDir Path root;

  @Test
  void directoryDescriptorStaysAnchoredAfterParentRename() throws Exception {
    Path original = Files.createDirectory(root.resolve("owned")),
        moved = root.resolve("moved"),
        other = Files.createDirectory(root.resolve("other"));
    try (NativeDirectory directory = NativeDirectory.open(original)) {
      Files.move(original, moved);
      Files.createSymbolicLink(original, other);
      try (var fence = directory.create("fence")) {
        write(fence, "private".getBytes());
        fence.force(true);
      }
      directory.force(true);
    }
    assertEquals("private", Files.readString(moved.resolve("fence")));
    assertFalse(Files.exists(other.resolve("fence")));
  }

  @Test
  void openedInputSurvivesNameReplacementAndFifoOpenNeverBlocks() throws Exception {
    Path input = Files.writeString(root.resolve("input"), "original");
    try (NativeInput descriptor = new NativeInput(input, true)) {
      Files.move(input, root.resolve("old"));
      Process fifo = new ProcessBuilder("/usr/bin/mkfifo", input.toString()).start();
      assertEquals(0, fifo.waitFor());
      byte[] bytes = new byte[16];
      int count = descriptor.read(bytes);
      assertEquals("original", new String(bytes, 0, count));
      assertTimeoutPreemptively(
          java.time.Duration.ofSeconds(1),
          () ->
              assertThrows(
                  Exception.class,
                  () -> {
                    try (var ignored = new NativeInput(input, true)) {}
                  }));
    }
  }

  @Test
  void canonicalInventoryEncodingMatchesSortedAsciiJsonIncludingUnicode() throws Exception {
    ObjectNode value = JSON.createObjectNode();
    value.put("z", "é\n");
    value.set("a", JSON.createArrayNode().add(1).add("😀"));
    assertEquals("{\"a\":[1,\"\\ud83d\\ude00\"],\"z\":\"\\u00e9\\n\"}", canonical(value));
    ObjectNode order = JSON.createObjectNode().put("𐀀", 2).put("\ue000", 1);
    assertEquals("{\"\\ue000\":1,\"\\ud800\\udc00\":2}", canonical(order));
  }

  @Test
  void symlinkHardlinkAndFifoInputsAreRejectedWithoutBlocking() throws Exception {
    Path file = Files.writeString(root.resolve("file"), "data");
    Path alias = root.resolve("alias");
    Files.createSymbolicLink(alias, file);
    assertThrows(Exception.class, () -> read(alias, true, 100));
    Files.createLink(root.resolve("hardlink"), file);
    assertThrows(Exception.class, () -> sha(file));
    Path fifo = root.resolve("fifo");
    Process create = new ProcessBuilder("/usr/bin/mkfifo", fifo.toString()).start();
    assertEquals(0, create.waitFor());
    assertTimeoutPreemptively(
        java.time.Duration.ofSeconds(1),
        () -> assertThrows(Exception.class, () -> read(fifo, true, 100)));
  }

  @Test
  void privateArtifactsRefuseOverwriteAndJsonRejectsTrailingContent() throws Exception {
    Path path = root.resolve("data.json");
    bytes(path, "{} {}".getBytes());
    assertEquals(0600, mode(path));
    assertThrows(Exception.class, () -> json(path));
    assertThrows(Exception.class, () -> bytes(path, "overwrite".getBytes()));
    assertEquals("{} {}", Files.readString(path));
    Path real = Files.createDirectory(root.resolve("real")),
        alias = root.resolve("directory-alias");
    Files.createSymbolicLink(alias, real);
    assertThrows(Exception.class, () -> directory(alias));
  }

  @Test
  void completeCliDispatchRejectsUnknownOptionsAndMissingAttestationBeforeAnyDocker()
      throws Exception {
    Transport forbidden =
        r -> {
          fail("No Docker");
          return 0;
        };
    SourcePreparer.Downloader noDownload =
        (n, p) -> {
          fail("No downloads");
        };
    assertEquals(
        0,
        BootstrapTools.execute(
            new String[] {"--help"}, forbidden, noDownload, (s, c) -> SeedFixtures.inputs()));
    for (String kind : List.of("source", "ca", "seed", "bootstrap"))
      assertThrows(
          Exception.class,
          () ->
              BootstrapTools.execute(
                  new String[] {"--project", root.toString(), kind, "--unknown"},
                  forbidden,
                  noDownload,
                  (s, c) -> SeedFixtures.inputs()));
    assertThrows(
        Exception.class,
        () ->
            BootstrapTools.execute(
                new String[] {
                  "--project", root.toString(), "bootstrap", "--plan", "/missing/plan.json"
                },
                forbidden,
                noDownload,
                (s, c) -> SeedFixtures.inputs()));
  }
}
