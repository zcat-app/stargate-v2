/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

class CaSeedTest {
  @TempDir Path root;
  byte[] deb, index, release, key;
  CaSeed.Pins pins;
  Path releasePath, indexPath, debPath, keyring, parent;

  String stanza(String filename) {
    return "Package: ca-certificates\n"
        + "Version: 20260816ubuntu0.24.04.1\n"
        + "Architecture: all\n"
        + "Filename: "
        + filename
        + "\nSize: "
        + deb.length
        + "\nSHA256: "
        + pins.deb()
        + "\n\n";
  }

  @BeforeEach
  void setup() throws Exception {
    deb = "synthetic package".getBytes();
    key = "synthetic keyring".getBytes();
    pins = new CaSeed.Pins("", "", sha(deb), sha(key));
    index = TestFiles.xz(stanza(CaSeed.DEB_PATH).getBytes());
    String indexSha = sha(index);
    release =
        ("SHA256:\n " + indexSha + " " + index.length + " " + CaSeed.INDEX_PATH + "\n").getBytes();
    pins = new CaSeed.Pins(sha(release), indexSha, sha(deb), sha(key));
    releasePath = Files.write(root.resolve("InRelease"), release);
    indexPath = Files.write(root.resolve("Packages.xz"), index);
    debPath = Files.write(root.resolve("ca.deb"), deb);
    keyring = Files.write(root.resolve("keyring.gpg"), key);
    parent = Files.createDirectory(root.resolve("work"));
  }

  @Test
  void pinnedReleaseAndPackageBindingsMatch() throws Exception {
    CaSeed.release(release, index, pins);
    CaSeed.packages(index, deb, pins);
  }

  @Test
  void corruptInputsAndWrongSignedIndexSizeFail() throws Exception {
    assertThrows(
        Exception.class,
        () -> CaSeed.release(release, Arrays.copyOf(index, index.length + 1), pins));
    assertThrows(
        Exception.class, () -> CaSeed.packages(index, Arrays.copyOf(deb, deb.length + 1), pins));
    byte[] wrong = new String(release).replace(" " + index.length + " ", " 1 ").getBytes();
    assertThrows(
        Exception.class,
        () ->
            CaSeed.release(
                wrong,
                index,
                new CaSeed.Pins(sha(wrong), pins.index(), pins.deb(), pins.keyring())));
  }

  @Test
  void wrongFilenameDuplicatePackageAndDuplicateFieldAreRejected() throws Exception {
    for (String text :
        List.of(
            stanza("wrong.deb"),
            stanza(CaSeed.DEB_PATH).repeat(2),
            stanza(CaSeed.DEB_PATH)
                .replace("Architecture: all", "Architecture: all\nArchitecture: all"))) {
      byte[] compressed = TestFiles.xz(text.getBytes());
      assertThrows(Exception.class, () -> CaSeed.packages(compressed, deb, pins));
    }
  }

  @Test
  void wrongMissingMultipleAndNonzeroValidSignaturesFail() throws Exception {
    String valid = "[GNUPG:] VALIDSIG " + CaSeed.SIGNER + " details\n";
    CaSeed.signature(0, valid);
    assertThrows(Exception.class, () -> CaSeed.signature(1, valid));
    for (String output : List.of("", valid.repeat(2), valid.replace(CaSeed.SIGNER, "A".repeat(40))))
      assertThrows(Exception.class, () -> CaSeed.signature(0, output));
  }

  @Test
  void linkedCertificateAndIncompleteBundleAreRejected() throws Exception {
    Path archive = root.resolve("ca.tar");
    TestFiles.tar(
        archive,
        List.of(
            new TestFiles.Entry(
                "./usr/share/ca-certificates/mozilla/bad.crt", new byte[0], 0777, "/etc/passwd")),
        false);
    assertThrows(Exception.class, () -> CaSeed.bundle(archive));
    TestFiles.tar(archive, List.of(), false);
    assertThrows(Exception.class, () -> CaSeed.bundle(archive));
  }

  byte[] certificate() throws Exception {
    try (var files = Files.list(Path.of("/usr/share/ca-certificates/mozilla"))) {
      return Files.readAllBytes(
          files.filter(p -> p.toString().endsWith(".crt")).findFirst().orElseThrow());
    }
  }

  @Test
  void fullBundlePreservesExactly120SortedNormalizedCertificateEntries() throws Exception {
    byte[] cert = certificate();
    List<TestFiles.Entry> entries = new ArrayList<>();
    for (int i = 119; i >= 0; i--)
      entries.add(
          TestFiles.file(
              String.format(Locale.ROOT, "./usr/share/ca-certificates/mozilla/cert-%03d.crt", i),
              cert));
    Path archive = root.resolve("ca.tar");
    TestFiles.tar(archive, entries, false);
    byte[] bundle = CaSeed.bundle(archive);
    String normalized = new String(cert, StandardCharsets.US_ASCII).stripTrailing() + "\n";
    assertEquals(normalized.repeat(120), new String(bundle, StandardCharsets.US_ASCII));
    entries.add(entries.getFirst());
    TestFiles.tar(archive, entries, false);
    assertThrows(Exception.class, () -> CaSeed.bundle(archive));
  }

  @Test
  void malformedCertificateIsRejected() throws Exception {
    Path archive = root.resolve("ca.tar");
    TestFiles.tar(
        archive,
        List.of(
            TestFiles.file("./usr/share/ca-certificates/mozilla/bad.crt", "not a PEM".getBytes())),
        false);
    assertThrows(Exception.class, () -> CaSeed.bundle(archive));
  }

  @Test
  void signatureFailureRetainsPrivateWorkspaceAndNeverProcessesPackage() throws Exception {
    List<Transport.Request> calls = new ArrayList<>();
    Transport fake =
        r -> {
          calls.add(r);
          bytes(r.out(), ("[GNUPG:] VALIDSIG " + CaSeed.SIGNER + " details\n").getBytes());
          bytes(r.err(), new byte[0]);
          return 1;
        };
    assertThrows(
        Exception.class,
        () -> new CaSeed(fake).prepare(releasePath, indexPath, debPath, parent, keyring, pins));
    assertEquals(1, calls.size());
    try (var files = Files.list(parent)) {
      Path work = files.findFirst().orElseThrow();
      assertEquals(0700, mode(work));
      assertFalse(Files.exists(work.resolve("ca-certificates.deb")));
      assertFalse(Files.exists(work.resolve("bootstrap-ca.pem")));
      assertTrue(Files.exists(work.resolve("InRelease")));
    }
  }

  @Test
  void dpkgFailureRetainsPackageAndNeverPublishesBundle() throws Exception {
    List<Transport.Request> calls = new ArrayList<>();
    Transport fake =
        r -> {
          calls.add(r);
          bytes(
              r.out(),
              (calls.size() == 1
                      ? "[GNUPG:] VALIDSIG " + CaSeed.SIGNER + " details\n"
                      : "invalid tar")
                  .getBytes());
          bytes(r.err(), new byte[0]);
          return calls.size() == 1 ? 0 : 2;
        };
    assertThrows(
        Exception.class,
        () -> new CaSeed(fake).prepare(releasePath, indexPath, debPath, parent, keyring, pins));
    assertEquals(
        List.of("/usr/bin/gpgv", "/usr/bin/dpkg-deb"),
        calls.stream().map(r -> r.argv().getFirst()).toList());
    try (var files = Files.list(parent)) {
      Path work = files.findFirst().orElseThrow();
      assertArrayEquals(deb, Files.readAllBytes(work.resolve("ca-certificates.deb")));
      assertFalse(Files.exists(work.resolve("bootstrap-ca.pem")));
    }
  }

  @Test
  void corruptKeyringFailsBeforeAnySubprocessOrWorkspace() throws Exception {
    Files.writeString(keyring, "corrupt");
    assertThrows(
        Exception.class,
        () ->
            new CaSeed(
                    r -> {
                      fail("No subprocess");
                      return 0;
                    })
                .prepare(releasePath, indexPath, debPath, parent, keyring, pins));
    try (var files = Files.list(parent)) {
      assertEquals(0, files.count());
    }
  }
}
