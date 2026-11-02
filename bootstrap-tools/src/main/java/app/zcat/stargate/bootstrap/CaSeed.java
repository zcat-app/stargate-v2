/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.regex.*;
import org.apache.commons.compress.archivers.tar.*;
import org.tukaani.xz.XZInputStream;

final class CaSeed {
  static final String
      RELEASE_SHA = "c607e7ab2685b82c6d37a57261f8413d68c82b01a6a4225e1c6292fcb95691b4",
      INDEX_SHA = "072a64e2a776d5ad586fe3d7f0d55cbb07d175161137b657dc1e81b35c1f1d2e",
      DEB_SHA = "8a0a754aaafed72cc8efb8c1731808133284a84fbfc76a4fcc73fce9e01b4187",
      KEYRING_SHA = "80a36b0a6de2f69f49d2df75ef473ccde121e9e190b9ea01d20a4f63778d5c31";
  static final String SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C",
      INDEX_PATH = "main/binary-amd64/Packages.xz",
      DEB_PATH = "pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.1_all.deb";
  static final Path KEYRING = Path.of("/usr/share/keyrings/ubuntu-archive-keyring.gpg");

  record Pins(String release, String index, String deb, String keyring) {}

  static final Pins PINS = new Pins(RELEASE_SHA, INDEX_SHA, DEB_SHA, KEYRING_SHA);
  final Transport transport;

  CaSeed(Transport transport) {
    this.transport = transport;
  }

  static void hash(byte[] data, String expected, String name) throws Exception {
    need(sha(data).equals(expected), name + " SHA256 mismatch");
  }

  static void release(byte[] release, byte[] compressed, Pins pins) throws Exception {
    hash(release, pins.release, "InRelease");
    hash(compressed, pins.index, "Packages.xz");
    Matcher match =
        Pattern.compile("(?m)^SHA256:\\n((?: [^\\n]+\\n)+)")
            .matcher(new String(release, StandardCharsets.US_ASCII));
    need(match.find(), "InRelease has no SHA256 section");
    List<List<String>> selected = new ArrayList<>();
    for (String line : match.group(1).lines().toList()) {
      String[] fields = line.strip().split("\\s+");
      if (fields.length == 3 && fields[2].equals(INDEX_PATH)) selected.add(List.of(fields));
    }
    need(
        selected.equals(
            List.of(List.of(pins.index, Integer.toString(compressed.length), INDEX_PATH))),
        "Signed index record mismatch");
  }

  static void packages(byte[] compressed, byte[] deb, Pins pins) throws Exception {
    hash(deb, pins.deb, "CA package");
    byte[] data;
    try (var input = new XZInputStream(new ByteArrayInputStream(compressed), 128 * 1024)) {
      data = limited(input, 64L * 1024 * 1024);
    }
    List<Map<String, String>> candidates = new ArrayList<>();
    for (String stanza : new String(data, StandardCharsets.UTF_8).split("\\n\\n")) {
      Map<String, String> fields = new HashMap<>();
      for (String line : stanza.lines().toList()) {
        int at = line.indexOf(": ");
        if (at >= 0 && !line.startsWith(" "))
          need(
              fields.putIfAbsent(line.substring(0, at), line.substring(at + 2)) == null,
              "Duplicate package index field");
      }
      if ("ca-certificates".equals(fields.get("Package"))
          && "20260816ubuntu0.24.04.1".equals(fields.get("Version"))) candidates.add(fields);
    }
    need(candidates.size() == 1, "CA package record missing/ambiguous");
    Map<String, String> expected =
        Map.of(
            "Architecture",
            "all",
            "Filename",
            DEB_PATH,
            "Size",
            Integer.toString(deb.length),
            "SHA256",
            pins.deb);
    for (var entry : expected.entrySet())
      need(
          entry.getValue().equals(candidates.getFirst().get(entry.getKey())),
          "Signed CA package record mismatch");
  }

  static byte[] bundle(Path archive) throws Exception {
    Map<String, byte[]> certs = new TreeMap<>();
    try (var input = new TarArchiveInputStream(Files.newInputStream(archive))) {
      for (TarArchiveEntry item; (item = input.getNextEntry()) != null; ) {
        String name = item.getName();
        if (!name.startsWith("./usr/share/ca-certificates/mozilla/") || !name.endsWith(".crt"))
          continue;
        need(
            item.isCheckSumOK()
                && Inventories.regularMember(item)
                && name.matches("\\./usr/share/ca-certificates/mozilla/[^/]+\\.crt")
                && !certs.containsKey(name)
                && item.getSize() <= 65536,
            "Unexpected certificate entry");
        byte[] data = limited(input, 65536);
        for (byte value : data) need((value & 255) < 128, "Non-ASCII certificate");
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(data));
        int end = data.length;
        while (end > 0 && " \t\r\n\f\u000b".indexOf(data[end - 1]) >= 0) end--;
        byte[] normalized = Arrays.copyOf(data, end + 1);
        normalized[end] = '\n';
        certs.put(name, normalized);
      }
    }
    need(certs.size() == 120, "Unexpected number of CA certificates");
    var output = new ByteArrayOutputStream();
    for (byte[] data : certs.values()) output.write(data);
    return output.toByteArray();
  }

  static void signature(int status, String output) throws Exception {
    Matcher match = Pattern.compile("(?m)^\\[GNUPG:\\] VALIDSIG ([0-9A-F]+) ").matcher(output);
    List<String> signatures = new ArrayList<>();
    while (match.find()) signatures.add(match.group(1));
    need(
        status == 0 && signatures.equals(List.of(SIGNER)),
        "Ubuntu snapshot signature verification failed");
  }

  Path prepare(Path releasePath, Path indexPath, Path debPath, Path parent) throws Exception {
    return prepare(releasePath, indexPath, debPath, parent, KEYRING, PINS);
  }

  Path prepare(Path releasePath, Path indexPath, Path debPath, Path parent, Path keyring, Pins pins)
      throws Exception {
    byte[] release = read(releasePath, false, 128L * 1024 * 1024),
        index = read(indexPath, false, 128L * 1024 * 1024),
        deb = read(debPath, false, 128L * 1024 * 1024);
    hash(read(keyring, false, 16L * 1024 * 1024), pins.keyring, "Ubuntu archive keyring");
    release(release, index, pins);
    trustedTool(Path.of("/usr/bin/gpgv"));
    trustedTool(Path.of("/usr/bin/dpkg-deb"));
    Path workspace = temporary(parent, "stargate-libc-seed-");
    try {
      Path signed = workspace.resolve("InRelease");
      bytes(signed, release);
      Path out = workspace.resolve("signature.out");
      int status =
          transport.run(
              new Transport.Request(
                  List.of(
                      "/usr/bin/gpgv",
                      "--homedir",
                      workspace.toString(),
                      "--status-fd",
                      "1",
                      "--keyring",
                      keyring.toString(),
                      signed.toString()),
                  workspace,
                  out,
                  workspace.resolve("signature.err"),
                  null,
                  180,
                  16L * 1024 * 1024,
                  32L * 1024 * 1024,
                  TOOL_ENV,
                  0077,
                  false));
      signature(status, Files.readString(out));
      packages(index, deb, pins);
      Path pack = workspace.resolve("ca-certificates.deb");
      bytes(pack, deb);
      Path tar = workspace.resolve("ca-files.tar");
      int unpack =
          transport.run(
              new Transport.Request(
                  List.of("/usr/bin/dpkg-deb", "--fsys-tarfile", pack.toString()),
                  workspace,
                  tar,
                  workspace.resolve("unpack.err"),
                  null,
                  180,
                  128L * 1024 * 1024,
                  144L * 1024 * 1024,
                  TOOL_ENV,
                  0077,
                  false));
      need(unpack == 0, "dpkg-deb failed");
      bytes(workspace.resolve("bootstrap-ca.pem"), bundle(tar));
      return workspace;
    } catch (Exception error) {
      throw new IOException(error.getMessage() + "; workspace retained: " + workspace, error);
    }
  }
}
