/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;

final class SourcePreparer {
  static final List<String> SOURCES =
      List.of(
          "glibc_2.39-0ubuntu8.9.dsc",
          "glibc_2.39-0ubuntu8.9.debian.tar.xz",
          "glibc_2.39.orig.tar.xz");
  static final String AUX = "glibc_2.39.orig.tar.xz.asc",
      PATCH = "patches/glibc-CVE-2026-18374.patch",
      TARGET = "libio/fileops.c";
  static final int AUX_SIZE = 833;
  static final long MAX_DOWNLOAD = 128L * 1024 * 1024;
  static final String ARCHIVE = "https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/";

  @FunctionalInterface
  interface Downloader {
    void download(String name, Path destination) throws Exception;
  }

  static final class WebDownloader implements Downloader {
    public void download(String name, Path destination) throws Exception {
      Cancellation.checkpoint();
      long started = System.nanoTime();
      need(SOURCES.contains(name) || AUX.equals(name), "Unsupported download filename");
      ProxySelector direct =
          new ProxySelector() {
            public List<Proxy> select(URI uri) {
              return List.of(Proxy.NO_PROXY);
            }

            public void connectFailed(URI uri, SocketAddress address, IOException error) {}
          };
      try (HttpClient client =
              HttpClient.newBuilder()
                  .connectTimeout(java.time.Duration.ofSeconds(30))
                  .proxy(direct)
                  .followRedirects(HttpClient.Redirect.NEVER)
                  .build();
          var worker = Executors.newVirtualThreadPerTaskExecutor()) {
        var request =
            HttpRequest.newBuilder(URI.create(ARCHIVE + name))
                .timeout(java.time.Duration.ofSeconds(30))
                .build();
        var response =
            client
                .sendAsync(request, HttpResponse.BodyHandlers.ofInputStream())
                .get(30, TimeUnit.SECONDS);
        try (var input = response.body()) {
          need(
              response.statusCode() == 200,
              "Archive HTTP failure or redirect refused: " + response.statusCode());
          try (var output = create(destination)) {
            long deadline = started + TimeUnit.SECONDS.toNanos(180), count = 0;
            byte[] buffer = new byte[1024 * 1024];
            while (true) {
              long remaining = deadline - System.nanoTime();
              need(remaining > 0, "Download deadline exceeded: " + name);
              Future<Integer> read = worker.submit(() -> input.read(buffer));
              int n;
              try {
                n =
                    read.get(
                        Math.min(TimeUnit.SECONDS.toNanos(30), remaining), TimeUnit.NANOSECONDS);
              } catch (Exception error) {
                input.close();
                read.cancel(true);
                throw new IOException("Download deadline/read failure: " + name, error);
              }
              if (n < 0) break;
              count += n;
              need(count <= MAX_DOWNLOAD, "Download size limit exceeded: " + name);
              write(output, Arrays.copyOf(buffer, n));
            }
          }
        }
      }
    }
  }

  record Inputs(Map<String, String> hashes, byte[] patch, String patchSha) {}

  final Path project;
  final Transport transport;
  final Downloader downloader;

  SourcePreparer(Path project, Transport transport, Downloader downloader) {
    this.project = project;
    this.transport = transport;
    this.downloader = downloader;
  }

  Inputs inputs() throws Exception {
    Path nativeDir = project.resolve("containers/native");
    JsonNode input = json(nativeDir.resolve("glibc-inputs.json"));
    JsonNode primary = input.path("source_files_sha256"),
        aux = input.path("source_auxiliary_files_sha256"),
        patches = input.path("patches");
    need(
        text(input.path("ubuntu_source_version"), "2.39-0ubuntu8.9")
            && primary.isObject()
            && new HashSet<>(names(primary)).equals(new HashSet<>(SOURCES))
            && aux.isObject()
            && names(aux).equals(List.of(AUX))
            && patches.isArray()
            && patches.size() == 1
            && text(patches.get(0).path("file"), PATCH),
        "Unsupported libc manifest");
    Map<String, String> hashes = new LinkedHashMap<>();
    for (JsonNode object : List.of(primary, aux))
      for (var entry : object.properties()) {
        need(
            entry.getValue().isTextual() && entry.getValue().asText().matches("[0-9a-f]{64}"),
            "Unsupported source hash");
        hashes.put(entry.getKey(), entry.getValue().asText());
      }
    byte[] patch = read(nativeDir.resolve(PATCH), false, 1024 * 1024);
    String actual = sha(patch);
    need(actual.equals(patches.get(0).path("sha256").asText()), "Local patch SHA256 mismatch");
    List<String> headers =
        new String(patch, StandardCharsets.ISO_8859_1)
            .lines()
            .filter(line -> line.startsWith("--- ") || line.startsWith("+++ "))
            .toList();
    need(
        headers.equals(List.of("--- a/libio/fileops.c", "+++ b/libio/fileops.c")),
        "Unsupported patch targets");
    return new Inputs(hashes, patch, actual);
  }

  static void verifyDsc(Path path, Map<String, String> hashes) throws Exception {
    String data = new String(read(path, false, MAX_DOWNLOAD), StandardCharsets.US_ASCII);
    Matcher blocks = Pattern.compile("(?m)^Checksums-Sha256:\\n((?: [^\\n]+\\n)+)").matcher(data);
    need(blocks.find(), "DSC must have exactly one SHA256 field");
    String block = blocks.group(1);
    need(!blocks.find(), "DSC duplicate SHA256 field");
    Map<String, String[]> records = new HashMap<>();
    for (String line : block.lines().toList()) {
      String[] fields = line.strip().split("\\s+");
      need(
          fields.length == 3
              && fields[0].matches("[0-9a-f]{64}")
              && fields[1].matches("[0-9]+")
              && records.putIfAbsent(fields[2], fields) == null,
          "Malformed or duplicate DSC SHA256 entry");
    }
    need(
        records.keySet().equals(Set.of(SOURCES.get(1), SOURCES.get(2), AUX)),
        "DSC references unsupported or missing source files");
    for (var entry : records.entrySet()) {
      String name = entry.getKey();
      String[] fields = entry.getValue();
      need(fields[0].equals(hashes.get(name)), "DSC SHA256 differs from manifest: " + name);
      long size = Long.parseLong(fields[1]);
      need(
          size == (name.equals(AUX) ? AUX_SIZE : Files.size(path.getParent().resolve(name))),
          "DSC source/signature size mismatch: " + name);
    }
  }

  void tool(List<String> args, Path workspace, String name, int umask) throws Exception {
    Path out = workspace.resolve(name), err = workspace.resolve(name + ".stderr");
    int status =
        transport.run(
            new Transport.Request(
                args,
                workspace,
                out,
                err,
                null,
                180,
                64L * 1024 * 1024,
                80L * 1024 * 1024,
                TOOL_ENV,
                umask,
                true));
    need(status == 0, args.getFirst() + " failed (" + status + "); see " + name);
  }

  static void permissions(Path source) throws Exception {
    directory(source);
    try (var paths = Files.walk(source)) {
      for (Path path : paths.toList()) {
        if (Files.isSymbolicLink(path)) continue;
        int mode = mode(path);
        need(
            Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                ? mode == 0755
                : Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                    && (mode == 0644 || mode == 0755),
            "Unsupported source permissions: " + path);
      }
    }
  }

  static Path target(Path source) throws Exception {
    directory(source.resolve("libio"));
    Path target = source.resolve(TARGET);
    regular(target, true);
    var data = info(target);
    need(
        ((Number) data.get("uid")).intValue() == uid()
            && (((Number) data.get("mode")).intValue() & 07022) == 0,
        "Unsafe patch target");
    return target;
  }

  record Images(String oldImage, String newImage) {}

  static Images images(byte[] patch) throws Exception {
    List<String> lines =
        Pattern.compile("(?<=\\n)")
            .splitAsStream(new String(patch, StandardCharsets.ISO_8859_1))
            .toList();
    List<Integer> hunks = new ArrayList<>();
    for (int i = 0; i < lines.size(); i++) if (lines.get(i).startsWith("@@ ")) hunks.add(i);
    need(hunks.size() == 1, "Unsupported patch hunk layout");
    Matcher header =
        Pattern.compile("@@ -[0-9]+,([0-9]+) \\+[0-9]+,([0-9]+) @@[^\\n]*\\n")
            .matcher(lines.get(hunks.getFirst()));
    need(header.matches(), "Unsupported patch hunk header");
    StringBuilder old = new StringBuilder(), next = new StringBuilder();
    int oldCount = 0, newCount = 0;
    for (int i = hunks.getFirst() + 1; i < lines.size(); i++) {
      String line = lines.get(i);
      if (line.equals("-- \n")) break;
      need(!line.isEmpty() && " -+".indexOf(line.charAt(0)) >= 0, "Unsupported patch hunk content");
      if (line.charAt(0) != '+') {
        old.append(line.substring(1));
        oldCount++;
      }
      if (line.charAt(0) != '-') {
        next.append(line.substring(1));
        newCount++;
      }
    }
    need(
        oldCount == Integer.parseInt(header.group(1))
            && newCount == Integer.parseInt(header.group(2)),
        "Patch hunk line counts differ");
    return new Images(old.toString(), next.toString());
  }

  ObjectNode apply(Path source, Path patch, Path workspace) throws Exception {
    Path target = target(source);
    byte[] before = read(target, true, MAX_DOWNLOAD);
    String text = new String(before, StandardCharsets.ISO_8859_1);
    Images images = images(read(patch, false, 1024 * 1024));
    int at = text.indexOf(images.oldImage);
    need(
        at >= 0 && text.indexOf(images.oldImage, at + images.oldImage.length()) < 0,
        "Patch requires exactly one full exact preimage");
    String expected =
        text.substring(0, at) + images.newImage + text.substring(at + images.oldImage.length());
    List<String> args =
        new ArrayList<>(
            List.of(
                "/usr/bin/patch",
                "--batch",
                "--forward",
                "--fuzz=0",
                "--no-backup-if-mismatch",
                "--reject-file=-",
                "-p1",
                "--directory=" + source,
                "--input=" + patch));
    List<String> dry = new ArrayList<>(args);
    dry.add("--dry-run");
    tool(dry, workspace, "patch-check.log", 0077);
    need(
        !Pattern.compile("fuzz|Reversed|previously applied|Skipping", Pattern.CASE_INSENSITIVE)
            .matcher(
                new String(
                    read(workspace.resolve("patch-check.log"), false, 64L * 1024 * 1024),
                    StandardCharsets.ISO_8859_1))
            .find(),
        "Patch dry run was not exact");
    target(source);
    need(Arrays.equals(before, read(target, true, MAX_DOWNLOAD)), "Target changed during dry run");
    tool(args, workspace, "patch-apply.log", 0077);
    target(source);
    byte[] after = read(target, true, MAX_DOWNLOAD);
    need(
        Arrays.equals(expected.getBytes(StandardCharsets.ISO_8859_1), after),
        "Patched target differs from exact expected postimage");
    return JSON.createObjectNode()
        .put("file", TARGET)
        .put("before_sha256", sha(before))
        .put("after_sha256", sha(after));
  }

  static void status(Path workspace, ObjectNode status) throws Exception {
    Path next = workspace.resolve("status.next.json");
    save(next, status);
    Files.move(
        next,
        workspace.resolve("status.json"),
        StandardCopyOption.REPLACE_EXISTING,
        StandardCopyOption.ATOMIC_MOVE);
  }

  Path prepare(Path parent) throws Exception {
    need(uid() != 0, "Run as a non-root user; do not use sudo");
    trustedTool(Path.of("/usr/bin/dpkg-source"));
    trustedTool(Path.of("/usr/bin/patch"));
    Inputs input = inputs();
    Path workspace = temporary(parent, "stargate-libc-source-");
    ObjectNode status =
        JSON.createObjectNode()
            .put("status", "incomplete")
            .put("stage", "download")
            .put("verification", "Git-pinned SHA256; no publisher signature verification claim")
            .put("patch_sha256", input.patchSha);
    ObjectNode artifacts = JSON.createObjectNode();
    status.set("artifacts", artifacts);
    try {
      status(workspace, status);
      bytes(workspace.resolve("backport.patch"), input.patch);
      List<String> errors = new ArrayList<>();
      List<String> names = new ArrayList<>(SOURCES);
      names.add(AUX);
      for (String name : names) {
        ObjectNode record =
            JSON.createObjectNode()
                .put("expected_sha256", input.hashes.get(name))
                .put("verified", false);
        artifacts.set(name, record);
        try {
          if (name.equals(AUX)) {
            need(errors.isEmpty(), "Auxiliary skipped: primary verification failed");
            verifyDsc(workspace.resolve(SOURCES.getFirst()), input.hashes);
          }
          downloader.download(name, workspace.resolve(name));
          String actual = sha(read(workspace.resolve(name), false, MAX_DOWNLOAD));
          record.put("actual_sha256", actual);
          need(actual.equals(input.hashes.get(name)), "SHA256 mismatch: " + name);
          need(
              !name.equals(AUX) || Files.size(workspace.resolve(name)) == AUX_SIZE,
              "Auxiliary signature size mismatch");
          record.put("verified", true);
        } catch (Exception error) {
          Cancellation.checkpoint();
          if (error instanceof InterruptedException
              || error.getCause() instanceof InterruptedException) throw error;
          record.put("error", error.toString());
          errors.add(error.toString());
        }
        status(workspace, status);
      }
      need(errors.isEmpty(), String.join("; ", errors));
      status.put("stage", "unpack");
      status(workspace, status);
      Path source = workspace.resolve("glibc-2.39");
      tool(
          List.of(
              "/usr/bin/dpkg-source",
              "--no-copy",
              "--no-overwrite-dir",
              "--require-strong-checksums",
              "--extract",
              workspace.resolve(SOURCES.getFirst()).toString(),
              source.toString()),
          workspace,
          "unpack.log",
          0022);
      permissions(source);
      status.put("stage", "patch");
      status(workspace, status);
      status.set("patched_target", apply(source, workspace.resolve("backport.patch"), workspace));
      permissions(source);
      status
          .put("status", "prepared")
          .put("stage", "complete")
          .put("source_directory", source.toString());
      status(workspace, status);
      return workspace;
    } catch (Exception error) {
      status.put("status", "incomplete").put("error", error.toString());
      try {
        status(workspace, status);
      } catch (Exception saved) {
        error.addSuppressed(saved);
      }
      throw new IOException(
          "Preparation incomplete; workspace retained at " + workspace + ": " + error, error);
    }
  }
}
