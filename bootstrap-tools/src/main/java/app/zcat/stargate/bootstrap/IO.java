/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.security.*;
import java.util.*;

final class IO {
  static final ObjectMapper JSON =
      new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
  static final Map<String, String> TOOL_ENV = Map.of("PATH", "/usr/bin:/bin", "LC_ALL", "C");

  static void need(boolean value, String message) throws IOException {
    if (!value) throw new IOException(message);
  }

  static int uid() throws IOException {
    for (String line : Files.readAllLines(Path.of("/proc/self/status")))
      if (line.startsWith("Uid:")) return Integer.parseInt(line.strip().split("\\s+")[2]);
    throw new IOException("Effective UID unavailable");
  }

  static Map<String, Object> info(Path path) throws IOException {
    return Files.readAttributes(
        path, "unix:mode,uid,nlink,size,ino,dev", LinkOption.NOFOLLOW_LINKS);
  }

  static int mode(Path path) throws IOException {
    return ((Number) info(path).get("mode")).intValue() & 07777;
  }

  static void regular(Path path, boolean singleLink) throws IOException {
    var data = info(path);
    int mode = ((Number) data.get("mode")).intValue();
    need(
        (mode & 0170000) == 0100000
            && (!singleLink || ((Number) data.get("nlink")).longValue() == 1),
        "Regular" + (singleLink ? " single-link" : "") + " file required: " + path);
  }

  static byte[] read(Path path, boolean singleLink, long max) throws Exception {
    Cancellation.checkpoint();
    try (NativeInput input = new NativeInput(path, singleLink)) {
      var before = input.info();
      need(((Number) before.get("size")).longValue() <= max, "File size limit exceeded: " + path);
      var output = new ByteArrayOutputStream();
      byte[] buffer = new byte[65536];
      long size = 0;
      for (int n; (n = input.read(buffer)) != -1; ) {
        size += n;
        need(size <= max, "Input size limit exceeded");
        output.write(buffer, 0, n);
      }
      input.check();
      need(
          Objects.equals(before.get("size"), input.info().get("size")),
          "Opened input size changed: " + path);
      return output.toByteArray();
    }
  }

  static byte[] limited(InputStream input, long max) throws IOException {
    var output = new ByteArrayOutputStream();
    byte[] buffer = new byte[65536];
    long size = 0;
    for (int n; (n = input.read(buffer)) != -1; ) {
      size += n;
      need(size <= max, "Input size limit exceeded");
      output.write(buffer, 0, n);
    }
    return output.toByteArray();
  }

  static String sha(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  static String sha(Path path) throws Exception {
    Cancellation.checkpoint();
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    try (NativeInput input = new NativeInput(path, true)) {
      var before = input.info();
      byte[] buffer = new byte[65536];
      for (int n; (n = input.read(buffer)) != -1; ) digest.update(buffer, 0, n);
      input.check();
      need(
          Objects.equals(before.get("size"), input.info().get("size")),
          "Opened input size changed: " + path);
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  static Path directory(Path path) throws Exception {
    need(
        path.isAbsolute() && path.equals(path.normalize()),
        "Absolute normalized directory required");
    for (Path current = path; current != null; current = current.getParent())
      need(
          Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS),
          "Directory contains symbolic or non-directory component: " + current);
    return path;
  }

  static Path privateDirectory(Path path) throws Exception {
    need(
        path.isAbsolute() && path.getFileName() != null && path.equals(path.normalize()),
        "New absolute directory required");
    directory(path.getParent());
    Files.createDirectory(
        path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    syncDirectory(path.getParent());
    return path;
  }

  static Path temporary(Path parent, String prefix) throws Exception {
    return Files.createTempDirectory(
        directory(parent.toAbsolutePath().normalize()),
        prefix,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
  }

  static FileChannel create(Path path) throws IOException {
    Path absolute = path.toAbsolutePath();
    try (NativeDirectory parent = NativeDirectory.open(absolute.getParent())) {
      return parent.create(absolute.getFileName().toString());
    }
  }

  static void write(FileChannel channel, byte[] bytes) throws IOException {
    ByteBuffer buffer = ByteBuffer.wrap(bytes);
    while (buffer.hasRemaining()) need(channel.write(buffer) > 0, "Short file write");
  }

  static void save(Path path, JsonNode data) throws Exception {
    try (FileChannel channel = create(path)) {
      write(
          channel,
          (JSON.writerWithDefaultPrettyPrinter().writeValueAsString(data) + "\n")
              .getBytes(StandardCharsets.UTF_8));
      channel.force(true);
    }
  }

  static void bytes(Path path, byte[] bytes) throws IOException {
    try (FileChannel channel = create(path)) {
      write(channel, bytes);
      channel.force(true);
    }
  }

  static void syncDirectory(Path path) throws IOException {
    try (NativeDirectory directory = NativeDirectory.open(path)) {
      directory.force(true);
    }
  }

  static String token() {
    byte[] data = new byte[16];
    new SecureRandom().nextBytes(data);
    return HexFormat.of().formatHex(data);
  }

  static JsonNode json(Path path) throws Exception {
    return JSON.readTree(read(path, true, 16L * 1024 * 1024));
  }

  static List<String> names(JsonNode object) {
    List<String> values = new ArrayList<>();
    object.fieldNames().forEachRemaining(values::add);
    return values;
  }

  static boolean empty(JsonNode value) {
    return value.isMissingNode()
        || value.isNull()
        || (value.isContainerNode() && value.isEmpty())
        || (value.isTextual() && value.asText().isEmpty())
        || (value.isBoolean() && !value.asBoolean());
  }

  static boolean text(JsonNode value, String expected) {
    return value.isTextual() && value.asText().equals(expected);
  }

  static boolean bool(JsonNode value, boolean expected) {
    return value.isBoolean() && value.asBoolean() == expected;
  }

  static String canonical(JsonNode value) {
    if (value.isObject()) {
      List<String> fields = names(value);
      fields.sort((a, b) -> Arrays.compare(a.codePoints().toArray(), b.codePoints().toArray()));
      List<String> parts = new ArrayList<>();
      for (String field : fields) parts.add(quoted(field) + ":" + canonical(value.get(field)));
      return "{" + String.join(",", parts) + "}";
    }
    if (value.isArray()) {
      List<String> parts = new ArrayList<>();
      for (JsonNode item : value) parts.add(canonical(item));
      return "[" + String.join(",", parts) + "]";
    }
    if (value.isTextual()) return quoted(value.asText());
    return value.toString();
  }

  static String quoted(String value) {
    StringBuilder out = new StringBuilder("\"");
    for (char c : value.toCharArray())
      switch (c) {
        case '"' -> out.append("\\\"");
        case '\\' -> out.append("\\\\");
        case '\b' -> out.append("\\b");
        case '\f' -> out.append("\\f");
        case '\n' -> out.append("\\n");
        case '\r' -> out.append("\\r");
        case '\t' -> out.append("\\t");
        default -> {
          if (c < 32 || c > 126) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
          else out.append(c);
        }
      }
    return out.append('"').toString();
  }

  static String canonicalSha(JsonNode value) throws Exception {
    return sha(canonical(value).getBytes(StandardCharsets.US_ASCII));
  }

  static void trustedTool(Path path) throws Exception {
    var data = Files.readAttributes(path, "unix:mode,uid");
    int mode = ((Number) data.get("mode")).intValue();
    need(
        (mode & 0170000) == 0100000
            && ((Number) data.get("uid")).intValue() == 0
            && (mode & 0022) == 0
            && Files.isExecutable(path),
        "Trusted system tool required: " + path);
  }
}
