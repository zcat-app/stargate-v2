/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;

final class LibcIO {
    static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    static final String BUILDER = "stargate-v2-libc-build", TEST_BUILDER = "stargate-v2-libc-check";
    static final String CHROOT = "/work/root", SRC = "/build/glibc-2.39";
    record Result(int status, byte[] stdout, byte[] stderr) {
        String text() { return new String(stdout, StandardCharsets.UTF_8); }
        String error() { return new String(stderr, StandardCharsets.UTF_8); }
        static Result text(int status, String text) { return new Result(status, text.getBytes(StandardCharsets.UTF_8), new byte[0]); }
    }
    interface Runner {
        Result run(List<String> command, byte[] input, Duration timeout) throws Exception;
        default void pipeline(List<String> first, List<String> second) throws Exception { throw new IOException("Streaming pipeline not implemented"); }
    }
    static final class Processes implements Runner {
        public Result run(List<String> command, byte[] input, Duration timeout) throws Exception {
            return LocalProcesses.run(command, input, timeout);
        }
        public void pipeline(List<String> first, List<String> second) throws Exception {
            LocalProcesses.pipeline(first, second);
        }
    }
    record Target(String id, boolean namespace) {}
    final Path project;
    final Runner runner;
    LibcIO(Path project, Runner runner) { this.project = project.toAbsolutePath().normalize(); this.runner = runner; }
    static void need(boolean value, String message) throws IOException { if (!value) throw new IOException(message); }
    static String quote(String text) { return "'" + text.replace("'", "'\\''") + "'"; }
    static List<String> names(JsonNode object) { List<String> names = new ArrayList<>(); object.fieldNames().forEachRemaining(names::add); return names; }
    static String sha(byte[] data) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data)); }
    static String sha(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) { byte[] buffer = new byte[65536]; for (int n; (n = input.read(buffer)) != -1;) digest.update(buffer, 0, n); }
        return HexFormat.of().formatHex(digest.digest());
    }
    JsonNode inputs() throws Exception {
        JsonNode input = JSON.readTree(project.resolve("containers/native/glibc-inputs.json").toFile());
        JsonNode sources = input.path("source_files_sha256");
        need(sources.isObject() && !sources.isEmpty(), "Unsupported source manifest");
        for (var field : sources.properties()) need(field.getKey().matches("[A-Za-z0-9][A-Za-z0-9._+~-]*") && !field.getKey().contains("..") && field.getValue().isTextual() && field.getValue().asText().matches("[0-9a-f]{64}"), "Unsupported source manifest");
        need(input.path("patches").isArray() && !input.path("patches").isEmpty() && input.path("patches").get(0).path("sha256").asText().matches("[0-9a-f]{64}"), "Unsupported patch manifest");
        return input;
    }
    Result command(List<String> command) throws Exception { Cancellation.checkpoint(); return runner.run(command, null, null); }
    Result checked(List<String> command) throws Exception { Result result = command(command); need(result.status == 0, "Command failed (" + result.status + "): " + command + "\n" + result.error()); return result; }
    static List<String> execCommand(Target target, String... arguments) {
        List<String> command = new ArrayList<>(List.of("docker", "exec", "-i", target.id));
        if (target.namespace) command.addAll(List.of("nsenter", "--target", "1", "--mount", "--root", "--wd"));
        command.addAll(List.of(arguments)); return command;
    }
    Result exec(Target target, byte[] input, String... arguments) throws Exception { Cancellation.checkpoint(); return runner.run(execCommand(target, arguments), input, null); }
    Result shellResult(Target target, String script) throws Exception { return exec(target, null, "/bin/sh", "-c", script); }
    String shell(Target target, String script) throws Exception {
        Result result = shellResult(target, script); need(result.status == 0, "Container command failed (" + result.status + "): " + script + "\n" + result.error()); return result.text();
    }
    JsonNode inspect(String id) throws Exception {
        JsonNode rows = JSON.readTree(checked(List.of("docker", "inspect", "--type", "container", id)).stdout);
        need(rows.isArray() && rows.size() == 1 && rows.get(0).isObject(), "Container identity inspection is ambiguous"); return rows.get(0);
    }
    static Path privateOutput(Path output) throws Exception {
        need(output.isAbsolute() && output.getFileName() != null, "Output directory must be a new absolute path");
        for (Path part : output) need(!part.toString().equals("..") && !part.toString().equals("."), "Output path contains dot components");
        for (Path parent = output.getParent(); parent != null; parent = parent.getParent()) need(Files.isDirectory(parent, LinkOption.NOFOLLOW_LINKS), "Output parent contains a symlink or non-directory");
        return Files.createDirectory(output, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    static void writeJson(Path path, JsonNode value, boolean exclusive) throws IOException {
        Cancellation.checkpoint();
        Files.writeString(path, JSON.writerWithDefaultPrettyPrinter().writeValueAsString(value) + "\n", exclusive ? new OpenOption[]{StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE} : new OpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE});
    }
}
