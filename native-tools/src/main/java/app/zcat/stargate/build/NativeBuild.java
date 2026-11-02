/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.build;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.regex.Pattern;

/** Build-time only: native compilation and real regression tests stay in pinned Docker builders. */
public final class NativeBuild {
    static final ObjectMapper JSON = new ObjectMapper().enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    static final String I2P_COMMIT = "137dde2f433b2142eec7a2307608d7d082be086f";
    static final String I2P_ARCHIVE_SHA = "37c6e50c30841bed3d414ba9d6e910ee969596dd6f89723cefe7cfe764536cfb";
    static final String NYM_IMAGE = "stargate-v2-nym-builder:local";
    static final List<String> SHARED_TESTS = List.of(
        "immediate_reply_send_starts_retry_timers_for_every_fragment",
        "reordered_streams_remain_separate_and_close_in_order",
        "churn_and_unknown_late_replies_retain_no_inactive_state",
        "rejected_close_frames_do_not_poison_stream",
        "requester_still_buffers_before_connect_and_discards_after_close",
        "removed_and_stale_lanes_clear_published_lengths_without_touching_live_lanes");
    record Result(int status, String output) {}
    @FunctionalInterface interface Runner { Result run(Path cwd, List<String> command, boolean capture) throws Exception; }
    static final class Processes implements Runner {
        public Result run(Path cwd, List<String> command, boolean capture) throws Exception {
            ProcessBuilder process = new ProcessBuilder(command).directory(cwd.toFile());
            if (!capture) {
                int status = process.inheritIO().start().waitFor();
                return new Result(status, "");
            }
            Process child = process.redirectErrorStream(true).start();
            String output = new String(child.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
            return new Result(child.waitFor(), output);
        }
    }
    private final Path root;
    private final Runner runner;
    NativeBuild(Path root, Runner runner) { this.root = root.toAbsolutePath().normalize(); this.runner = runner; }

    public static void main(String[] args) {
        try {
            if (args.length == 1 && args[0].equals("--help")) { usage(); return; }
            if (args.length < 3 || !args[0].equals("--project")) throw new IllegalArgumentException("Expected --project ROOT i2p|nym");
            NativeBuild build = new NativeBuild(Path.of(args[1]), new Processes());
            int jobs = 4;
            Path work = Path.of("target/nym-build");
            for (int i = 3; i < args.length; i++) {
                if (args[i].equals("--help")) { usage(); return; }
                if (args[2].equals("nym") && args[i].equals("--jobs") && i + 1 < args.length) jobs = Integer.parseInt(args[++i]);
                else if (args[2].equals("nym") && args[i].equals("--work-dir") && i + 1 < args.length) work = Path.of(args[++i]);
                else throw new IllegalArgumentException("Unknown or incomplete argument: " + args[i]);
            }
            if (args[2].equals("i2p")) build.i2p();
            else if (args[2].equals("nym")) { require(jobs >= 1 && jobs <= 16, "jobs must be 1–16"); build.nym(work.toAbsolutePath().normalize(), jobs); }
            else throw new IllegalArgumentException("Unknown build: " + args[2]);
        } catch (Exception failure) { System.err.println("Native build failed: " + failure.getMessage()); System.exit(1); }
    }
    private static void usage() { System.out.println("Usage: java -jar native-tools.jar --project ROOT i2p|nym [--jobs 1..16] [--work-dir PATH]\nI2P uses ROOT/target/i2p-isolation-build; Nym defaults to ./target/nym-build."); }
    static void require(boolean ok, String message) throws IOException { if (!ok) throw new IOException(message); }
    static String sha(Path path) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (var input = Files.newInputStream(path)) {
            byte[] buffer = new byte[64 * 1024];
            for (int count; (count = input.read(buffer)) != -1;) digest.update(buffer, 0, count);
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private JsonNode json(String relative) throws IOException { return JSON.readTree(root.resolve(relative).toFile()); }
    String output(Path cwd, String... args) throws Exception {
        return rawOutput(cwd, args).strip();
    }
    private String rawOutput(Path cwd, String... args) throws Exception {
        Result result = runner.run(cwd, List.of(args), true);
        require(result.status == 0, "Command failed (" + result.status + "): " + String.join(" ", args) + "\n" + result.output);
        return result.output;
    }
    private void run(Path cwd, String... args) throws Exception {
        Result result = runner.run(cwd, List.of(args), false);
        require(result.status == 0, "Command failed (" + result.status + "): " + String.join(" ", args));
    }
    private String identity() throws Exception { return output(root, "id", "-u") + ":" + output(root, "id", "-g"); }
    static Path inputPath(Path source, String relative) throws IOException {
        Path path = source.resolve(relative).normalize();
        require(!Path.of(relative).isAbsolute() && path.startsWith(source.normalize()), "Source path escapes source tree: " + relative);
        Path current = path;
        while (current != null && current.startsWith(source)) {
            require(!Files.isSymbolicLink(current), "Symbolic source input: " + current); current = current.getParent();
        }
        return path;
    }
    static boolean sourceHashesMatch(Path source, JsonNode hashes) throws Exception {
        for (var entry : hashes.properties()) {
            Path file = inputPath(source, entry.getKey());
            if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) || !sha(file).equals(entry.getValue().asText())) return false;
        }
        return true;
    }
    static void compareTree(Path expected, Path actual) throws Exception {
        require(Files.isDirectory(expected, LinkOption.NOFOLLOW_LINKS), "Missing or symbolic expected source directory: " + expected);
        require(Files.isDirectory(actual, LinkOption.NOFOLLOW_LINKS), "Missing or symbolic source directory: " + actual);
        try (var paths = Files.walk(expected)) {
            for (Path file : paths.toList()) {
                if (!Files.isRegularFile(file)) continue;
                String relative = expected.relativize(file).toString();
                Path candidate = actual.resolve(relative);
                // Pinned archives contain internal file symlinks. Permit the exact declared
                // link (or a byte-identical regular copy), never a substituted source link.
                if (Files.isSymbolicLink(file)) {
                    require(file.toRealPath().startsWith(expected.toRealPath()), "Expected source link escapes source tree: " + relative);
                    if (Files.isSymbolicLink(candidate)) {
                        Path parent = Path.of(relative).getParent();
                        inputPath(actual, parent == null ? "." : parent.toString());
                        require(Files.readSymbolicLink(file).equals(Files.readSymbolicLink(candidate)) && candidate.toRealPath().startsWith(actual.toRealPath()), "Unexpected source link: " + relative);
                    } else inputPath(actual, relative);
                } else inputPath(actual, relative);
                require(Files.isRegularFile(candidate) && Files.mismatch(file, candidate) == -1,
                    "Unexpected source change: " + relative);
            }
        }
    }
    private static void copyTree(Path source, Path destination) throws IOException {
        try (var paths = Files.walk(source)) {
            for (Path from : paths.toList()) {
                Path to = destination.resolve(source.relativize(from));
                if (Files.isDirectory(from)) Files.createDirectories(to);
                else Files.copy(from, to, StandardCopyOption.COPY_ATTRIBUTES);
            }
        }
    }
    private static void deleteTree(Path path) throws IOException {
        try (var paths = Files.walk(path)) { for (Path file : paths.sorted(Comparator.reverseOrder()).toList()) Files.delete(file); }
    }
    private static void writeRecord(Path work, ObjectNode record) throws IOException {
        String value = JSON.writerWithDefaultPrettyPrinter().writeValueAsString(record) + "\n";
        Path temporary = Files.createTempFile(work, "build-record-", ".json");
        try { Files.writeString(temporary, value); Files.move(temporary, work.resolve("build-record.json"), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE); }
        finally { Files.deleteIfExists(temporary); }
        System.out.print(value);
    }
    void i2p() throws Exception {
        Path work = root.resolve("target/i2p-isolation-build");
        Files.createDirectories(work);
        Files.deleteIfExists(work.resolve("build-record.json"));
        Path archive = work.resolve("source.tar.gz");
        if (!Files.exists(archive)) {
            Path partial = Files.createTempFile(work, "source-", ".partial");
            try (HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).followRedirects(HttpClient.Redirect.NORMAL).build()) {
                var response = client.send(HttpRequest.newBuilder(URI.create("https://codeload.github.com/PurpleI2P/i2pd/tar.gz/" + I2P_COMMIT)).timeout(Duration.ofSeconds(60)).build(), HttpResponse.BodyHandlers.ofFile(partial));
                require(response.statusCode() == 200 && sha(partial).equals(I2P_ARCHIVE_SHA), "Source checksum mismatch or download failure");
                Files.move(partial, archive);
            } finally { Files.deleteIfExists(partial); }
        }
        require(sha(archive).equals(I2P_ARCHIVE_SHA), "Source checksum mismatch");
        Path source = work.resolve("i2pd-" + I2P_COMMIT);
        Path inputs = root.resolve("containers/i2p"), patch = inputs.resolve("identity-fail-closed.patch");
        Path temporary = Files.createTempDirectory(work, "verified-source-");
        try {
            run(root, "tar", "-xzf", archive.toString(), "--no-same-owner", "--no-same-permissions", "-C", temporary.toString());
            Path expected = temporary.resolve(source.getFileName());
            run(expected, "patch", "-p1", "--batch", "--input", patch.toString());
            run(expected, "patch", "-p1", "--batch", "--input", inputs.resolve("lifecycle-ack.patch").toString());
            if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) copyTree(expected, source);
            compareTree(expected, source);
        } finally { deleteTree(temporary); }
        run(root, "docker", "build", "-f", inputs.resolve("Dockerfile.builder").toString(), "-t", "stargate-v2-i2p-builder:local", root.toString());
        run(root, i2pCommand(source, inputs, work, identity()).toArray(String[]::new));
        JsonNode builder = JSON.readTree(output(root, "docker", "image", "inspect", "stargate-v2-i2p-builder:local"));
        ObjectNode record = JSON.createObjectNode();
        record.put("sourceCommit", I2P_COMMIT).put("sourceArchiveSha256", I2P_ARCHIVE_SHA)
            .put("patchSha256", sha(patch)).put("lifecyclePatchSha256", sha(inputs.resolve("lifecycle-ack.patch")))
            .put("ownerSourceSha256", sha(inputs.resolve("owner.c"))).put("binarySha256", sha(source.resolve("i2pd")))
            .put("ownerBinarySha256", sha(work.resolve("stargate-i2p-owner"))).put("builderImage", builder.get(0).get("Id").asText())
            .put("builderDockerfileSha256", sha(inputs.resolve("Dockerfile.builder")))
            .put("runtime", "Existing separately verified patched libc and runtime libraries; only the I2P executable is replaced.");
        writeRecord(work, record);
    }
    static List<String> i2pCommand(Path source, Path inputs, Path work, String identity) {
        return List.of("docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", identity,
            "-v", source + ":/source", "-v", inputs + ":/inputs:ro", "-v", work + ":/output", "stargate-v2-i2p-builder:local", "sh", "-ec",
            "make -j2 DEBUG=no USE_UPNP=yes; cc -std=c11 -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=3 -Wl,-z,relro,-z,now /inputs/owner.c -o /output/stargate-i2p-owner");
    }
    static List<String> nymCommand(Path source, Path cache, String identity) {
        return List.of("docker", "run", "--rm", "--user", identity, "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "-v", source + ":/src", "-v", cache + ":/cargo-cache", "-e", "CARGO_HOME=/cargo-cache", "-w", "/src", NYM_IMAGE);
    }
    static List<String> append(List<String> prefix, String... suffix) { List<String> args = new ArrayList<>(prefix); args.addAll(List.of(suffix)); return args; }
    String regression(Path work, String log, List<String> command) throws Exception {
        Result result = runner.run(root, command, true);
        System.out.print(result.output);
        Files.writeString(work.resolve(log), result.output);
        require(result.status == 0, "Regression command failed (" + result.status + "); see " + work.resolve(log));
        return result.output;
    }
    static void requireTests(String output, List<String> names, String message) throws IOException {
        for (String name : names) {
            // Match actual Rust test-runner result lines, not echoed commands or zero-test summaries.
            String prefix = name.contains("::") ? "" : "(?:[A-Za-z0-9_:]+::)?";
            Pattern line = Pattern.compile("(?m)^test " + prefix + Pattern.quote(name) + " \\.\\.\\. ok\\r?$");
            require(line.matcher(output).find(), message + ": " + name);
        }
    }
    void nym(Path work, int jobs) throws Exception {
        require(jobs >= 1 && jobs <= 16, "jobs must be 1–16");
        Files.createDirectories(work);
        Files.deleteIfExists(work.resolve("build-record.json"));
        Path source = work.resolve("source"), cache = work.resolve("cache");
        Files.createDirectories(cache);
        JsonNode manifest = json("containers/nym/security-build.json"), release = json("containers/nym-release.json");
        JsonNode lifecycle = json("containers/nym/lifecycle-build.json"), shared = json("containers/nym/shared-client-build.json");
        Path patch = root.resolve("containers/nym/security-dependencies.patch"), lifecyclePatch = root.resolve("containers/nym/lifecycle.patch"), sharedPatch = root.resolve("containers/nym/shared-client.patch");
        require(shared.path("sourceCommit").asText().equals(manifest.path("sourceCommit").asText()) && sha(sharedPatch).equals(shared.path("patchSha256").asText()), "Nym shared-client input mismatch");
        require(lifecycle.path("sourceCommit").asText().equals(manifest.path("sourceCommit").asText()) && sha(lifecyclePatch).equals(lifecycle.path("patchSha256").asText()), "Nym lifecycle input mismatch");
        require(sha(patch).equals(manifest.path("patchSha256").asText()), "Nym patch checksum mismatch");
        if (!Files.exists(source)) run(root, "git", "clone", "--depth", "1", "--single-branch", "--branch", release.path("tag").asText(), "https://github.com/nymtech/nym.git", source.toString());
        require(output(root, "git", "-C", source.toString(), "rev-parse", "HEAD").equals(manifest.path("sourceCommit").asText()), "Nym source commit mismatch");
        verifyChangedSources(source, lifecycle.path("sourceSha256"), shared.path("sourceSha256"));
        if (!sha(inputPath(source, "Cargo.lock")).equals(manifest.path("cargoLockSha256").asText())) run(root, "git", "-C", source.toString(), "apply", patch.toString());
        require(sha(inputPath(source, "Cargo.lock")).equals(manifest.path("cargoLockSha256").asText()), "Nym lock checksum mismatch");
        if (!sourceHashesMatch(source, lifecycle.path("sourceSha256"))) run(root, "git", "-C", source.toString(), "apply", lifecyclePatch.toString());
        require(sourceHashesMatch(source, lifecycle.path("sourceSha256")), "Nym lifecycle source mismatch");
        if (!sourceHashesMatch(source, shared.path("sourceSha256"))) run(root, "git", "-C", source.toString(), "apply", sharedPatch.toString());
        require(sourceHashesMatch(source, shared.path("sourceSha256")), "Nym shared-client source mismatch");
        Path context = work.resolve("builder-context"); Files.createDirectories(context);
        run(root, "docker", "build", "-f", root.resolve("containers/Dockerfile.nym-builder").toString(), "-t", NYM_IMAGE, context.toString());
        List<String> command = nymCommand(source, cache, identity());
        run(root, append(command, "cargo", "build", "--locked", "--release", "-p", "nym-socks5-client", "-j", String.valueOf(jobs)).toArray(String[]::new));
        String sharedOutput = regression(work, "shared-client-tests.log", sharedCommand(command, jobs));
        requireTests(sharedOutput, SHARED_TESTS, "Expected shared-client regressions did not run");
        Path verifier = findVerifier(cache), testSource = work.resolve("webpki-tests");
        if (!Files.exists(testSource)) {
            run(root, "git", "init", testSource.toString());
            run(root, "git", "-C", testSource.toString(), "remote", "add", "origin", "https://github.com/rustls/webpki.git");
            run(root, "git", "-C", testSource.toString(), "fetch", "--depth", "1", "origin", manifest.path("verifierTestCommit").asText());
            run(root, "git", "-C", testSource.toString(), "checkout", "--detach", "FETCH_HEAD");
        }
        require(output(root, "git", "-C", testSource.toString(), "rev-parse", "HEAD").equals(manifest.path("verifierTestCommit").asText()) && output(root, "git", "-C", testSource.toString(), "status", "--porcelain").isEmpty(), "Unexpected verifier regression source");
        compareTree(verifier.resolve("src"), testSource.resolve("src"));
        String tested = regression(work, "tls-regression.log", verifierCommand(command, testSource, jobs));
        requireTests(tested, List.of("verify_cert::tests::distrusted_spki"), "Expected TLS distrust regression did not run");
        Path binary = source.resolve("target/release/nym-socks5-client");
        require(!contains(binary, "emSign ECC Root CA - G3".getBytes(StandardCharsets.UTF_8)), "Distrusted emSign root remains in binary");
        ObjectNode record = JSON.createObjectNode();
        record.put("sourceCommit", manifest.path("sourceCommit").asText()).put("patchSha256", sha(patch)).put("lifecyclePatchSha256", sha(lifecyclePatch));
        record.set("lifecycleSourceSha256", lifecycle.path("sourceSha256"));
        record.put("sharedClientPatchSha256", sha(sharedPatch)); record.set("sharedClientSourceSha256", shared.path("sourceSha256"));
        record.put("sharedClientRegressionPassed", true).put("cargoLockSha256", sha(source.resolve("Cargo.lock"))).put("binarySha256", sha(binary))
            .put("builderImage", output(root, "docker", "image", "inspect", "--format", "{{.Id}}", NYM_IMAGE)).put("builderBase", manifest.path("builderBase").asText())
            .put("verifierTestCommit", manifest.path("verifierTestCommit").asText()).put("verifierRegressionPassed", true);
        record.set("buildInfo", JSON.readTree(output(root, binary.toString(), "build-info", "--output", "json")));
        writeRecord(work, record);
    }
    void verifyChangedSources(Path source, JsonNode lifecycle, JsonNode shared) throws Exception {
        Set<String> allowed = new HashSet<>(List.of("Cargo.lock"));
        lifecycle.fieldNames().forEachRemaining(allowed::add); shared.fieldNames().forEachRemaining(allowed::add);
        // -z preserves unusual path bytes rather than trusting Git's quoted display format.
        String changed = rawOutput(root, "git", "-C", source.toString(), "diff", "HEAD", "--name-only", "-z");
        for (String name : changed.split("\u0000")) require(name.isEmpty() || allowed.contains(name), "Unexpected Nym source edits: " + name);
        require(rawOutput(root, "git", "-C", source.toString(), "ls-files", "--others", "--exclude-standard", "-z").isEmpty(), "Unexpected untracked Nym source inputs");
    }
    static List<String> sharedCommand(List<String> command, int jobs) {
        return append(command, "cargo", "test", "--locked", "--release", "-p", "nym-socks5-proxy-helpers", "-p", "nym-client-core", "--lib", "shared_client_tests", "-j", String.valueOf(jobs));
    }
    static List<String> verifierCommand(List<String> command, Path testSource, int jobs) {
        List<String> test = new ArrayList<>(command.subList(0, command.indexOf(NYM_IMAGE)));
        test.addAll(List.of("-v", testSource + ":/verifier", NYM_IMAGE));
        return append(test, "cargo", "test", "--manifest-path", "/verifier/Cargo.toml", "--target-dir", "/src/target", "--locked", "--release", "--features", "ring", "--lib", "distrusted_spki", "-j", String.valueOf(jobs));
    }
    static Path findVerifier(Path cache) throws IOException {
        Path registry = cache.resolve("registry/src");
        try (var entries = Files.list(registry)) {
            List<Path> matches = entries.map(path -> path.resolve("rustls-webpki-0.103.16")).filter(Files::isDirectory).toList();
            require(matches.size() == 1, "Expected exactly one shipped rustls-webpki-0.103.16 source");
            return matches.getFirst();
        }
    }
    static boolean contains(Path file, byte[] needle) throws IOException {
        try (var input = new BufferedInputStream(Files.newInputStream(file))) {
            int matched = 0;
            for (int value; (value = input.read()) != -1;) {
                if (value == (needle[matched] & 0xff)) { if (++matched == needle.length) return true; }
                else matched = value == (needle[0] & 0xff) ? 1 : 0;
            }
        }
        return false;
    }
}
