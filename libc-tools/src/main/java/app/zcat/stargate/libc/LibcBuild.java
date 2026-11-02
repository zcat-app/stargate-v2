/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static app.zcat.stargate.libc.LibcIO.*;

final class LibcBuild {
    static final List<String> DEPS = List.of("quilt", "autoconf", "debhelper", "texinfo", "xsltproc", "rdfind", "symlinks", "netbase", "gperf", "systemtap-sdt-dev", "libaudit-dev", "libcap-dev", "libselinux1-dev", "libgd-dev", "dpkg-dev", "xz-utils", "gettext");
    final LibcIO io;
    LibcBuild(LibcIO io) { this.io = io; }
    record Options(String builder, String image, String marker, Path output) { boolean fresh() { return builder != null; } }
    static void options(Options options) throws Exception {
        int count = (options.builder != null ? 1 : 0) + (options.image != null ? 1 : 0) + (options.marker != null ? 1 : 0) + (options.output != null ? 1 : 0);
        need(count == 0 || count == 4, "Fresh builder ID, expected image ID, builder marker and output directory are all required");
        if (count == 4) Ownership.freshArguments(options.builder, options.image, options.marker);
    }
    JsonNode verifyInputs(Target builder) throws Exception {
        JsonNode inputs = io.inputs();
        for (var entry : inputs.path("source_files_sha256").properties()) {
            String[] words = io.shell(builder, "sha256sum " + CHROOT + SRC + "/../" + entry.getKey()).strip().split("\\s+");
            need(words.length > 0 && words[0].equals(entry.getValue().asText()), "Source hash mismatch for " + entry.getKey());
        }
        need(sha(io.project.resolve("containers/native/patches/glibc-CVE-2026-18374.patch")).equals(inputs.path("patches").get(0).path("sha256").asText()), "Patch file does not match pinned SHA256");
        String marker = io.shell(builder, "grep -c \"CVE-2026-18374\" " + CHROOT + SRC + "/libio/fileops.c || true").strip();
        need(marker.matches("[0-9]+") && Long.parseLong(marker) > 0, "Pinned patch is not applied to unpacked source");
        String version = inputs.path("local_version").asText();
        need(version.matches("[A-Za-z0-9][A-Za-z0-9.+:~_-]*"), "Unsupported local version");
        return inputs;
    }
    static String preflightScript() {
        return "if test -e " + CHROOT + "/build/build.rc || test -e " + CHROOT + "/build/build.log || test -e " + CHROOT + SRC + "/stamp-dir || test -e " + CHROOT + SRC + "/build-tree; then echo dirty; else set -- " + CHROOT + "/build/*.deb; if test -e \"$1\"; then echo dirty; else echo clean; fi; fi";
    }
    void prependChangelog(Target builder, String version) throws Exception {
        String stamp = io.shell(builder, "chroot " + CHROOT + " date -R").strip();
        Result current = io.shellResult(builder, "cat " + CHROOT + SRC + "/debian/changelog");
        need(current.status() == 0, "Changelog read failed");
        if (current.text().contains("glibc (" + version + ")")) return;
        String stanza = "glibc (" + version + ") noble; urgency=medium\n\n  * Local Stargate backport build, not an Ubuntu release.\n  * Apply upstream commit 9765a538ebf8661a6e5578e01e35a3dd30db7eb4\n    fixing CVE-2026-18374 (heap buffer overflow in fopen ccs= handling).\n\n -- Stargate build <stargate@localhost>  " + stamp + "\n\n";
        byte[] prefix = stanza.getBytes(StandardCharsets.UTF_8), combined = Arrays.copyOf(prefix, prefix.length + current.stdout().length);
        System.arraycopy(current.stdout(), 0, combined, prefix.length, current.stdout().length);
        Result upload = io.exec(builder, combined, "/bin/sh", "-c", "cat > " + CHROOT + SRC + "/debian/changelog.new");
        need(upload.status() == 0, "Changelog update failed");
        io.shell(builder, "mv " + CHROOT + SRC + "/debian/changelog.new " + CHROOT + SRC + "/debian/changelog");
    }
    static String buildScript() { return "cd " + SRC + " && rm -f ../build.rc && (dpkg-buildpackage --no-pre-clean -us -uc -b -j4 > ../build.log 2>&1; echo $? > ../build.rc); true"; }
    static String pivotScript(String command) {
        return "mount --rbind " + CHROOT + " " + CHROOT + " && mkdir -p " + CHROOT + "/.old-build-root && cd " + CHROOT + " && pivot_root . .old-build-root && cd / && umount --lazy /.old-build-root && rmdir /.old-build-root && exec /bin/sh -c " + quote(command);
    }
    static String stampCleanup(boolean fresh) {
        String cleanup = "find " + CHROOT + SRC + "/stamp-dir -maxdepth 1 -type f \\( -name \"check_*\" -o -name \"binaryinst_*\" -o -name \"install_*\" -o -name \"debhelper*\" \\) -delete";
        return fresh ? "if test -d " + CHROOT + SRC + "/stamp-dir; then " + cleanup + "; fi" : cleanup;
    }
    void build(Target builder, String version, String image, boolean fresh) throws Exception {
        String existing = io.shellResult(builder, "cat " + CHROOT + "/build/build.rc 2>/dev/null || echo missing").text().strip();
        need(!fresh || existing.equals("missing"), "Fresh builder acquired existing build state; refusing reuse");
        if (!fresh && existing.equals("0") && !io.shellResult(builder, "ls " + CHROOT + "/build/libc6_" + version + "_amd64.deb 2>/dev/null").text().strip().isEmpty()) { System.out.println("Reusing completed dpkg-buildpackage run."); return; }
        long started = System.nanoTime();
        try (var environment = new Ownership.Helper(io, builder.id(), image)) {
            Target runner = environment.start();
            io.shell(runner, "chroot " + CHROOT + " apt-get update -qq");
            io.shell(runner, "chroot " + CHROOT + " apt-get install -y -qq " + String.join(" ", DEPS));
            io.shell(runner, "chroot " + CHROOT + " /bin/sh -c \"cd " + SRC + " && dh_prep\"");
            io.shell(runner, stampCleanup(fresh));
            io.shell(runner, "if test -f " + CHROOT + "/build/build.log; then cp " + CHROOT + "/build/build.log " + CHROOT + "/build/build-attempt-" + java.time.Instant.now().toEpochMilli() + ".log; fi");
            Result result = io.exec(runner, null, "unshare", "--mount", "--propagation", "private", "/bin/sh", "-c", pivotScript(buildScript()));
            need(result.status() == 0, "dpkg-buildpackage invocation failed");
        }
        String rc = io.shell(builder, "cat " + CHROOT + "/build/build.rc 2>/dev/null || echo missing").strip();
        String tail = io.shell(builder, "tail -40 " + CHROOT + "/build/build.log 2>/dev/null");
        System.out.println("build rc=" + rc + " elapsed=" + (System.nanoTime() - started) / 1_000_000_000L + "s\n" + tail);
        need(rc.equals("0"), "dpkg-buildpackage failed (rc=" + rc + "); full log: " + CHROOT + "/build/build.log");
    }
    void collect(Target builder, String version, Path output, boolean exclusive) throws Exception {
        Cancellation.checkpoint();
        for (Path current = output; current != null; current = current.getParent()) if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) need(Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS), "Package output parent is symbolic or not a directory");
        if (!exclusive) Files.createDirectories(output);
        if (!exclusive) Files.deleteIfExists(output.resolve("build-hashes.json"));
        Set<String> expected = new LinkedHashSet<>(List.of("libc6_" + version + "_amd64.deb", "libc-bin_" + version + "_amd64.deb", "libc6-dbg_" + version + "_amd64.deb"));
        ObjectNode hashes = JSON.createObjectNode();
        for (String containerPath : io.shell(builder, "ls " + CHROOT + "/build/*.deb").strip().split("\\s+")) {
            String name = containerPath.substring(containerPath.lastIndexOf('/') + 1);
            if (!expected.contains(name)) continue;
            need(containerPath.equals(CHROOT + "/build/" + name), "Unexpected package path: " + containerPath);
            Result fetched = io.shellResult(builder, "cat " + containerPath);
            need(fetched.status() == 0, "Failed to collect " + name);
            Path file = output.resolve(name);
            if (!exclusive && Files.exists(file, LinkOption.NOFOLLOW_LINKS)) need(Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS) && ((Number)Files.getAttribute(file, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() == 1, "Package output file is linked or not regular");
            Files.write(file, fetched.stdout(), exclusive ? new OpenOption[]{StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE} : new OpenOption[]{StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS});
            hashes.put(name, sha(fetched.stdout()));
        }
        need(hashes.size() == expected.size(), "Expected debs not produced: " + expected);
        ObjectNode metadata = JSON.createObjectNode().put("local_version", version).put("source_log", "dpkg-buildpackage output retained at /build/build.log in the build container"); metadata.set("debs", hashes);
        writeJson(output.resolve("build-hashes.json"), metadata, exclusive);
        hashes.properties().forEach(entry -> System.out.println(entry.getKey() + " sha256=" + entry.getValue().asText()));
    }
    void execute(Options options) throws Exception {
        options(options);
        String id, image;
        if (options.fresh()) { Ownership.fresh(io.inspect(options.builder), options.builder, options.image, options.marker); id = options.builder; image = options.image; }
        else {
            JsonNode data = io.inspect(BUILDER); id = data.path("Id").asText(); image = data.path("Image").asText();
            need(id.matches("[0-9a-f]{64}") && image.matches("sha256:[0-9a-f]{64}") && data.path("Name").asText().equals("/" + BUILDER) && data.path("State").path("Running").asBoolean(false), "Prepared builder identity or running state mismatch");
            need(Ownership.privateResources(data, true, Set.of("", "private"), false), "Prepared builder has host, shared or unexpected resources");
        }
        Target builder = new Target(id, false);
        Path output = options.fresh() ? privateOutput(options.output) : io.project.resolve("target/native");
        if (options.fresh()) { System.out.println("Fresh build output directory: " + output); need(io.shell(builder, preflightScript()).strip().equals("clean"), "Fresh builder contains existing build state; refusing reuse"); }
        JsonNode inputs = verifyInputs(builder);
        String version = inputs.path("local_version").asText();
        prependChangelog(builder, version);
        if (options.fresh()) Ownership.fresh(io.inspect(id), id, image, options.marker);
        build(builder, version, image, options.fresh());
        collect(builder, version, output, options.fresh());
    }
}
