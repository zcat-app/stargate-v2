/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedExecutor.object;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

final class BuilderBootstrap {
  static final String LABEL = "org.stargate.libc.fresh-builder";
  static final String COPY =
      "tar -C / --one-file-system --numeric-owner --xattrs --xattrs-include=\"*\" --acls"
          + " --exclude=./work --exclude=./proc --exclude=./dev --exclude=./sys --exclude=./tmp"
          + " --exclude=./run --exclude=./etc/resolv.conf --exclude=./etc/hosts"
          + " --exclude=./etc/hostname -cpf - . | tar -C /work/root --numeric-owner --xattrs"
          + " --xattrs-include=\"*\" --acls -xpf -";
  static final String SETUP =
      "mkdir -p /work/root/proc /work/root/sys /work/root/dev/pts /work/root/dev/shm /work/root/tmp"
          + " /work/root/run /work/root/work && chmod 1777 /work/root/tmp && mknod -m 666"
          + " /work/root/dev/null c 1 3 && mknod -m 666 /work/root/dev/zero c 1 5 && mknod -m 666"
          + " /work/root/dev/random c 1 8 && mknod -m 666 /work/root/dev/urandom c 1 9 && printf"
          + " '127.0.0.1 localhost\\n"
          + "::1 localhost\\n"
          + "' > /work/root/etc/hosts && printf 'stargate-libc-fresh\\n"
          + "' > /work/root/etc/hostname";
  static final String PREFLIGHT =
      "if test -e /work/root/build/build.rc || test -e /work/root/build/build.log || test -e"
          + " /work/root/build/glibc-2.39/stamp-dir || test -e"
          + " /work/root/build/glibc-2.39/build-tree; then echo dirty; else set --"
          + " /work/root/build/*.deb; if test -e \"$1\"; then echo dirty; else echo clean; fi; fi";

  static String ipv4(String value) throws Exception {
    String[] fields = value.split("\\.", -1);
    need(fields.length == 4, "Invalid numeric DNS");
    for (String field : fields)
      need(
          field.matches("0|[1-9][0-9]{0,2}") && Integer.parseInt(field) <= 255,
          "Invalid numeric DNS");
    int first = Integer.parseInt(fields[0]), second = Integer.parseInt(fields[1]);
    need(
        !(first >= 224 && first <= 239)
            && !value.equals("0.0.0.0")
            && !(first == 169 && second == 254)
            && (first != 127 || value.equals("127.0.0.11")),
        "Unusable DNS");
    return value;
  }

  static List<Integer> groups(String value) throws Exception {
    List<Integer> groups = new ArrayList<>();
    if (value.isEmpty()) return groups;
    for (String field : value.split(":", -1)) {
      need(field.matches("[0-9a-fA-F]{1,4}"), "Invalid numeric DNS");
      groups.add(Integer.parseInt(field, 16));
    }
    return groups;
  }

  static String ipv6(String value) throws Exception {
    need(value.matches("[0-9a-fA-F:.]+") && value.contains(":"), "Invalid numeric DNS");
    if (value.contains(".")) {
      int at = value.lastIndexOf(':');
      String tail = value.substring(at + 1);
      String[] parts = tail.split("\\.", -1);
      need(parts.length == 4, "Invalid numeric DNS");
      for (String part : parts)
        need(
            part.matches("0|[1-9][0-9]{0,2}") && Integer.parseInt(part) <= 255,
            "Invalid numeric DNS");
      value =
          value.substring(0, at + 1)
              + Integer.toHexString(Integer.parseInt(parts[0]) * 256 + Integer.parseInt(parts[1]))
              + ":"
              + Integer.toHexString(Integer.parseInt(parts[2]) * 256 + Integer.parseInt(parts[3]));
    }
    int at = value.indexOf("::");
    need(at < 0 || value.indexOf("::", at + 2) < 0, "Invalid numeric DNS");
    List<Integer> left = groups(at < 0 ? value : value.substring(0, at)),
        right = at < 0 ? List.of() : groups(value.substring(at + 2));
    need(at < 0 ? left.size() == 8 : left.size() + right.size() < 8, "Invalid numeric DNS");
    List<Integer> all = new ArrayList<>(left);
    if (at >= 0) while (all.size() + right.size() < 8) all.add(0);
    all.addAll(right);
    need(
        (all.getFirst() & 0xff00) != 0xff00
            && (all.getFirst() & 0xffc0) != 0xfe80
            && all.stream().anyMatch(n -> n != 0)
            && !(all.subList(0, 7).stream().allMatch(n -> n == 0) && all.getLast() == 1),
        "Unusable DNS");
    int start = -1, length = 0;
    for (int i = 0; i < 8; ) {
      if (all.get(i) != 0) {
        i++;
        continue;
      }
      int end = i;
      while (end < 8 && all.get(end) == 0) end++;
      if (end - i >= 2 && end - i > length) {
        start = i;
        length = end - i;
      }
      i = end;
    }
    List<String> hex = all.stream().map(Integer::toHexString).toList();
    return start < 0
        ? String.join(":", hex)
        : String.join(":", hex.subList(0, start))
            + "::"
            + String.join(":", hex.subList(start + length, 8));
  }

  static byte[] dns(byte[] bytes) throws Exception {
    for (byte value : bytes) need((value & 255) < 128, "Invalid numeric DNS");
    Set<String> names = new LinkedHashSet<>();
    for (String line : new String(bytes, StandardCharsets.US_ASCII).lines().toList()) {
      String content = line.split("#", 2)[0].strip();
      if (content.isEmpty()) continue;
      String[] fields = content.split("\\s+");
      if (!fields[0].equals("nameserver")) continue;
      need(fields.length == 2 && !fields[1].contains("%"), "Malformed DNS");
      names.add(fields[1].contains(":") ? ipv6(fields[1]) : ipv4(fields[1]));
    }
    need(names.size() >= 1 && names.size() <= 3, "Expected one to three DNS servers");
    StringBuilder out = new StringBuilder();
    for (String name : names) out.append("nameserver " + name + "\n");
    return out.toString().getBytes(StandardCharsets.US_ASCII);
  }

  static void image(JsonNode rows, String imageId, JsonNode base, String marker) throws Exception {
    JsonNode image = SeedContract.single(rows, "committed image"),
        root = image.path("RootFS"),
        original = base.path("RootFS"),
        layers = root.path("Layers"),
        old = original.path("Layers"),
        cfg = image.path("Config");
    need(
        text(image.path("Id"), imageId)
            && text(image.path("Parent"), SeedContract.IMAGE_ID)
            && text(image.path("Os"), "linux")
            && text(image.path("Architecture"), "amd64")
            && cfg.isObject()
            && empty(cfg.path("Volumes"))
            && text(cfg.path("Labels").path("org.stargate.libc.seed-image"), marker)
            && text(cfg.path("Labels").path(SeedContract.LABEL), marker)
            && empty(image.path("RepoTags"))
            && empty(image.path("RepoDigests"))
            && text(root.path("Type"), "layers")
            && text(original.path("Type"), "layers")
            && layers.isArray()
            && old.isArray()
            && !old.isEmpty()
            && layers.size() == old.size() + 1,
        "Committed image provenance mismatch");
    for (int i = 0; i < layers.size(); i++)
      need(
          layers.get(i).isTextual()
              && layers.get(i).asText().matches("sha256:[0-9a-f]{64}")
              && (i >= old.size() || layers.get(i).equals(old.get(i))),
          "Committed image layer mismatch");
  }

  static void builder(JsonNode rows, String cid, String marker, String image, String state)
      throws Exception {
    JsonNode c = SeedContract.single(rows, "builder"),
        cfg = c.path("Config"),
        host = c.path("HostConfig"),
        st = c.path("State"),
        net = c.path("NetworkSettings"),
        mounts = c.path("Mounts");
    need(
        cfg.isObject() && host.isObject() && st.isObject() && net.isObject(),
        "Invalid builder config");
    need(
        text(c.path("Id"), cid)
            && text(c.path("Name"), "/stargate-libc-builder-" + marker)
            && text(c.path("Image"), image)
            && text(cfg.path("Labels").path(LABEL), marker)
            && text(cfg.path("User"), "0:0")
            && cfg.path("Entrypoint").equals(JSON.valueToTree(List.of("/bin/sleep")))
            && cfg.path("Cmd").equals(JSON.valueToTree(List.of("infinity")))
            && text(st.path("Status"), state)
            && bool(st.path("Running"), state.equals("running"))
            && bool(st.path("OOMKilled"), false)
            && bool(st.path("Dead"), false),
        "Builder identity mismatch");
    JsonNode tmpfs = host.path("Tmpfs");
    need(
        tmpfs.isObject()
            && names(tmpfs).equals(List.of("/work"))
            && tmpfs.path("/work").isTextual()
            && new HashSet<>(List.of(tmpfs.path("/work").asText().split(",", -1)))
                .equals(Set.of("rw", "exec", "dev", "nosuid", "size=9g", "mode=0700"))
            && mounts.isArray()
            && mounts.size() <= 1,
        "Builder work tmpfs mismatch");
    for (JsonNode mount : mounts)
      need(
          text(mount.path("Type"), "tmpfs") && text(mount.path("Destination"), "/work"),
          "Builder mount mismatch");
    SeedContract.isolation(cfg, host, net);
    need(
        empty(host.path("Mounts"))
            && empty(host.path("CapAdd"))
            && empty(host.path("CapDrop"))
            && empty(host.path("SecurityOpt"))
            && SeedContract.number(host.path("Memory"), 0),
        "Builder isolation mismatch");
  }

  static void mount(byte[] data) throws Exception {
    for (byte value : data) need((value & 255) < 128, "Invalid non-ASCII mount report");
    String[] fields = new String(data, StandardCharsets.US_ASCII).strip().split("\\s+", 3);
    need(
        fields.length == 3 && fields[0].equals("/work") && fields[1].equals("tmpfs"),
        "Work is not a distinct tmpfs");
    Set<String> opts = new HashSet<>(List.of(fields[2].split(",")));
    need(
        opts.containsAll(Set.of("rw", "nosuid"))
            && Collections.disjoint(opts, Set.of("noexec", "nodev", "ro"))
            && (opts.contains("size=9437184k") || opts.contains("size=9g")),
        "Work mount options mismatch");
  }

  final SeedExecutor e;
  final Path root;
  final SeedExecutor.Journal journal;
  final String marker = token();
  String cid, imageId, state;
  boolean owned;

  BuilderBootstrap(SeedExecutor executor, String seedId) {
    e = executor;
    e.cid = seedId;
    e.state = "running";
    e.owned = true;
    root = e.root;
    journal = e.journal;
  }

  void inspect() throws Exception {
    e.daemon();
    Path out =
        e.invoke(
            "inspect-builder",
            List.of("inspect", "--type", "container", cid),
            120,
            null,
            null,
            true);
    try {
      builder(json(out), cid, marker, imageId, state);
    } catch (Exception error) {
      throw new Transport.Uncertain("Builder inspection failed", error);
    }
  }

  Path command(String stage, List<String> args, int timeout, String tar) throws Exception {
    inspect();
    List<String> command = new ArrayList<>(List.of("exec", cid));
    command.addAll(args);
    return e.invoke(stage, command, timeout, null, tar, false);
  }

  Path command(String stage, List<String> args) throws Exception {
    return command(stage, args, 120, null);
  }

  void checks(String prefix, String label) throws Exception {
    for (var check : SeedContract.checks().entrySet()) {
      String path = prefix + check.getKey();
      String[] actual =
          e.string(command(label + "-hash", List.of("sha256sum", path))).strip().split("\\s+");
      need(List.of(actual).equals(List.of(check.getValue(), path)), "Copied input hash mismatch");
    }
    Path out =
        command(
            label + "-source",
            List.of("tar", "-C", prefix + "/build", "-cf", "-", "glibc-2.39"),
            600,
            label + "-source.tar");
    e.sourceProof(out);
    List<String> query =
        prefix.isEmpty()
            ? List.of("dpkg-query", "-W", "-f=" + SeedContract.FMT)
            : List.of("chroot", prefix, "dpkg-query", "-W", "-f=" + SeedContract.FMT);
    out = command(label + "-packages", query);
    e.packageProof(out);
    out =
        command(
            label + "-sources",
            List.of("cat", prefix + "/etc/apt/sources.list.d/stargate-snapshot.list"));
    need(
        Arrays.equals(
            read(out, true, 16L * 1024 * 1024),
            SeedContract.SOURCES.getBytes(StandardCharsets.UTF_8)),
        "Snapshot sources mismatch");
  }

  void cleanup() throws Exception {
    need(owned && cid != null, "Builder identity not established");
    inspect();
    if (state.equals("running")) {
      Path out =
          e.invoke("stop-builder", List.of("stop", "--timeout", "15", cid), 90, null, null, true);
      need(e.string(out).strip().equals(cid), "Builder stop acknowledgement mismatch");
      state = "exited";
      inspect();
    }
    inspect();
    Path out = e.invoke("remove-builder", List.of("rm", cid), 90, null, null, true);
    need(e.string(out).strip().equals(cid), "Builder removal acknowledgement mismatch");
    e.daemon();
    out =
        e.invoke(
            "list-after-builder-removal",
            List.of("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"),
            120,
            null,
            null,
            true);
    need(e.string(out).lines().noneMatch(cid::equals), "Builder absence not confirmed");
    journal.record("builder_removed", object("id", cid));
  }

  ObjectNode run() {
    ObjectNode result =
        object(
            "status",
            "failed",
            "scope",
            "bootstrap readiness only; no libc build or tests",
            "seed_id",
            e.cid,
            "builder_marker",
            marker,
            "builder_id",
            null,
            "image_id",
            null,
            "cleanup",
            "retain all resources for exact-ID review");
    try {
      journal.record("bootstrap_started", result);
      e.inputs();
      e.inspect("running");
      e.daemon();
      JsonNode baseRows =
          json(
              e.invoke(
                  "base-image-inspect",
                  List.of("image", "inspect", SeedContract.IMAGE),
                  120,
                  null,
                  null,
                  true));
      SeedContract.image(baseRows);
      JsonNode base = baseRows.get(0);
      e.inspect("running");
      Path out =
          e.invoke(
              "commit-owned-seed",
              List.of(
                  "commit",
                  "--change",
                  "LABEL org.stargate.libc.seed-image=" + e.definition.path("marker").asText(),
                  e.cid),
              600,
              null,
              null,
              true);
      imageId = e.string(out).strip();
      result.put("image_id", imageId);
      need(imageId.matches("sha256:[0-9a-f]{64}"), "Commit acknowledgement ambiguous");
      e.inspect("running");
      e.daemon();
      image(
          json(
              e.invoke(
                  "inspect-committed-image",
                  List.of("image", "inspect", imageId),
                  120,
                  null,
                  null,
                  true)),
          imageId,
          base,
          e.definition.path("marker").asText());
      journal.record("image_bound", object("image_id", imageId, "seed_id", e.cid));
      String name = "stargate-libc-builder-" + marker;
      Path cidfile = root.resolve("builder.cid");
      e.daemon();
      out =
          e.invoke(
              "create-builder",
              List.of(
                  "create",
                  "--pull",
                  "never",
                  "--cidfile",
                  cidfile.toString(),
                  "--name",
                  name,
                  "--label",
                  LABEL + "=" + marker,
                  "--network",
                  "bridge",
                  "--pid",
                  "",
                  "--ipc",
                  "private",
                  "--uts",
                  "",
                  "--cgroupns",
                  "private",
                  "--user",
                  "0:0",
                  "--tmpfs",
                  "/work:rw,exec,dev,nosuid,size=9g,mode=0700",
                  "--log-driver",
                  "none",
                  "--entrypoint",
                  "/bin/sleep",
                  imageId,
                  "infinity"),
              120,
              null,
              null,
              true);
      String id = e.string(out).strip();
      need(
          id.matches("[0-9a-f]{64}")
              && !sha(cidfile).isEmpty()
              && Files.readString(cidfile).strip().equals(id),
          "Builder acknowledgement ambiguous");
      SeedExecutor.privateCid(cidfile);
      journal.directory.force(true);
      cid = id;
      result.put("builder_id", id);
      state = "created";
      inspect();
      owned = true;
      journal.record("builder_owned", object("id", cid, "image_id", imageId, "marker", marker));
      out = e.invoke("start-builder", List.of("start", cid), 120, null, null, true);
      need(e.string(out).strip().equals(cid), "Builder start ambiguous");
      state = "running";
      inspect();
      mount(
          read(
              command(
                  "work-mount",
                  List.of("findmnt", "-n", "-o", "TARGET,FSTYPE,OPTIONS", "-T", "/work")),
              true,
              16L * 1024 * 1024));
      need(
          e.string(command("work-owner", List.of("stat", "-c", "%a:%u:%g", "/work")))
              .strip()
              .equals("700:0:0"),
          "Work ownership mismatch");
      String prereqs =
          "for x in nsenter unshare mount umount mountpoint findmnt pivot_root tar chroot mknod; do"
              + " command -v \"$x\" >/dev/null; done; tar --help | grep -q -- --xattrs; tar --help"
              + " | grep -q -- --acls; tar --help | grep -q -- --numeric-owner";
      command("prerequisites", List.of("/bin/sh", "-ec", prereqs));
      checks("", "image");
      byte[] resolver =
          dns(
              read(
                  command("read-dns", List.of("cat", "/etc/resolv.conf")),
                  true,
                  16L * 1024 * 1024));
      command("make-root", List.of("mkdir", "-p", "/work/root"));
      command("copy-root", List.of("/bin/bash", "-o", "pipefail", "-ec", COPY), 1200, null);
      command("setup-root", List.of("/bin/sh", "-ec", SETUP));
      inspect();
      e.invoke(
          "write-dns",
          List.of("exec", "-i", cid, "/bin/sh", "-ec", "cat > /work/root/etc/resolv.conf"),
          120,
          resolver,
          null,
          false);
      command(
          "devices",
          List.of(
              "chroot",
              "/work/root",
              "/bin/sh",
              "-ec",
              ": > /dev/null && test -c /dev/null && test -c /dev/zero && test -c /dev/random &&"
                  + " test -c /dev/urandom && head -c 1 /dev/zero > /dev/null && head -c 1"
                  + " /dev/urandom > /dev/null"));
      command("root-prerequisites", List.of("chroot", "/work/root", "/bin/sh", "-ec", prereqs));
      checks("/work/root", "root");
      command(
          "check-build-deps",
          List.of(
              "chroot",
              "/work/root",
              "/usr/bin/env",
              "DEB_BUILD_OPTIONS=",
              "DEB_BUILD_PROFILES=",
              "dpkg-checkbuilddeps",
              "/build/glibc-2.39/debian/control"));
      need(
          e.string(command("existing-preflight", List.of("/bin/sh", "-c", PREFLIGHT)))
              .strip()
              .equals("clean"),
          "Fresh preflight failed");
      e.inputs();
      e.inspect("running");
      inspect();
      journal.record(
          "bootstrap_ready", object("builder_id", cid, "image_id", imageId, "marker", marker));
      result
          .put("status", "bootstrap-ready")
          .put("package_inventory_sha256", SeedContract.PACKAGE_SHA);
    } catch (Exception error) {
      result.put("error", error.toString());
      if (cid != null) result.put("builder_id", cid);
      if (owned && !(error instanceof Transport.Uncertain) && !journal.poisoned)
        try {
          cleanup();
          result.put("cleanup", "builder removed and absence confirmed; seed and image retained");
        } catch (Exception failed) {
          result
              .put("cleanup", "builder cleanup ambiguous; retain for exact-ID review")
              .put("cleanup_error", failed.toString());
        }
      if (!journal.poisoned)
        try {
          journal.record("bootstrap_halted", object("error", result.path("error").asText()));
        } catch (Exception ignored) {
        }
    }
    return result;
  }
}
