/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;

final class SeedContract {
  static final String
      IMAGE = "ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc",
      IMAGE_ID = "sha256:6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36",
      CA_SHA = "64e7c24b0536b525fb19b145768bd5e6e12ced0df3db837c34553ea789acd143",
      KEYRING_SHA = CaSeed.KEYRING_SHA,
      PATCH_SHA = "d84d9908588fa764b8727ffa4d9ada466fa00ebe283d968d471590da8b39f91f",
      TARGET_SHA = "2486c2e4d138c407afc5448ce6c0e1bfd6b7ca2e46fbc69c2e41c53892bd4b92",
      INVENTORY_SHA = "f1654d71000cb6ee358897046ffb73c7128d4c1f00fdd6a55d5ac19576a788b3",
      PACKAGE_SHA = "4812261212acdd9ccc4921137defbf96fc2f223c7a6853c36c03b2a995681670";
  static final Map<String, String> FILES;

  static {
    Map<String, String> values = new LinkedHashMap<>();
    values.put(
        "glibc_2.39-0ubuntu8.9.dsc",
        "1b73a89e0910eb3e5920cde639ac7eb606256d8ee809688ff9b5912b67002711");
    values.put(
        "glibc_2.39-0ubuntu8.9.debian.tar.xz",
        "d6114f2302896a3c8612453e1bf1d0e61603e3029ba4a7c246fbb1ab4c48d2b0");
    values.put(
        "glibc_2.39.orig.tar.xz",
        "f77bd47cf8170c57365ae7bf86696c118adb3b120d3259c64c502d3dc1e2d926");
    values.put(
        SourcePreparer.AUX, "2cce427ef7933c17379f5514e4f0ccf8dffae5bf8c72f0f7e0bf8b8401f34be5");
    FILES = Collections.unmodifiableMap(values);
  }

  static final List<String> DEPS =
      List.of(
          "quilt",
          "autoconf",
          "debhelper",
          "texinfo",
          "xsltproc",
          "rdfind",
          "symlinks",
          "netbase",
          "gperf",
          "systemtap-sdt-dev",
          "libaudit-dev",
          "libcap-dev",
          "libselinux1-dev",
          "libgd-dev",
          "dpkg-dev",
          "xz-utils",
          "gettext");
  static final String LABEL = "org.stargate.libc.dependency-seed",
      CID = "@FULL_OWNED_CONTAINER_ID@",
      SNAPSHOT = "https://snapshot.ubuntu.com/ubuntu/20261027T000000Z/",
      FMT = "${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n",
      SOURCES;

  static {
    StringBuilder text = new StringBuilder();
    for (String suite : List.of("noble", "noble-updates", "noble-security"))
      for (String kind : List.of("deb", "deb-src"))
        text.append(
            kind
                + " [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                + SNAPSHOT
                + " "
                + suite
                + " main universe\n");
    SOURCES = text.toString();
  }

  @FunctionalInterface
  interface Inputs {
    ObjectNode verify(Path workspace, Path ca) throws Exception;
  }

  static ObjectNode verifyInputs(Path workspace, Path ca) throws Exception {
    directory(workspace);
    need(
        ca.isAbsolute() && ca.getFileName().toString().equals("bootstrap-ca.pem"),
        "CA path must name bootstrap-ca.pem");
    directory(ca.getParent());
    need(sha(ca).equals(CA_SHA), "CA bundle hash mismatch");
    Path statusPath = workspace.resolve("status.json");
    sha(statusPath);
    JsonNode status = json(statusPath);
    Path source = workspace.resolve("glibc-2.39");
    need(
        text(status.path("status"), "prepared")
            && text(status.path("stage"), "complete")
            && text(status.path("source_directory"), source.toString())
            && text(status.path("patch_sha256"), PATCH_SHA)
            && text(status.path("patched_target").path("file"), SourcePreparer.TARGET)
            && text(status.path("patched_target").path("after_sha256"), TARGET_SHA),
        "Source status mismatch");
    for (var entry : FILES.entrySet()) {
      JsonNode item = status.path("artifacts").path(entry.getKey());
      need(
          bool(item.path("verified"), true)
              && text(item.path("actual_sha256"), entry.getValue())
              && text(item.path("expected_sha256"), entry.getValue())
              && sha(workspace.resolve(entry.getKey())).equals(entry.getValue()),
          "Source archive mismatch: " + entry.getKey());
    }
    directory(source.resolve("libio"));
    need(
        sha(source.resolve(SourcePreparer.TARGET)).equals(TARGET_SHA), "Source postimage mismatch");
    ObjectNode inventory = Inventories.source(source);
    need(
        canonicalSha(inventory).equals(INVENTORY_SHA),
        "Source tree differs from recorded successful seed");
    ObjectNode result =
        JSON.createObjectNode()
            .put("source_workspace", workspace.toString())
            .put("ca_bundle", ca.toString())
            .put("status_sha256", sha(statusPath))
            .put("source_inventory_sha256", INVENTORY_SHA)
            .put("source_entry_count", inventory.size())
            .put("ca_sha256", CA_SHA);
    result.set("archives", JSON.valueToTree(FILES));
    return result;
  }

  static JsonNode single(JsonNode rows, String kind) throws Exception {
    need(rows.isArray() && rows.size() == 1 && rows.get(0).isObject(), "Ambiguous " + kind);
    return rows.get(0);
  }

  static void image(JsonNode rows) throws Exception {
    JsonNode data = single(rows, "image");
    need(
        data.path("Config").isObject()
            && data.path("RepoDigests").isArray()
            && text(data.path("Id"), IMAGE_ID)
            && text(data.path("Os"), "linux")
            && text(data.path("Architecture"), "amd64")
            && namesArray(data.path("RepoDigests")).contains(IMAGE)
            && empty(data.path("Config").path("Volumes")),
        "Image mismatch");
  }

  static List<String> namesArray(JsonNode array) {
    List<String> out = new ArrayList<>();
    for (JsonNode value : array) out.add(value.asText());
    return out;
  }

  static void quota(String quota) throws Exception {
    need(quota == null || quota.equals("8G"), "Unsupported layer quota");
  }

  static void container(JsonNode rows, String marker, String cid, String state, String quota)
      throws Exception {
    quota(quota);
    need(
        List.of("created", "running", "exited").contains(state)
            && marker.matches("[0-9a-f]{32}")
            && cid.matches("[0-9a-f]{64}"),
        "Invalid container identity/state");
    JsonNode c = single(rows, "container"),
        cfg = c.path("Config"),
        host = c.path("HostConfig"),
        st = c.path("State"),
        net = c.path("NetworkSettings");
    need(
        cfg.isObject() && host.isObject() && st.isObject() && net.isObject(),
        "Invalid container config");
    JsonNode labels = cfg.path("Labels"),
        storage = host.path("StorageOpt"),
        logging = host.path("LogConfig");
    need(
        labels.isObject() && (empty(storage) || storage.isObject()) && logging.isObject(),
        "Invalid nested container config");
    need(
        text(c.path("Id"), cid)
            && text(c.path("Name"), "/stargate-libc-seed-" + marker)
            && text(c.path("Image"), IMAGE_ID)
            && text(labels.path(LABEL), marker)
            && text(cfg.path("User"), "0:0")
            && cfg.path("Entrypoint").equals(JSON.valueToTree(List.of("/bin/sleep")))
            && cfg.path("Cmd").equals(JSON.valueToTree(List.of("infinity")))
            && bool(st.path("Running"), state.equals("running"))
            && text(st.path("Status"), state)
            && bool(st.path("OOMKilled"), false)
            && bool(st.path("Dead"), false),
        "Container identity/state mismatch");
    isolation(cfg, host, net);
    need(
        c.path("Mounts").isArray()
            && c.path("Mounts").isEmpty()
            && empty(host.path("Mounts"))
            && empty(host.path("Tmpfs"))
            && empty(host.path("CapAdd"))
            && empty(host.path("CapDrop"))
            && empty(host.path("SecurityOpt"))
            && number(host.path("Memory"), 4L * 1024 * 1024 * 1024)
            && number(host.path("MemorySwap"), 4L * 1024 * 1024 * 1024)
            && number(host.path("NanoCpus"), 2_000_000_000)
            && number(host.path("PidsLimit"), 512)
            && (quota == null
                ? empty(storage)
                : storage.equals(JSON.valueToTree(Map.of("size", "8G"))))
            && text(logging.path("Type"), "none"),
        "Container isolation/resource mismatch");
  }

  static boolean number(JsonNode value, long expected) {
    return value.isIntegralNumber() && value.canConvertToLong() && value.asLong() == expected;
  }

  static void isolation(JsonNode cfg, JsonNode host, JsonNode net) throws Exception {
    for (String field :
        List.of(
            "Binds",
            "VolumesFrom",
            "PortBindings",
            "Devices",
            "DeviceRequests",
            "DeviceCgroupRules",
            "Links")) need(empty(host.path(field)), "Host/shared resource: " + field);
    need(
        empty(cfg.path("Volumes"))
            && empty(cfg.path("ExposedPorts"))
            && bool(host.path("PublishAllPorts"), false)
            && bool(host.path("Privileged"), false)
            && text(host.path("NetworkMode"), "bridge")
            && text(host.path("PidMode"), "")
            && text(host.path("IpcMode"), "private")
            && text(host.path("UTSMode"), "")
            && text(host.path("CgroupnsMode"), "private")
            && !text(host.path("UsernsMode"), "host")
            && net.path("Networks").isObject()
            && names(net.path("Networks")).equals(List.of("bridge"))
            && net.path("Ports").isObject(),
        "Isolation mismatch");
    for (JsonNode ports : net.path("Ports")) need(empty(ports), "Published ports refused");
  }

  static Map<String, String> checks() {
    Map<String, String> checks = new LinkedHashMap<>();
    checks.put("/build/bootstrap-ca.pem", CA_SHA);
    FILES.forEach((name, sha) -> checks.put("/build/" + name, sha));
    checks.put("/build/glibc-2.39/libio/fileops.c", TARGET_SHA);
    checks.put("/usr/share/keyrings/ubuntu-archive-keyring.gpg", KEYRING_SHA);
    return checks;
  }

  static ObjectNode stage(String name, List<String> argv, int timeout) {
    ObjectNode result = JSON.createObjectNode().put("stage", name).put("timeout_seconds", timeout);
    result.set("argv", JSON.valueToTree(argv));
    return result;
  }

  static List<String> join(List<String> prefix, String... suffix) {
    List<String> out = new ArrayList<>(prefix);
    out.addAll(List.of(suffix));
    return out;
  }

  static ObjectNode plan(ObjectNode inputs, String marker, Path output, String quota)
      throws Exception {
    quota(quota);
    need(marker.matches("[0-9a-f]{32}"), "Invalid marker");
    String name = "stargate-libc-seed-" + marker,
        source = inputs.path("source_workspace").asText(),
        ca = inputs.path("ca_bundle").asText();
    ArrayNode stages = JSON.createArrayNode();
    List<String> d = List.of("docker"), ex = List.of("docker", "exec", CID);
    stages.add(
        stage("image-inspect", join(d, "image", "inspect", IMAGE), 120).put("verify", "image"));
    List<String> create =
        new ArrayList<>(
            List.of(
                "docker",
                "create",
                "--pull",
                "never",
                "--cidfile",
                output.resolve("container.cid").toString(),
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
                "--memory",
                "4g",
                "--memory-swap",
                "4g",
                "--cpus",
                "2",
                "--pids-limit",
                "512"));
    if (quota != null) create.addAll(List.of("--storage-opt", "size=8G"));
    create.addAll(List.of("--log-driver", "none", "--entrypoint", "/bin/sleep", IMAGE, "infinity"));
    stages.add(stage("create", create, 120));
    stages.add(
        stage("inspect-created", join(d, "inspect", "--type", "container", CID), 120)
            .put("verify", "container-created"));
    stages.add(stage("start", join(d, "start", CID), 120));
    stages.add(
        stage("inspect-running", join(d, "inspect", "--type", "container", CID), 120)
            .put("verify", "container-running"));
    stages.add(stage("mkdir", join(ex, "mkdir", "-p", "/build"), 120));
    List<String> copies = new ArrayList<>(List.of(ca));
    for (String file : FILES.keySet()) copies.add(source + "/" + file);
    copies.add(source + "/glibc-2.39");
    for (String path : copies)
      stages.add(stage("copy-input", join(d, "cp", path, CID + ":/build/"), 600));
    for (var check : checks().entrySet())
      stages.add(
          stage("check-hash-before", join(ex, "sha256sum", check.getKey()), 120)
              .put("expected_sha256", check.getValue()));
    stages.add(
        stage("copyback-source-before", join(d, "cp", CID + ":/build/glibc-2.39", "-"), 600)
            .put("output", "source-before.tar")
            .put("verify", "source-tar"));
    stages.add(
        stage(
            "sources-remove",
            join(ex, "/bin/sh", "-ec", "rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*"),
            120));
    stages.add(
        stage(
                "sources-write",
                join(
                    d,
                    "exec",
                    "-i",
                    CID,
                    "/bin/sh",
                    "-ec",
                    "cat > /etc/apt/sources.list.d/stargate-snapshot.list"),
                120)
            .put("stdin_utf8", SOURCES));
    stages.add(
        stage(
                "sources-show",
                join(ex, "cat", "/etc/apt/sources.list.d/stargate-snapshot.list"),
                120)
            .put("expected_stdout_utf8", SOURCES));
    stages.add(stage("date", join(ex, "date", "-u", "+%Y-%m-%dT%H:%M:%SZ"), 120));
    stages.add(
        stage(
            "apt-update-seed",
            join(
                ex,
                "apt-get",
                "-o",
                "APT::Update::Error-Mode=any",
                "-o",
                "Acquire::https::CAInfo=/build/bootstrap-ca.pem",
                "update"),
            1800));
    stages.add(
        stage(
            "apt-install-ca",
            join(
                d,
                "exec",
                "-e",
                "DEBIAN_FRONTEND=noninteractive",
                CID,
                "apt-get",
                "-o",
                "Acquire::https::CAInfo=/build/bootstrap-ca.pem",
                "install",
                "-y",
                "ca-certificates",
                "build-essential"),
            2400));
    stages.add(
        stage("installed-ca", join(ex, "test", "-s", "/etc/ssl/certs/ca-certificates.crt"), 120));
    stages.add(
        stage(
            "apt-update-installed",
            join(ex, "apt-get", "-o", "APT::Update::Error-Mode=any", "update"),
            1800));
    stages.add(
        stage(
            "build-dep",
            join(
                d,
                "exec",
                "-e",
                "DEBIAN_FRONTEND=noninteractive",
                "-e",
                "DEB_BUILD_OPTIONS=",
                "-e",
                "DEB_BUILD_PROFILES=",
                CID,
                "apt-get",
                "build-dep",
                "-y",
                "/build/glibc_2.39-0ubuntu8.9.dsc"),
            2400));
    List<String> deps =
        join(d, "exec", "-e", "DEBIAN_FRONTEND=noninteractive", CID, "apt-get", "install", "-y");
    deps.addAll(DEPS);
    stages.add(stage("helper-deps", deps, 2400));
    stages.add(
        stage(
            "check-build-deps",
            join(
                d,
                "exec",
                "-e",
                "DEB_BUILD_OPTIONS=",
                "-e",
                "DEB_BUILD_PROFILES=",
                "-w",
                "/build/glibc-2.39",
                CID,
                "dpkg-checkbuilddeps"),
            120));
    stages.add(
        stage("package-inventory", join(ex, "dpkg-query", "-W", "-f=" + FMT), 120)
            .put("expected_sha256", PACKAGE_SHA));
    stages.add(stage("apt-policy", join(ex, "apt-cache", "policy"), 120));
    for (var check : checks().entrySet())
      stages.add(
          stage("check-hash-after", join(ex, "sha256sum", check.getKey()), 120)
              .put("expected_sha256", check.getValue()));
    stages.add(
        stage("copyback-source-after", join(d, "cp", CID + ":/build/glibc-2.39", "-"), 600)
            .put("output", "source-after.tar")
            .put("verify", "source-tar"));
    ObjectNode result =
        JSON.createObjectNode()
            .put("format", 1)
            .put("status", "planned-not-executed")
            .put("marker", marker)
            .put("container_name", name)
            .put("image", IMAGE)
            .put("image_id", IMAGE_ID);
    if (quota == null) result.putNull("layer_quota");
    else result.put("layer_quota", quota);
    result.set("inputs", inputs);
    result.set("stages", stages);
    return result
        .put(
            "success", "retain inspected owned container; dependency seed only, no build or chroot")
        .put(
            "failure",
            "stop; ambiguous Docker outcome requires manual review; never delete by shared name or"
                + " label");
  }

  static ObjectNode prepare(Path source, Path ca, Path output, String quota, Inputs verifier)
      throws Exception {
    quota(quota);
    need(
        output.isAbsolute() && output.getFileName() != null && output.equals(output.normalize()),
        "New absolute output required");
    directory(output.getParent());
    need(
        !output.startsWith(source) && !output.startsWith(ca.getParent()),
        "Output overlaps input workspaces");
    privateDirectory(output);
    try {
      ObjectNode plan = plan(verifier.verify(source, ca), token(), output, quota);
      save(output.resolve("plan.json"), plan);
      syncDirectory(output);
      return plan;
    } catch (Exception error) {
      throw new java.io.IOException(
          "Preparation failed; new output retained at " + output + ": " + error, error);
    }
  }
}
