/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

class SeedExecutor {
  static ObjectNode object(Object... pairs) {
    ObjectNode out = JSON.createObjectNode();
    for (int i = 0; i < pairs.length; i += 2)
      out.set((String) pairs[i], JSON.valueToTree(pairs[i + 1]));
    return out;
  }

  static class Journal implements AutoCloseable {
    boolean poisoned;
    final NativeDirectory directory;
    final FileChannel file;

    Journal(Path root) throws Exception {
      directory = NativeDirectory.open(root);
      FileChannel opened = null;
      try {
        opened = directory.create("execution.jsonl");
        opened.force(true);
        directory.force(true);
        file = opened;
      } catch (Exception error) {
        if (opened != null) opened.close();
        directory.close();
        throw error;
      }
    }

    void record(String event, ObjectNode fields) throws Exception {
      need(!poisoned, "Journal failure prohibits Docker operations");
      try {
        ObjectNode record = fields.deepCopy();
        record.put("event", event);
        write(file, (canonical(record) + "\n").getBytes(StandardCharsets.UTF_8));
        file.force(true);
      } catch (Exception error) {
        poisoned = true;
        throw error;
      }
    }

    public void close() throws IOException {
      try {
        file.close();
      } finally {
        directory.close();
      }
    }
  }

  static String claim(Path plan) throws Exception {
    need(
        plan.isAbsolute() && plan.getFileName().toString().equals("plan.json"),
        "Canonical plan path required");
    directory(plan.getParent());
    var parent = info(plan.getParent());
    var item = info(plan);
    regular(plan, true);
    need(
        ((Number) parent.get("uid")).intValue() == uid()
            && mode(plan.getParent()) == 0700
            && ((Number) item.get("uid")).intValue() == uid()
            && mode(plan) == 0600,
        "Plan must be private and owned");
    String digest = sha(plan);
    JsonNode data = json(plan);
    need(
        SeedContract.number(data.path("format"), 1)
            && text(data.path("status"), "planned-not-executed")
            && data.path("marker").asText().matches("[0-9a-f]{32}")
            && text(
                data.path("container_name"), "stargate-libc-seed-" + data.path("marker").asText()),
        "Invalid plan");
    try (NativeDirectory directory = NativeDirectory.open(plan.getParent());
        FileChannel fence = directory.create("plan.once")) {
      write(
          fence,
          (canonical(object("plan_sha256", digest, "marker", data.path("marker").asText())) + "\n")
              .getBytes(StandardCharsets.UTF_8));
      fence.force(true);
      directory.force(true);
    }
    return digest;
  }

  static void trustedDocker(Path docker, String expected) throws Exception {
    need(
        docker.isAbsolute()
            && docker.toRealPath().equals(docker)
            && docker.getFileName().toString().equals("docker"),
        "Canonical Docker CLI required");
    trustedTool(docker);
    need(
        expected.matches("[0-9a-f]{64}") && sha(docker).equals(expected),
        "Docker CLI hash mismatch");
  }

  final ObjectNode definition;
  final Path root, docker;
  final String dockerSha, daemonId;
  final Journal journal;
  final Transport transport;
  final SeedContract.Inputs verifier;
  final Map<String, String> env;
  int counter;
  long outputBytes;
  String cid, state;
  boolean owned, startedCreate;
  final ArrayNode diskObservations = JSON.createArrayNode();

  SeedExecutor(
      ObjectNode definition,
      Path root,
      Path docker,
      String dockerSha,
      String daemonId,
      Journal journal,
      Transport transport,
      SeedContract.Inputs verifier)
      throws Exception {
    this.definition = definition;
    this.root = root;
    this.docker = docker;
    this.dockerSha = dockerSha;
    this.daemonId = daemonId;
    this.journal = journal;
    this.transport = transport;
    this.verifier = verifier;
    Path config = privateDirectory(root.resolve("docker-config"));
    env = Map.of("PATH", "/usr/bin:/bin", "LC_ALL", "C", "DOCKER_CONFIG", config.toString());
  }

  String quota() {
    return definition.path("layer_quota").isNull() ? null : definition.path("layer_quota").asText();
  }

  Path invoke(String stage, List<String> args) throws Exception {
    return invoke(stage, args, 120, null, null, false);
  }

  Path invoke(
      String stage,
      List<String> args,
      int timeout,
      byte[] stdin,
      String tar,
      boolean uncertainFailure)
      throws Exception {
    Cancellation.checkpoint();
    need(!journal.poisoned, "Journal failure prohibits Docker operations");
    need(sha(docker).equals(dockerSha), "Docker CLI changed during execution");
    need(stage.matches("[a-z0-9-]+"), "Invalid stage name");
    String tag = String.format(Locale.ROOT, "%04d-%s", ++counter, stage);
    Path out = root.resolve(tar == null ? tag + ".out" : tar), err = root.resolve(tag + ".err");
    need(out.getParent().equals(root), "Invalid output name");
    List<String> argv =
        new ArrayList<>(List.of(docker.toString(), "--host", "unix:///var/run/docker.sock"));
    argv.addAll(args);
    journal.record(
        "command_intent",
        object(
            "stage",
            stage,
            "argv",
            argv,
            "timeout_seconds",
            timeout,
            "stdout",
            out.getFileName().toString(),
            "stderr",
            err.getFileName().toString()));
    int rc;
    try {
      long remaining = 2L * 1024 * 1024 * 1024 - outputBytes;
      need(remaining > 0, "Total output budget exhausted");
      rc =
          transport.run(
              new Transport.Request(
                  argv,
                  root,
                  out,
                  err,
                  stdin,
                  timeout,
                  tar == null ? 16L * 1024 * 1024 : 512L * 1024 * 1024,
                  remaining,
                  env,
                  0077,
                  false));
      outputBytes += Files.size(out) + Files.size(err);
      need(outputBytes <= 2L * 1024 * 1024 * 1024, "Total output budget exceeded");
      journal.directory.force(true);
    } catch (Exception error) {
      if (!journal.poisoned)
        journal.record(
            "command_uncertain", object("stage", stage, "error", error.getClass().getSimpleName()));
      throw new Transport.Uncertain("Docker command outcome uncertain: " + stage, error);
    }
    journal.record("command_result", object("stage", stage, "exit_code", rc));
    if (rc != 0) {
      boolean knownApt =
          !args.isEmpty()
              && args.getFirst().equals("exec")
              && args.contains("apt-get")
              && rc == 100;
      if (uncertainFailure || !knownApt)
        throw new Transport.Uncertain("Docker command failed: " + stage + " exit " + rc);
      throw new IOException("Docker command failed: " + stage + " exit " + rc);
    }
    return out;
  }

  String string(Path output) throws Exception {
    return new String(read(output, true, 512L * 1024 * 1024), StandardCharsets.UTF_8);
  }

  void daemon() throws Exception {
    Path output =
        invoke(
            "daemon-identity", List.of("info", "--format", "{{json .ID}}"), 120, null, null, true);
    try {
      need(text(json(output), daemonId), "Daemon identity changed");
    } catch (Exception error) {
      throw new Transport.Uncertain("Daemon identity ambiguous/changed", error);
    }
  }

  void inspect(String expected) throws Exception {
    daemon();
    Path out =
        invoke(
            "inspect-owned", List.of("inspect", "--type", "container", cid), 120, null, null, true);
    try {
      SeedContract.container(json(out), definition.path("marker").asText(), cid, expected, quota());
    } catch (Exception error) {
      throw new Transport.Uncertain("Owned container inspection failed", error);
    }
  }

  void inputs() throws Exception {
    JsonNode record = definition.path("inputs");
    need(
        verifier
            .verify(
                Path.of(record.path("source_workspace").asText()),
                Path.of(record.path("ca_bundle").asText()))
            .equals(record),
        "Inputs changed since planning");
  }

  void image() throws Exception {
    daemon();
    Path out =
        invoke(
            "image-inspect",
            List.of("image", "inspect", SeedContract.IMAGE),
            120,
            null,
            null,
            true);
    try {
      SeedContract.image(json(out));
    } catch (Exception error) {
      throw new Transport.Uncertain("Image inspection failed", error);
    }
  }

  static ObjectNode space(Path path) {
    try {
      var store = Files.getFileStore(path);
      return object(
          "available_bytes", store.getUsableSpace(), "total_bytes", store.getTotalSpace());
    } catch (Exception error) {
      return object(
          "available_bytes", null, "total_bytes", null, "error", error.getClass().getSimpleName());
    }
  }

  void disk(String phase, boolean withSeed) throws Exception {
    daemon();
    Path out =
        invoke(
            "docker-root-dir",
            List.of("info", "--format", "{{json .DockerRootDir}}"),
            120,
            null,
            null,
            true);
    JsonNode value;
    try {
      value = json(out);
      need(
          value.isTextual()
              && Path.of(value.asText()).isAbsolute()
              && Path.of(value.asText()).normalize().toString().equals(value.asText()),
          "Docker root directory ambiguous");
    } catch (Exception error) {
      throw new Transport.Uncertain("Docker root directory is ambiguous", error);
    }
    ObjectNode record =
        object(
            "phase",
            phase,
            "docker_root",
            value.asText(),
            "docker_filesystem",
            space(Path.of(value.asText())),
            "output_filesystem",
            space(root));
    if (withSeed) {
      inspect("running");
      out =
          invoke(
              "seed-size",
              List.of("inspect", "--type", "container", "--size", cid),
              120,
              null,
              null,
              true);
      try {
        JsonNode rows = json(out);
        SeedContract.container(rows, definition.path("marker").asText(), cid, "running", quota());
        JsonNode size = rows.get(0).path("SizeRw");
        if (size.isIntegralNumber() && size.canConvertToLong() && size.asLong() >= 0)
          record.put("seed_writable_bytes", size.asLong());
        else record.putNull("seed_writable_bytes").put("seed_size_status", "unavailable");
      } catch (Exception error) {
        throw new Transport.Uncertain("Seed size inspection ambiguous", error);
      }
    }
    journal.record("disk_observation", record);
    diskObservations.add(record);
  }

  static List<String> argv(JsonNode stage) {
    return SeedContract.namesArray(stage.path("argv"));
  }

  void createSeed() throws Exception {
    image();
    daemon();
    startedCreate = true;
    JsonNode spec = definition.path("stages").get(1);
    List<String> command = argv(spec);
    Path out =
        invoke(
            "create",
            command.subList(1, command.size()),
            spec.path("timeout_seconds").asInt(),
            null,
            null,
            true);
    String value;
    try {
      Path cidfile = root.resolve("container.cid");
      sha(cidfile);
      value = string(out).strip();
      need(
          value.matches("[0-9a-f]{64}") && Files.readString(cidfile).strip().equals(value),
          "Container create acknowledgement mismatch");
      privateCid(cidfile);
      syncDirectory(root);
    } catch (Exception error) {
      throw new Transport.Uncertain("Container create acknowledgement ambiguous", error);
    }
    cid = value;
    inspect("created");
    journal.record(
        "container_owned",
        object(
            "id",
            cid,
            "marker",
            definition.path("marker").asText(),
            "image",
            SeedContract.IMAGE_ID));
    owned = true;
    state = "created";
  }

  static void privateCid(Path path) throws Exception {
    regular(path, true);
    need(
        ((Number) info(path).get("uid")).intValue() == uid() && (mode(path) & 0077) == 0,
        "Unsafe cidfile");
    try (var channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
      channel.force(true);
    }
  }

  List<String> substituted(JsonNode spec) {
    List<String> args = argv(spec);
    return args.subList(1, args.size()).stream()
        .map(value -> value.replace(SeedContract.CID, cid))
        .toList();
  }

  void start() throws Exception {
    inspect("created");
    JsonNode spec = definition.path("stages").get(3);
    Path out =
        invoke("start", substituted(spec), spec.path("timeout_seconds").asInt(), null, null, true);
    if (!string(out).strip().equals(cid))
      throw new Transport.Uncertain("Start acknowledgement mismatch");
    inspect("running");
    state = "running";
    journal.record("container_started", object("id", cid));
  }

  void stage(JsonNode spec) throws Exception {
    inspect("running");
    String name = spec.path("stage").asText();
    Path out =
        invoke(
            name,
            substituted(spec),
            spec.path("timeout_seconds").asInt(),
            spec.has("stdin_utf8")
                ? spec.path("stdin_utf8").asText().getBytes(StandardCharsets.UTF_8)
                : null,
            spec.has("output") ? spec.path("output").asText() : null,
            false);
    if (spec.has("expected_stdout_utf8"))
      need(
          Arrays.equals(
              read(out, true, 16L * 1024 * 1024),
              spec.path("expected_stdout_utf8").asText().getBytes(StandardCharsets.UTF_8)),
          name + " output mismatch");
    if (spec.has("expected_sha256")) {
      String actual;
      if (name.equals("package-inventory")) {
        packageProof(out);
        actual = SeedContract.PACKAGE_SHA;
      } else {
        String[] fields = string(out).strip().split("\\s+");
        List<String> args = argv(spec);
        need(
            fields.length == 2 && fields[1].equals(args.getLast()),
            name + " malformed hash output");
        actual = fields[0];
      }
      need(actual.equals(spec.path("expected_sha256").asText()), name + " hash mismatch");
    }
    if (text(spec.path("verify"), "source-tar")) sourceProof(out);
    journal.record("stage_verified", object("stage", name));
  }

  void sourceProof(Path archive) throws Exception {
    need(
        canonicalSha(Inventories.tar(archive)).equals(SeedContract.INVENTORY_SHA),
        "Source inventory mismatch");
  }

  void packageProof(Path inventory) throws Exception {
    need(sha(inventory).equals(SeedContract.PACKAGE_SHA), "Package inventory mismatch");
  }

  void cleanup() throws Exception {
    need(owned && cid != null, "No acknowledged owned container");
    inspect(state);
    if (state.equals("running")) {
      Path out =
          invoke("stop-owned", List.of("stop", "--timeout", "15", cid), 90, null, null, true);
      if (!string(out).strip().equals(cid))
        throw new Transport.Uncertain("Stop acknowledgement mismatch");
      inspect("exited");
      state = "exited";
    }
    inspect(state);
    Path out = invoke("remove-owned", List.of("rm", cid), 90, null, null, true);
    if (!string(out).strip().equals(cid))
      throw new Transport.Uncertain("Remove acknowledgement mismatch");
    daemon();
    out =
        invoke(
            "list-after-removal",
            List.of("container", "ls", "--all", "--no-trunc", "--format", "{{.ID}}"),
            120,
            null,
            null,
            true);
    if (string(out).lines().anyMatch(cid::equals))
      throw new Transport.Uncertain("Container absence unconfirmed");
    journal.record("container_removed", object("id", cid));
  }

  ObjectNode run() {
    ObjectNode result =
        object(
            "status",
            "failed",
            "stage",
            "preflight",
            "container_id",
            null,
            "marker",
            definition.path("marker").asText(),
            "cleanup",
            "not-created",
            "scope",
            "dependency seed only",
            "layer_quota_requested",
            quota(),
            "hard_layer_quota",
            quota() == null ? "not-requested-and-not-verified" : "requested-not-verified");
    try {
      journal.record(
          "execution_started",
          object("marker", definition.path("marker").asText(), "daemon", daemonId));
      inputs();
      disk("before-create", false);
      result.put("stage", "create");
      createSeed();
      result.put("container_id", cid);
      if (quota() != null)
        result.put("hard_layer_quota", "configured-enforcement-not-independently-verified");
      result.put("stage", "start");
      start();
      result.put("stage", "disk-before-copy");
      disk("before-copy", true);
      result.put("stage", "stages");
      inputs();
      JsonNode stages = definition.path("stages");
      for (int i = 5; i < stages.size(); i++) {
        result.put("stage", stages.get(i).path("stage").asText());
        stage(stages.get(i));
      }
      inputs();
      inspect("running");
      result.put("stage", "disk-after-dependencies");
      disk("after-dependencies", true);
      journal.record("dependency_seed_ready", object("id", cid));
      result
          .put("status", "dependency-ready")
          .put("stage", "complete")
          .put("cleanup", "owned-seed-retained");
    } catch (Exception error) {
      result.put("error", error.toString());
      if (cid != null) result.put("container_id", cid);
      if (owned && !(error instanceof Transport.Uncertain) && !journal.poisoned) {
        try {
          cleanup();
          result.put("cleanup", "removed-and-absence-confirmed");
        } catch (Exception failed) {
          result
              .put("cleanup", "failed-or-ambiguous-retained-for-review")
              .put("cleanup_error", failed.toString());
        }
      } else if (startedCreate)
        result.put("cleanup", "ambiguous-or-unverified-retained-for-review");
      if (!journal.poisoned)
        try {
          journal.record(
              "execution_halted",
              object(
                  "stage",
                  result.path("stage").asText(),
                  "cleanup",
                  result.path("cleanup").asText()));
        } catch (Exception ignored) {
        }
    }
    result.set("disk_observations", diskObservations);
    return result;
  }

  static ObjectNode execute(
      Path plan,
      Path docker,
      String dockerSha,
      String daemonId,
      Transport transport,
      SeedContract.Inputs verifier)
      throws Exception {
    need(
        plan.isAbsolute() && plan.getFileName().toString().equals("plan.json"),
        "Absolute plan.json required");
    Path output = directory(plan.getParent());
    try (var files = Files.list(output)) {
      need(
          files.map(p -> p.getFileName().toString()).toList().equals(List.of("plan.json")),
          "Fresh plan directory required; prior attempt cannot be reused");
    }
    trustedDocker(docker, dockerSha);
    need(daemonId.matches("[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}"), "Reviewed daemon ID required");
    ObjectNode definition = (ObjectNode) json(plan);
    JsonNode record = definition.path("inputs");
    Path source = Path.of(record.path("source_workspace").asText()),
        ca = Path.of(record.path("ca_bundle").asText());
    ObjectNode current = verifier.verify(source, ca);
    need(
        !output.startsWith(source) && !output.startsWith(ca.getParent()),
        "Output overlaps input workspace");
    String quota =
        definition.path("layer_quota").isNull() ? null : definition.path("layer_quota").asText();
    need(
        current.equals(record)
            && definition.equals(
                SeedContract.plan(current, definition.path("marker").asText(), output, quota)),
        "Plan or inputs differ from fixed contract");
    String digest = sha(plan);
    need(claim(plan).equals(digest), "Plan changed during claim");
    try (var journal = new Journal(output)) {
      journal.record("plan_claimed", object("plan_sha256", digest, "docker_sha256", dockerSha));
      ObjectNode result =
          new SeedExecutor(
                  definition, output, docker, dockerSha, daemonId, journal, transport, verifier)
              .run();
      save(output.resolve("result.json"), result);
      journal.directory.force(true);
      return result;
    }
  }
}
