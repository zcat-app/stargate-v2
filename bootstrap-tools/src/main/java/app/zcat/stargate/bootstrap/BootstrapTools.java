/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;

public final class BootstrapTools {
  public static void main(String[] args) {
    Cancellation cancellation = Cancellation.install();
    int status = 1;
    try {
      status =
          execute(
              args,
              new Transport.Processes(),
              new SourcePreparer.WebDownloader(),
              SeedContract::verifyInputs);
      Cancellation.checkpoint();
    } catch (Exception error) {
      System.err.println("Bootstrap tools failed: " + error.getMessage());
    } finally {
      cancellation.close();
    }
    System.exit(cancellation.exitCode(status));
  }

  static Map<String, String> options(String[] args, int start, Set<String> allowed)
      throws Exception {
    Map<String, String> values = new HashMap<>();
    for (int i = start; i < args.length; i++) {
      String name = args[i];
      need(
          allowed.contains(name) && !values.containsKey(name),
          "Unknown or duplicate option: " + name);
      if (name.equals("--ack-exclusive-local-daemon")) values.put(name, "true");
      else {
        need(i + 1 < args.length && !args[i + 1].startsWith("--"), "Missing option value: " + name);
        values.put(name, args[++i]);
      }
    }
    return values;
  }

  static String required(Map<String, String> values, String name) throws Exception {
    need(values.containsKey(name), "Required option: " + name);
    return values.get(name);
  }

  static Path path(Map<String, String> values, String name) throws Exception {
    return Path.of(required(values, name));
  }

  static int execute(
      String[] args,
      Transport transport,
      SourcePreparer.Downloader downloader,
      SeedContract.Inputs verifier)
      throws Exception {
    if (Arrays.asList(args).contains("--help")) {
      usage();
      return 0;
    }
    need(
        args.length >= 3 && args[0].equals("--project"),
        "Expected --project ROOT source|ca|seed|bootstrap");
    Path project = Path.of(args[1]).toAbsolutePath().normalize();
    String kind = args[2];
    if (kind.equals("source")) {
      var values = options(args, 3, Set.of("--workspace-parent"));
      Path workspace =
          new SourcePreparer(project, transport, downloader)
              .prepare(path(values, "--workspace-parent"));
      System.out.println(
          "Source prepared: "
              + workspace.resolve("glibc-2.39")
              + "\nStatus and logs: "
              + workspace
              + "\n"
              + "Source preparation only; no chroot, bootstrap, compilation or build/test"
              + " proof.");
      return 0;
    }
    if (kind.equals("ca")) {
      var values =
          options(args, 3, Set.of("--inrelease", "--packages", "--ca-deb", "--workspace-parent"));
      Path workspace =
          new CaSeed(transport)
              .prepare(
                  path(values, "--inrelease"),
                  path(values, "--packages"),
                  path(values, "--ca-deb"),
                  path(values, "--workspace-parent"));
      System.out.println(
          "Temporary CA bundle: "
              + workspace.resolve("bootstrap-ca.pem")
              + " (SHA256 "
              + sha(workspace.resolve("bootstrap-ca.pem"))
              + ")\n"
              + "Source-only preparation: no APT resolution, builder, compilation or build proof.");
      return 0;
    }
    if (kind.equals("bootstrap")) {
      var values =
          options(
              args,
              3,
              Set.of(
                  "--plan",
                  "--docker-cli",
                  "--docker-sha256",
                  "--daemon-id",
                  "--ack-exclusive-local-daemon"));
      required(values, "--ack-exclusive-local-daemon");
      Path plan = path(values, "--plan"), docker = path(values, "--docker-cli");
      String dockerSha = required(values, "--docker-sha256"),
          daemon = required(values, "--daemon-id");
      ObjectNode seeded =
          SeedExecutor.execute(plan, docker, dockerSha, daemon, transport, verifier);
      if (!text(seeded.path("status"), "dependency-ready")) {
        System.out.println(seeded);
        return 1;
      }
      ObjectNode definition = (ObjectNode) json(plan);
      Path root = privateDirectory(plan.getParent().resolve("bootstrap"));
      try (var journal = new SeedExecutor.Journal(root)) {
        var executor =
            new SeedExecutor(
                definition, root, docker, dockerSha, daemon, journal, transport, verifier);
        ObjectNode result =
            new BuilderBootstrap(executor, seeded.path("container_id").asText()).run();
        save(root.resolve("result.json"), result);
        journal.directory.force(true);
        System.out.println(result);
        return text(result.path("status"), "bootstrap-ready") ? 0 : 1;
      }
    }
    need(kind.equals("seed") && args.length >= 4, "Unknown command");
    String mode = args[3];
    Set<String> allowed =
        switch (mode) {
          case "prepare" ->
              Set.of("--source-workspace", "--ca-bundle", "--output", "--layer-quota");
          case "execute" ->
              Set.of(
                  "--plan",
                  "--docker-cli",
                  "--docker-sha256",
                  "--daemon-id",
                  "--ack-exclusive-local-daemon");
          case "claim", "verify-inputs" -> Set.of("--plan");
          case "verify-image" -> Set.of("--inspection");
          case "verify-container" ->
              Set.of("--inspection", "--marker", "--id", "--state", "--layer-quota");
          case "verify-source-tar" -> Set.of("--archive");
          default -> throw new IllegalArgumentException("Unknown seed operation: " + mode);
        };
    var values = options(args, 4, allowed);
    switch (mode) {
      case "prepare" -> {
        Path output = path(values, "--output");
        SeedContract.prepare(
            path(values, "--source-workspace"),
            path(values, "--ca-bundle"),
            output,
            values.get("--layer-quota"),
            verifier);
        System.out.println(
            "Plan prepared: " + output.resolve("plan.json") + "; no Docker or build was run.");
      }
      case "execute" -> {
        required(values, "--ack-exclusive-local-daemon");
        ObjectNode result =
            SeedExecutor.execute(
                path(values, "--plan"),
                path(values, "--docker-cli"),
                required(values, "--docker-sha256"),
                required(values, "--daemon-id"),
                transport,
                verifier);
        System.out.println(result);
        return text(result.path("status"), "dependency-ready") ? 0 : 1;
      }
      case "claim" ->
          System.out.println(
              "Plan consumed once; SHA256 " + SeedExecutor.claim(path(values, "--plan")));
      case "verify-inputs" -> {
        JsonNode plan = json(path(values, "--plan")), record = plan.path("inputs");
        need(
            verifier
                .verify(
                    Path.of(record.path("source_workspace").asText()),
                    Path.of(record.path("ca_bundle").asText()))
                .equals(record),
            "Inputs changed since planning");
        System.out.println("Fixed source and CA inputs match plan.");
      }
      case "verify-image" -> {
        SeedContract.image(json(path(values, "--inspection")));
        System.out.println("Image identity matches fixed input.");
      }
      case "verify-container" -> {
        SeedContract.container(
            json(path(values, "--inspection")),
            required(values, "--marker"),
            required(values, "--id"),
            required(values, "--state"),
            values.get("--layer-quota"));
        System.out.println("Owned container configuration matches plan.");
      }
      case "verify-source-tar" -> {
        need(
            canonicalSha(Inventories.tar(path(values, "--archive")))
                .equals(SeedContract.INVENTORY_SHA),
            "Copied source differs from fixed inventory");
        System.out.println("Copied source matches fixed inventory.");
      }
    }
    return 0;
  }

  static void usage() {
    System.out.println(
        "Usage: bootstrap-tools --project ROOT source|ca|seed|bootstrap [options]\n"
            + "source --workspace-parent DIR\n"
            + "ca --inrelease FILE --packages FILE --ca-deb FILE --workspace-parent DIR\n"
            + "seed prepare --source-workspace DIR --ca-bundle FILE --output NEW_ABSOLUTE_DIR"
            + " [--layer-quota 8G]\n"
            + "seed execute|bootstrap --plan FILE --docker-cli CANONICAL_DOCKER --docker-sha256 SHA"
            + " --daemon-id ID --ack-exclusive-local-daemon\n"
            + "seed claim|verify-inputs --plan FILE\n"
            + "seed verify-image --inspection FILE\n"
            + "seed verify-container --inspection FILE --marker HEX32 --id FULL_ID --state"
            + " created|running|exited [--layer-quota 8G]\n"
            + "seed verify-source-tar --archive FILE\n"
            + "No libc compilation is performed by these commands.");
  }
}
