/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.bootstrap;

import static app.zcat.stargate.bootstrap.IO.*;
import static app.zcat.stargate.bootstrap.SeedExecutor.object;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;

final class SeedFixtures {
  static final String MARKER = "1".repeat(32),
      CID = "2".repeat(64),
      BUILDER = "6".repeat(64),
      IMAGE = "sha256:" + "3".repeat(64),
      BASE_LAYER = "sha256:" + "4".repeat(64),
      NEW_LAYER = "sha256:" + "5".repeat(64),
      DAEMON = "expected-daemon";

  static ObjectNode inputs() {
    return object("source_workspace", "/fake/source", "ca_bundle", "/fake/ca/bootstrap-ca.pem");
  }

  static ObjectNode seed(String marker, String state, String quota) {
    ObjectNode config =
        object(
            "Labels",
            Map.of(SeedContract.LABEL, marker),
            "User",
            "0:0",
            "Entrypoint",
            List.of("/bin/sleep"),
            "Cmd",
            List.of("infinity"));
    ObjectNode host =
        object(
            "NetworkMode",
            "bridge",
            "PidMode",
            "",
            "IpcMode",
            "private",
            "UTSMode",
            "",
            "CgroupnsMode",
            "private",
            "UsernsMode",
            "",
            "PublishAllPorts",
            false,
            "Privileged",
            false,
            "Memory",
            4L * 1024 * 1024 * 1024,
            "MemorySwap",
            4L * 1024 * 1024 * 1024,
            "NanoCpus",
            2_000_000_000,
            "PidsLimit",
            512,
            "StorageOpt",
            quota == null ? null : Map.of("size", "8G"),
            "LogConfig",
            Map.of("Type", "none"));
    return object(
        "Id",
        CID,
        "Name",
        "/stargate-libc-seed-" + marker,
        "Image",
        SeedContract.IMAGE_ID,
        "Config",
        config,
        "State",
        object(
            "Status", state, "Running", state.equals("running"), "OOMKilled", false, "Dead", false),
        "Mounts",
        List.of(),
        "NetworkSettings",
        object("Networks", Map.of("bridge", Map.of()), "Ports", Map.of()),
        "HostConfig",
        host);
  }

  static ObjectNode builder(String marker, String state) {
    ObjectNode data = seed(marker, state, null);
    data.put("Id", BUILDER).put("Name", "/stargate-libc-builder-" + marker).put("Image", IMAGE);
    ((ObjectNode) data.path("Config").path("Labels"))
        .removeAll()
        .put(BuilderBootstrap.LABEL, marker);
    ObjectNode host = (ObjectNode) data.path("HostConfig");
    host.put("Memory", 0);
    host.set("Tmpfs", JSON.valueToTree(Map.of("/work", "rw,exec,dev,nosuid,size=9g,mode=0700")));
    return data;
  }

  static ObjectNode image() {
    return object(
        "Id",
        SeedContract.IMAGE_ID,
        "Os",
        "linux",
        "Architecture",
        "amd64",
        "RepoDigests",
        List.of(SeedContract.IMAGE),
        "Config",
        Map.of(),
        "RootFS",
        Map.of("Type", "layers", "Layers", List.of(BASE_LAYER)));
  }

  static void sourceTar(Path out, boolean bad) throws Exception {
    TestFiles.tar(
        out,
        List.of(
            TestFiles.dir("glibc-2.39"),
            TestFiles.file("glibc-2.39/file", (bad ? "xyz" : "abc").getBytes())),
        false);
  }

  static String sourceSha() throws Exception {
    return canonicalSha(object("file", List.of("file", 3, sha("abc".getBytes()))));
  }

  static class ProofExecutor extends SeedExecutor {
    ProofExecutor(
        ObjectNode definition,
        Path root,
        Path docker,
        String sha,
        String daemon,
        Journal journal,
        Transport transport,
        SeedContract.Inputs verifier)
        throws Exception {
      super(definition, root, docker, sha, daemon, journal, transport, verifier);
    }

    @Override
    void sourceProof(Path archive) throws Exception {
      need(
          canonicalSha(Inventories.tar(archive)).equals(sourceSha()),
          "Synthetic copied source mismatch");
    }

    @Override
    void packageProof(Path inventory) throws Exception {
      need(
          sha(inventory).equals(sha("package-inventory\n".getBytes())),
          "Synthetic package inventory mismatch");
    }
  }

  static class FakeDocker implements Transport {
    final List<List<String>> calls = new ArrayList<>();
    final List<String> stages = new ArrayList<>();
    String seedState = "absent",
        builderState = "absent",
        seedMarker = MARKER,
        builderMarker,
        quota,
        failure;
    boolean failed;

    FakeDocker(String failure) {
      this.failure = failure;
    }

    public int run(Request request) throws Exception {
      List<String> args = request.argv().subList(3, request.argv().size());
      calls.add(List.copyOf(args));
      String name = request.err().getFileName().toString();
      String stage = name.substring(name.indexOf('-') + 1, name.length() - 4);
      stages.add(stage);
      byte[] data = new byte[0];
      int rc = 0;
      bytes(request.err(), new byte[0]);
      if (failure != null && failure.equals(stage) && !stage.equals("existing-preflight")) {
        bytes(request.out(), new byte[0]);
        throw new Transport.Uncertain("Injected ambiguous failure");
      }
      if (stage.equals("daemon-identity"))
        data =
            JSON.writeValueAsBytes(
                "daemon-changed".equals(failure) && seedState.equals("running")
                    ? "other-daemon"
                    : DAEMON);
      else if (stage.equals("docker-root-dir"))
        data =
            JSON.writeValueAsBytes(
                "bad-disk-path".equals(failure) && seedState.equals("running")
                    ? "relative"
                    : "/tmp");
      else if (stage.equals("image-inspect") || stage.equals("base-image-inspect"))
        data = JSON.writeValueAsBytes(List.of(image()));
      else if (stage.equals("create")) {
        seedState = "created";
        seedMarker = args.get(args.indexOf("--label") + 1).split("=", 2)[1];
        quota = args.contains("--storage-opt") ? "8G" : null;
        bytes(Path.of(args.get(args.indexOf("--cidfile") + 1)), (CID + "\n").getBytes());
        data = (CID + "\n").getBytes();
        if ("ambiguous-create".equals(failure)) rc = 125;
        if ("unsupported-storage".equals(failure) && quota != null) rc = 1;
      } else if (stage.equals("inspect-owned") || stage.equals("seed-size")) {
        ObjectNode row = seed(seedMarker, seedState, quota);
        if ("identity-mismatch".equals(failure) && seedState.equals("running")
            || "cleanup-mismatch".equals(failure) && failed)
          ((ObjectNode) row.path("Config").path("Labels")).put(SeedContract.LABEL, "f".repeat(32));
        if (stage.equals("seed-size") && !"size-unavailable".equals(failure))
          row.put("SizeRw", 1234);
        data = JSON.writeValueAsBytes(List.of(row));
      } else if (stage.equals("start")) {
        seedState = "running";
        data = CID.getBytes();
      } else if (stage.equals("stop-owned")) {
        seedState = "exited";
        data =
            (("stop-warning".equals(failure) ? "Flag --time deprecated\n" : "") + CID).getBytes();
      } else if (stage.equals("remove-owned")) {
        seedState = "absent";
        data = CID.getBytes();
      } else if (stage.equals("list-after-removal"))
        data = seedState.equals("absent") ? new byte[0] : CID.getBytes();
      else if (stage.equals("commit-owned-seed"))
        data =
            (("commit-warning".equals(failure) ? "Flag --pause deprecated\n" : "") + IMAGE)
                .getBytes();
      else if (stage.equals("inspect-committed-image"))
        data =
            JSON.writeValueAsBytes(
                List.of(
                    object(
                        "Id",
                        IMAGE,
                        "Parent",
                        SeedContract.IMAGE_ID,
                        "Os",
                        "linux",
                        "Architecture",
                        "amd64",
                        "Config",
                        Map.of(
                            "Labels",
                            Map.of(
                                "org.stargate.libc.seed-image",
                                seedMarker,
                                SeedContract.LABEL,
                                seedMarker)),
                        "RootFS",
                        Map.of("Type", "layers", "Layers", List.of(BASE_LAYER, NEW_LAYER)))));
      else if (stage.equals("create-builder")) {
        builderMarker = args.get(args.indexOf("--label") + 1).split("=", 2)[1];
        builderState = "created";
        bytes(Path.of(args.get(args.indexOf("--cidfile") + 1)), BUILDER.getBytes());
        data = BUILDER.getBytes();
      } else if (stage.equals("inspect-builder"))
        data = JSON.writeValueAsBytes(List.of(builder(builderMarker, builderState)));
      else if (stage.equals("start-builder")) {
        builderState = "running";
        data = BUILDER.getBytes();
      } else if (stage.equals("stop-builder")) {
        builderState = "exited";
        data =
            (("builder-stop-warning".equals(failure) ? "Flag --time deprecated\n" : "") + BUILDER)
                .getBytes();
      } else if (stage.equals("remove-builder")) {
        builderState = "absent";
        data = BUILDER.getBytes();
      } else if (stage.equals("list-after-builder-removal"))
        data = builderState.equals("absent") ? new byte[0] : BUILDER.getBytes();
      else if (stage.equals("work-mount"))
        data = "/work tmpfs rw,nosuid,size=9437184k,mode=700\n".getBytes();
      else if (stage.equals("work-owner")) data = "700:0:0\n".getBytes();
      else if (stage.equals("read-dns")) data = "nameserver 1.1.1.1\n".getBytes();
      else if (stage.equals("existing-preflight"))
        data =
            (("dirty-root".equals(failure) || "builder-stop-warning".equals(failure))
                    ? "dirty"
                    : "clean")
                .getBytes();
      else if (stage.startsWith("copyback-source-") || stage.endsWith("-source")) {
        sourceTar(request.out(), "bad-copyback".equals(failure));
        return 0;
      } else if (args.contains("sha256sum")) {
        String path = args.getLast(),
            key = path.startsWith("/work/root") ? path.substring("/work/root".length()) : path;
        data = (SeedContract.checks().get(key) + "  " + path + "\n").getBytes();
      } else if (stage.equals("sources-show") || stage.endsWith("-sources"))
        data = SeedContract.SOURCES.getBytes();
      else if (stage.equals("package-inventory") || stage.endsWith("-packages"))
        data = "package-inventory\n".getBytes();
      else if (stage.equals("build-dep")) {
        if (List.of("normal-failure", "cleanup-mismatch", "stop-warning")
            .contains(failure == null ? "" : failure)) {
          rc = 100;
          failed = true;
        }
        if ("ambiguous-failure".equals(failure)) rc = 1;
      }
      bytes(request.out(), data);
      return rc;
    }
  }
}
