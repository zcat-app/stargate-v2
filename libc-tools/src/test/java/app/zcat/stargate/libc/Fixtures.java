/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import static app.zcat.stargate.libc.LibcIO.*;

final class Fixtures {
    static final String BUILDER_ID = "a".repeat(64), HELPER_ID = "b".repeat(64), IMAGE = "sha256:" + "c".repeat(64), MARKER = "d".repeat(32);
    static ObjectNode base() throws Exception {
        return (ObjectNode)JSON.readTree("{\"HostConfig\":{\"Binds\":null,\"VolumesFrom\":null,\"Mounts\":null,\"Tmpfs\":null,\"PidMode\":\"\",\"IpcMode\":\"private\",\"UTSMode\":\"\",\"NetworkMode\":\"bridge\",\"Privileged\":false,\"PortBindings\":{},\"PublishAllPorts\":false},\"Mounts\":[],\"NetworkSettings\":{\"Ports\":{},\"Networks\":{\"bridge\":{}}},\"Config\":{\"Labels\":{},\"Volumes\":null}}");
    }
    static ObjectNode builder() throws Exception {
        ObjectNode data = base().put("Id", BUILDER_ID).put("Name", "/isolated-proof").put("Image", IMAGE);
        data.set("State", JSON.createObjectNode().put("Running", true));
        ((ObjectNode)data.path("Config").path("Labels")).put(Ownership.FRESH_LABEL, MARKER); return data;
    }
    static ObjectNode helper(String name, String marker) throws Exception {
        ObjectNode data = base().put("Id", HELPER_ID).put("Name", "/" + name).put("Image", IMAGE);
        ObjectNode config = (ObjectNode)data.path("Config"), host = (ObjectNode)data.path("HostConfig");
        ((ObjectNode)config.path("Labels")).put(Ownership.HELPER_LABEL, marker);
        config.put("User", "0:0").set("Entrypoint", JSON.valueToTree(List.of("/bin/sleep"))); config.set("Cmd", JSON.valueToTree(List.of("infinity")));
        host.put("PidMode", "container:" + BUILDER_ID).put("ShmSize", 1024L * 1024 * 1024).set("CapAdd", JSON.valueToTree(List.of("SYS_ADMIN", "SYS_PTRACE")));
        host.set("SecurityOpt", JSON.valueToTree(List.of("seccomp=unconfined", "apparmor=unconfined"))); return data;
    }
    static Path manifest(Path root) throws Exception {
        Path nativeDir = Files.createDirectories(root.resolve("containers/native/patches"));
        Path patch = nativeDir.resolve("glibc-CVE-2026-18374.patch"); Files.writeString(patch, "synthetic unit patch");
        ObjectNode input = JSON.createObjectNode().put("local_version", "2.39-test");
        input.set("source_files_sha256", JSON.createObjectNode().put("source.dsc", "1".repeat(64)));
        input.set("patches", JSON.createArrayNode().add(JSON.createObjectNode().put("sha256", sha(patch))));
        writeJson(root.resolve("containers/native/glibc-inputs.json"), input, false); return root;
    }
    static final class Harness implements Runner {
        final List<List<String>> calls = new ArrayList<>();
        ObjectNode builder = builder(), helper;
        boolean wrongCleanup, bindCleanup; int helperInspections, removeStatus, unmountStatus, packageStatus, buildResult = 0;
        String existing = "missing", finalRc = "0", preflight = "clean"; int rcReads;
        Harness() throws Exception {}
        public Result run(List<String> command, byte[] input, Duration timeout) throws Exception {
            calls.add(List.copyOf(command));
            if (command.subList(0, 2).equals(List.of("docker", "inspect"))) {
                JsonNode data;
                if (command.getLast().equals(HELPER_ID)) {
                    helperInspections++; ObjectNode view = helper.deepCopy();
                    if (helperInspections > 1 && wrongCleanup) view.put("Image", "sha256:" + "f".repeat(64));
                    if (helperInspections > 1 && bindCleanup) ((ObjectNode)view.path("HostConfig")).set("Binds", JSON.valueToTree(List.of("/host:/work")));
                    data = view;
                } else data = builder;
                return Result.text(0, JSON.writeValueAsString(JSON.createArrayNode().add(data)));
            }
            if (command.subList(0, 2).equals(List.of("docker", "create"))) {
                String name = command.get(command.indexOf("--name") + 1), label = command.get(command.indexOf("--label") + 1);
                helper = helper(name, label.substring(label.indexOf('=') + 1)); return Result.text(0, HELPER_ID + "\n");
            }
            if (command.subList(0, 2).equals(List.of("docker", "rm"))) return Result.text(removeStatus, "");
            String script = command.getLast();
            if (script.contains("if mountpoint -q")) return Result.text(unmountStatus, "");
            if (script.equals(LibcBuild.preflightScript())) return Result.text(0, preflight);
            if (script.startsWith("sha256sum ")) return Result.text(0, "1".repeat(64) + " source.dsc\n");
            if (script.startsWith("grep -c")) return Result.text(0, "1\n");
            if (script.equals("chroot /work/root date -R")) return Result.text(0, "Sat, 31 Oct 2026 00:00:00 +0000\n");
            if (script.equals("cat /work/root/build/glibc-2.39/debian/changelog")) return Result.text(0, "original changelog\n");
            if (script.contains("cat /work/root/build/build.rc")) return Result.text(0, rcReads++ == 0 ? existing : finalRc);
            if (command.contains("unshare")) return Result.text(buildResult, "");
            if (script.startsWith("ls /work/root/build/libc6_")) return Result.text(0, "existing-package");
            if (script.equals("ls /work/root/build/*.deb")) return Result.text(0, "/work/root/build/libc6_2.39-test_amd64.deb /work/root/build/libc-bin_2.39-test_amd64.deb /work/root/build/libc6-dbg_2.39-test_amd64.deb /work/root/build/unselected.deb");
            if (script.startsWith("cat /work/root/build/") && script.endsWith(".deb")) return Result.text(packageStatus, "synthetic package, not a real deb");
            return Result.text(0, "");
        }
    }
}
