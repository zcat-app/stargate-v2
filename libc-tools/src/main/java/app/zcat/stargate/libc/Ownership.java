/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.*;
import static app.zcat.stargate.libc.LibcIO.*;

final class Ownership {
    static final String FRESH_LABEL = "org.stargate.libc.fresh-builder", HELPER_LABEL = "org.stargate.libc.mount-helper";
    static final String RUNNER_LABEL = "org.stargate.libc.regression-runner";
    static String token() { byte[] value = new byte[16]; new SecureRandom().nextBytes(value); return HexFormat.of().formatHex(value); }
    static boolean absent(JsonNode value) { return value.isMissingNode() || value.isNull() || (value.isContainerNode() && value.isEmpty()) || (value.isTextual() && value.asText().isEmpty()) || (value.isBoolean() && !value.asBoolean()); }
    static boolean oneOf(JsonNode value, String... choices) { return value.isTextual() && List.of(choices).contains(value.asText()); }
    static boolean privateResources(JsonNode data, boolean workTmpfs, Set<String> pidModes, boolean privileged) {
        JsonNode host = data.path("HostConfig"), network = data.path("NetworkSettings"), config = data.path("Config"), mounts = data.path("Mounts");
        if (!host.isObject() || !network.isObject() || !config.isObject() || !mounts.isArray()) return false;
        for (String field : List.of("Binds", "VolumesFrom", "PortBindings", "Devices", "DeviceRequests", "DeviceCgroupRules", "Links")) if (!absent(host.path(field))) return false;
        if (!absent(config.path("Volumes")) || !host.path("Privileged").isBoolean() || host.path("Privileged").asBoolean() != privileged || !host.path("PublishAllPorts").isBoolean() || host.path("PublishAllPorts").asBoolean() || !pidModes.contains(host.path("PidMode").asText("<missing>")) || host.path("CgroupnsMode").asText().equals("host") || host.path("UsernsMode").asText().equals("host") || !oneOf(host.path("IpcMode"), "", "private") || !oneOf(host.path("UTSMode"), "", "private") || !oneOf(host.path("NetworkMode"), "default", "bridge", "none")) return false;
        JsonNode ports = network.path("Ports"), networks = network.path("Networks");
        if (!ports.isObject() || !networks.isObject()) return false;
        for (JsonNode port : ports) if (!absent(port)) return false;
        for (String name : names(networks)) if (!List.of("bridge", "none").contains(name)) return false;
        JsonNode tmpfs = host.path("Tmpfs"), configured = host.path("Mounts");
        if (!absent(tmpfs)) { if (!tmpfs.isObject() || !workTmpfs || tmpfs.size() > 1 || !tmpfs.has("/work")) return false; }
        if (!absent(configured)) {
            if (!configured.isArray() || configured.size() > (workTmpfs ? 1 : 0)) return false;
            for (JsonNode mount : configured) if (!mount.isObject() || !mount.path("Type").asText().equals("tmpfs") || !mount.path("Target").asText().equals("/work") || !absent(mount.path("Source"))) return false;
        }
        if (mounts.size() > (workTmpfs ? 1 : 0)) return false;
        for (JsonNode mount : mounts) if (!mount.isObject() || !mount.path("Type").asText().equals("tmpfs") || !mount.path("Destination").asText().equals("/work")) return false;
        return true;
    }
    static void freshArguments(String builder, String image, String marker) throws IOException {
        need(builder.matches("[0-9a-f]{64}") && image.matches("sha256:[0-9a-f]{64}") && marker.matches("[0-9a-f]{32}"), "Fresh builder requires full container ID, image ID and 32-hex marker");
    }
    static void fresh(JsonNode data, String builder, String image, String marker) throws IOException {
        freshArguments(builder, image, marker);
        String name = data.path("Name").asText();
        need(data.path("Id").asText().equals(builder) && name.matches("/[A-Za-z0-9][A-Za-z0-9_.-]*") && !List.of("/" + BUILDER, "/" + TEST_BUILDER).contains(name) && data.path("Image").asText().equals(image) && data.path("State").path("Running").isBoolean() && data.path("State").path("Running").asBoolean() && data.path("Config").path("Labels").path(FRESH_LABEL).asText().equals(marker), "Fresh builder identity, image, running state or label mismatch");
        need(privateResources(data, true, Set.of("", "private"), false), "Fresh builder has host, shared or unexpected resources");
    }
    static boolean capabilities(JsonNode value) {
        if (!value.isArray() || value.size() != 2) return false;
        Set<String> names = new HashSet<>();
        for (JsonNode item : value) { if (!item.isTextual()) return false; String name = item.asText(); if (name.startsWith("CAP_")) name = name.substring(4); if (!Set.of("SYS_ADMIN", "SYS_PTRACE").contains(name)) return false; names.add(name); }
        return names.equals(Set.of("SYS_ADMIN", "SYS_PTRACE"));
    }
    static void helper(JsonNode data, String helper, String name, String image, String builder, String marker) throws IOException {
        JsonNode config = data.path("Config"), host = data.path("HostConfig");
        List<String> security = new ArrayList<>(); if (host.path("SecurityOpt").isArray()) for (JsonNode item : host.path("SecurityOpt")) security.add(item.asText()); Collections.sort(security);
        need(data.path("Id").asText().equals(helper) && data.path("Name").asText().equals("/" + name) && data.path("Image").asText().equals(image) && config.path("Labels").path(HELPER_LABEL).asText().equals(marker) && privateResources(data, false, Set.of("container:" + builder), false) && host.path("NetworkMode").asText().equals("bridge") && config.path("User").asText().equals("0:0") && config.path("Entrypoint").equals(JSON.valueToTree(List.of("/bin/sleep"))) && config.path("Cmd").equals(JSON.valueToTree(List.of("infinity"))) && capabilities(host.path("CapAdd")) && absent(host.path("CapDrop")) && security.equals(List.of("apparmor=unconfined", "seccomp=unconfined")) && host.path("ShmSize").asLong(-1) == 1024L * 1024 * 1024, "Mount helper identity or configuration mismatch; no cleanup attempted");
    }
    static List<String> helperCommand(String name, String marker, String builder, String image) {
        return List.of("docker", "create", "--name", name, "--label", HELPER_LABEL + "=" + marker, "--network", "bridge", "--user", "0:0", "--pid", "container:" + builder, "--cap-add", "SYS_ADMIN", "--cap-add", "SYS_PTRACE", "--security-opt", "seccomp=unconfined", "--security-opt", "apparmor=unconfined", "--shm-size", "1g", "--entrypoint", "/bin/sleep", image, "infinity");
    }
    static final class Helper implements AutoCloseable {
        final LibcIO io; final String id, name, image, builder, marker;
        Helper(LibcIO io, String builder, String image) throws Exception {
            this.io = io; this.builder = builder; this.image = image; marker = token(); name = "stargate-libc-check-" + marker;
            id = io.checked(helperCommand(name, marker, builder, image)).text().strip();
            need(id.matches("[0-9a-f]{64}"), "Mount helper returned invalid ID; inspect only owned candidate " + name);
            verify();
        }
        Target start() throws Exception {
            System.out.println("Mount helper: id=" + id + " name=" + name + " label=" + HELPER_LABEL + "=" + marker);
            try {
                io.checked(List.of("docker", "start", id));
                Target target = new Target(id, true);
                io.shell(target, "mount --make-rprivate /work && mkdir -p " + CHROOT + "/proc " + CHROOT + "/dev && mount -t proc proc " + CHROOT + "/proc && mount --rbind /dev " + CHROOT + "/dev && mount --make-rslave " + CHROOT + "/dev");
                io.shell(target, "chroot " + CHROOT + " /bin/bash -c 'test \"$(cat <(printf ready))\" = ready && test -d /proc/self/fd && test -d /dev/pts && test -d /dev/shm'");
                return target;
            } catch (Exception failure) { throw failure; }
        }
        void verify() throws Exception { helper(io.inspect(id), id, name, image, builder, marker); }
        public void close() throws Exception {
          try (var cleanup = Cancellation.cleanup()) {
            verify();
            Result unmount = io.shellResult(new Target(id, true), "set -e; if mountpoint -q " + CHROOT + "/dev; then umount --recursive --lazy " + CHROOT + "/dev; fi; if mountpoint -q " + CHROOT + "/proc; then umount --lazy " + CHROOT + "/proc; fi");
            Result remove = io.command(List.of("docker", "rm", "--force", id));
            need(unmount.status() == 0 && remove.status() == 0, "Mount helper cleanup failed for " + id + ": unmount=" + unmount.status() + ", remove=" + remove.status());
          }
        }
    }
}
