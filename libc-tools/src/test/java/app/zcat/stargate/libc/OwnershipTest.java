/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;
import static app.zcat.stargate.libc.Fixtures.*;

class OwnershipTest {
    @TempDir Path root;
    @Test void freshArgumentsAndIdentityFailClosed() throws Exception {
        Ownership.fresh(builder(), BUILDER_ID, IMAGE, MARKER);
        assertThrows(Exception.class, () -> Ownership.freshArguments("a".repeat(12), IMAGE, MARKER));
        for (String field : List.of("Id", "Name", "Image")) { var data = builder(); data.put(field, "wrong"); assertThrows(Exception.class, () -> Ownership.fresh(data, BUILDER_ID, IMAGE, MARKER)); }
        var stopped = builder(); ((ObjectNode)stopped.path("State")).put("Running", false); assertThrows(Exception.class, () -> Ownership.fresh(stopped, BUILDER_ID, IMAGE, MARKER));
        var unlabeled = builder(); ((ObjectNode)unlabeled.path("Config").path("Labels")).removeAll(); assertThrows(Exception.class, () -> Ownership.fresh(unlabeled, BUILDER_ID, IMAGE, MARKER));
    }
    @Test void hostSharedDeviceNetworkAndMountResourcesAreRejected() throws Exception {
        Map<String, Object> bad = new LinkedHashMap<>();
        bad.put("Binds", List.of("/host:/work")); bad.put("VolumesFrom", List.of("other")); bad.put("Mounts", List.of(Map.of("Type", "bind", "Source", "/host", "Target", "/work"))); bad.put("Tmpfs", Map.of("/other", "")); bad.put("PidMode", "host"); bad.put("IpcMode", "shareable"); bad.put("UTSMode", "host"); bad.put("NetworkMode", "host"); bad.put("Privileged", true); bad.put("PortBindings", Map.of("80/tcp", List.of(Map.of("HostPort", "80")))); bad.put("PublishAllPorts", true); bad.put("Devices", List.of(Map.of("PathOnHost", "/dev/sda"))); bad.put("DeviceRequests", List.of(Map.of("Driver", "test"))); bad.put("DeviceCgroupRules", List.of("c *:* rwm")); bad.put("Links", List.of("other")); bad.put("CgroupnsMode", "host"); bad.put("UsernsMode", "host");
        for (var entry : bad.entrySet()) { var data = builder(); ((ObjectNode)data.path("HostConfig")).set(entry.getKey(), JSON.valueToTree(entry.getValue())); assertFalse(Ownership.privateResources(data, true, Set.of("", "private"), false), entry.getKey()); }
        var volumes = builder(); ((ObjectNode)volumes.path("Config")).set("Volumes", JSON.valueToTree(Map.of("/work", Map.of()))); assertFalse(Ownership.privateResources(volumes, true, Set.of("", "private"), false));
        var networks = builder(); ((ObjectNode)networks.path("NetworkSettings").path("Networks")).set("foreign", JSON.createObjectNode()); assertFalse(Ownership.privateResources(networks, true, Set.of("", "private"), false));
    }
    @Test void onlyOwnedWorkTmpfsIsAccepted() throws Exception {
        var data = builder(); ((ObjectNode)data.path("HostConfig")).set("Tmpfs", JSON.valueToTree(Map.of("/work", "size=1g"))); Ownership.fresh(data, BUILDER_ID, IMAGE, MARKER);
        data = builder(); ((ObjectNode)data.path("HostConfig")).set("Mounts", JSON.valueToTree(List.of(Map.of("Type", "tmpfs", "Target", "/work")))); Ownership.fresh(data, BUILDER_ID, IMAGE, MARKER);
        data = builder(); data.set("Mounts", JSON.valueToTree(List.of(Map.of("Type", "tmpfs", "Destination", "/work")))); Ownership.fresh(data, BUILDER_ID, IMAGE, MARKER);
        data.set("Mounts", JSON.valueToTree(List.of(Map.of("Type", "volume", "Destination", "/work")))); assertFalse(Ownership.privateResources(data, true, Set.of("", "private"), false));
    }
    @Test void capabilityPrefixNormalizationNeverAcceptsDuplicatesOrExtraPrivileges() {
        for (List<String> values : List.of(List.of("SYS_ADMIN", "SYS_PTRACE"), List.of("CAP_SYS_ADMIN", "CAP_SYS_PTRACE"), List.of("SYS_ADMIN", "CAP_SYS_PTRACE"))) assertTrue(Ownership.capabilities(JSON.valueToTree(values)));
        for (Object value : List.of("CAP_SYS_ADMIN", List.of(), List.of("SYS_ADMIN", "SYS_ADMIN"), List.of("CAP_SYS_ADMIN", "SYS_ADMIN"), List.of("CAP_CAP_SYS_ADMIN", "SYS_PTRACE"), List.of("SYS_ADMIN", "NET_ADMIN"), List.of("SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"))) assertFalse(Ownership.capabilities(JSON.valueToTree(value)));
    }
    @Test void helperCommandsEnterBuilderNamespaceAndCleanOnlyCapturedId() throws Exception {
        var harness = new Harness(); LibcIO io = new LibcIO(root, harness);
        try (var helper = new Ownership.Helper(io, BUILDER_ID, IMAGE)) { helper.start(); }
        assertTrue(harness.calls.stream().anyMatch(c -> c.equals(List.of("docker", "rm", "--force", HELPER_ID))));
        assertTrue(harness.calls.stream().anyMatch(c -> c.contains("nsenter") && c.contains("--root") && c.contains("--wd")));
        assertFalse(harness.calls.stream().anyMatch(c -> c.contains(TEST_BUILDER)));
        var create = harness.calls.getFirst(); assertEquals("bridge", create.get(create.indexOf("--network") + 1)); assertEquals("container:" + BUILDER_ID, create.get(create.indexOf("--pid") + 1));
    }
    @Test void changedCleanupIdentityOrResourcesCauseNoUnmountOrRemove() throws Exception {
        for (boolean bind : List.of(false, true)) {
            var harness = new Harness(); harness.wrongCleanup = !bind; harness.bindCleanup = bind;
            var helper = new Ownership.Helper(new LibcIO(root, harness), BUILDER_ID, IMAGE);
            assertThrows(Exception.class, helper::close);
            assertFalse(harness.calls.stream().anyMatch(c -> c.get(1).equals("rm") || c.getLast().contains("if mountpoint -q")));
        }
    }
    @Test void cleanupErrorsAreSurfacedAndRemovalStillAttempted() throws Exception {
        for (boolean unmount : List.of(false, true)) {
            var harness = new Harness(); if (unmount) harness.unmountStatus = 1; else harness.removeStatus = 1;
            var helper = new Ownership.Helper(new LibcIO(root, harness), BUILDER_ID, IMAGE);
            assertTrue(assertThrows(Exception.class, helper::close).getMessage().contains("cleanup failed"));
            assertTrue(harness.calls.stream().anyMatch(c -> c.equals(List.of("docker", "rm", "--force", HELPER_ID))));
        }
    }
}
