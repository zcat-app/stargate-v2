// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Exact inspect-time helper identity, command, isolation and mount validation. */
final class HelperPolicy {
    record Mount(String type, String source, String destination, boolean writable) {}
    record Spec(String id, String created, String name, String image, Map<String,String> labels, String user,
                List<String> entrypoint, List<String> command, Set<String> capabilities, Map<String,String> tmpfs,
                Set<Mount> mounts, Set<String> volumeNames) {}
    private HelperPolicy() {}
    static void validate(JsonNode c, Spec s) throws IOException {
        DockerPolicy.containerId(s.id()); DockerPolicy.imageId(s.image());
        JsonNode config = c.path("Config"), host = c.path("HostConfig"), mounts = c.path("Mounts");
        if (!DockerPolicy.text(c, "Id").equals(s.id()) || !DockerPolicy.text(c, "Created").equals(s.created()) || s.created().isEmpty()
                || !DockerPolicy.text(c, "Name").equals("/" + s.name()) || !DockerPolicy.text(c, "Image").equals(s.image())
                || !config.isObject() || !host.isObject() || !mounts.isArray() || !stringMap(config.path("Labels")).equals(s.labels())
                || !DockerPolicy.text(config, "User").equals(s.user()) || !strings(config.path("Entrypoint")).equals(s.entrypoint())
                || !strings(config.path("Cmd")).equals(s.command()) || !strings(config.path("Healthcheck").path("Test")).equals(List.of("NONE"))
                || !DockerPolicy.text(host, "NetworkMode").equals("none") || !isBoolean(host, "ReadonlyRootfs", true)
                || !isBoolean(host, "Privileged", false) || !strings(host.path("CapDrop")).equals(List.of("ALL"))
                || !caps(host.path("CapAdd")).equals(s.capabilities()) || !strings(host.path("SecurityOpt")).equals(List.of("no-new-privileges"))
                || !DockerPolicy.text(host, "UsernsMode").equals("host") || !integer(host, "Memory", 512L * 1024 * 1024)
                || !integer(host, "MemorySwap", 512L * 1024 * 1024) || !integer(host, "NanoCpus", 2_000_000_000L)
                || !integer(host, "PidsLimit", 128) || nonempty(host.path("PortBindings")) || truthy(host.path("PublishAllPorts"))
                || nonempty(host.path("PidMode")) || !(host.path("IpcMode").isMissingNode() || host.path("IpcMode").isNull() || host.path("IpcMode").asText().isEmpty() || host.path("IpcMode").asText().equals("private"))
                || nonempty(host.path("UTSMode")) || nonempty(host.path("Devices")) || nonempty(host.path("VolumesFrom"))
                || !stringMap(host.path("Tmpfs")).equals(s.tmpfs()) || !limits(host.path("Ulimits")) || !logs(host.path("LogConfig"))) throw DockerPolicy.failure();
        Set<Mount> actual = new HashSet<>();
        for (JsonNode m : mounts) {
            String type = DockerPolicy.text(m, "Type"), source = DockerPolicy.text(m, type.equals("volume") ? "Name" : "Source");
            JsonNode writable = m.get("RW"); if (writable == null || !writable.isBoolean()) throw DockerPolicy.failure();
            if (!actual.add(new Mount(type, source, DockerPolicy.text(m, "Destination"), writable.booleanValue()))) throw DockerPolicy.failure();
        }
        if (!actual.equals(s.mounts()) || actual.size() != mounts.size()) throw DockerPolicy.failure();
        Map<String,Boolean> expectedVolumes = new HashMap<>();
        for (Mount mount : s.mounts()) if (mount.type().equals("volume") && expectedVolumes.put(mount.source(), !mount.writable()) != null) throw DockerPolicy.failure();
        if (!expectedVolumes.keySet().equals(s.volumeNames())) throw DockerPolicy.failure();
        Map<String,Boolean> volumes = new HashMap<>(); JsonNode options = host.path("Mounts");
        if (!options.isArray()) throw DockerPolicy.failure();
        for (JsonNode option : options) if (option.path("Type").asText().equals("volume")) {
            String name = DockerPolicy.text(option, "Source");
            JsonNode readOnly = option.get("ReadOnly");
            if (readOnly != null && !readOnly.isNull() && !readOnly.isBoolean()) throw DockerPolicy.failure();
            boolean readonly = readOnly != null && readOnly.isBoolean() && readOnly.booleanValue();
            if (!isBoolean(option.path("VolumeOptions"), "NoCopy", true) || volumes.put(name, readonly) != null) throw DockerPolicy.failure();
        }
        if (!volumes.equals(expectedVolumes)) throw DockerPolicy.failure();
    }
    static void finished(JsonNode c) throws IOException {
        JsonNode state = c.path("State");
        if (!isBoolean(state, "Running", false) || !state.path("Status").asText().equals("exited") || !isBoolean(state, "OOMKilled", false)
                || truthy(state.path("Dead")) || !integer(state, "ExitCode", 0)) throw DockerPolicy.failure();
    }
    private static boolean logs(JsonNode log) throws IOException {
        return log.isObject() && log.path("Type").asText().equals("local")
                && stringMap(log.path("Config")).equals(Map.of("max-size", "1m", "max-file", "1", "compress", "false"));
    }
    private static boolean limits(JsonNode limits) {
        if (!limits.isArray()) return false; boolean core = false, size = false;
        for (JsonNode value : limits) {
            if (value.path("Name").asText().equals("core")) { if (core || !integer(value, "Soft", 0) || !integer(value, "Hard", 0)) return false; core = true; }
            if (value.path("Name").asText().equals("fsize")) { if (size || !integer(value, "Soft", ArchiveInspector.MAX_ARCHIVE) || !integer(value, "Hard", ArchiveInspector.MAX_ARCHIVE)) return false; size = true; }
        }
        return core && size;
    }
    private static Set<String> caps(JsonNode array) throws IOException {
        if (array.isNull() || array.isMissingNode()) return Set.of();
        List<String> raw = strings(array); Set<String> result = new HashSet<>();
        for (String cap : raw) if (!result.add(cap.startsWith("CAP_") ? cap.substring(4) : cap)) throw DockerPolicy.failure();
        return result;
    }
    static List<String> strings(JsonNode array) throws IOException {
        if (!array.isArray()) throw DockerPolicy.failure(); List<String> result = new ArrayList<>();
        for (JsonNode value : array) { if (!value.isTextual()) throw DockerPolicy.failure(); result.add(value.textValue()); } return result;
    }
    static Map<String,String> stringMap(JsonNode node) throws IOException {
        if (node.isNull() || node.isMissingNode()) return Map.of();
        if (!node.isObject()) throw DockerPolicy.failure(); Map<String,String> result = new HashMap<>();
        var fields = node.fields(); while (fields.hasNext()) { var field = fields.next(); if (!field.getValue().isTextual()) throw DockerPolicy.failure(); result.put(field.getKey(), field.getValue().textValue()); }
        return result;
    }
    private static boolean integer(JsonNode n, String key, long value) { JsonNode v = n.get(key); return v != null && v.isIntegralNumber() && v.canConvertToLong() && v.longValue() == value; }
    private static boolean isBoolean(JsonNode n, String key, boolean value) { JsonNode v = n.get(key); return v != null && v.isBoolean() && v.booleanValue() == value; }
    private static boolean truthy(JsonNode node) { return !node.isMissingNode() && !node.isNull() && (!node.isBoolean() || node.booleanValue()); }
    private static boolean nonempty(JsonNode node) {
        if (node.isNull() || node.isMissingNode()) return false;
        if (node.isTextual()) return !node.textValue().isEmpty();
        if (node.isContainerNode()) return !node.isEmpty();
        return true;
    }
}
