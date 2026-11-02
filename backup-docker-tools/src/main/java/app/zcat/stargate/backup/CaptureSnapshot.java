// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/** Stable identities for attested, stopped local source volumes and writers. */
final class CaptureSnapshot {
    record Snapshot(String daemon, Map<String,JsonNode> volumes, Map<String,JsonNode> writers) {}
    private CaptureSnapshot() {}
    static Snapshot inspect(DockerTransport docker, DockerPolicy.Selection selected, Set<String> helpers, Snapshot expected) throws Exception {
        JsonNode id = DockerPolicy.parse(docker.call("info", "--format", "{{json .ID}}"));
        if (!id.isTextual() || id.textValue().isEmpty() || (expected != null && !expected.daemon().equals(id.textValue()))) throw DockerPolicy.failure();
        Map<String,JsonNode> volumes = new HashMap<>(), writers = new HashMap<>(); Set<String> attached = new HashSet<>();
        Set<String> allowed = new HashSet<>(selected.containers()); allowed.addAll(helpers);
        for (var entry : selected.volumes().entrySet()) {
            JsonNode volume = DockerPolicy.captureVolume(docker.inspect("volume", entry.getValue()), entry.getValue());
            volumes.put(entry.getKey(), volume);
            Set<String> found = lines(docker.call("ps", "-a", "--no-trunc", "--filter", "volume=" + entry.getValue(), "--format", "{{.ID}}"));
            DockerPolicy.attachments(found, allowed); attached.addAll(found);
        }
        if (!attached.containsAll(selected.containers())) throw DockerPolicy.failure();
        for (String writer : selected.containers()) {
            JsonNode c = docker.inspect("container", writer), state = c.path("State");
            if (!DockerPolicy.text(c, "Id").equals(writer) || !state.isObject() || !state.path("Running").isBoolean() || state.path("Running").booleanValue()
                    || !(state.path("Status").asText().equals("created") || state.path("Status").asText().equals("exited"))
                    || trueOrMalformed(state, "Paused") || trueOrMalformed(state, "Restarting") || trueOrMalformed(state, "Dead")
                    || DockerPolicy.json(c).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65536) throw DockerPolicy.failure();
            ObjectNode info = DockerPolicy.project(c, "Id", "Name", "Image", "Mounts", "State");
            if (info.path("Mounts").isArray()) {
                ArrayList<JsonNode> mounts = new ArrayList<>(); info.path("Mounts").forEach(m -> mounts.add(canonical(m)));
                mounts.sort(Comparator.comparing(JsonNode::toString)); ArrayNode stable = JsonNodeFactory.instance.arrayNode(); mounts.forEach(stable::add); info.set("Mounts", stable);
            }
            writers.put(writer, info);
        }
        Snapshot result = new Snapshot(id.textValue(), Map.copyOf(volumes), Map.copyOf(writers));
        if (expected != null && !expected.equals(result)) throw DockerPolicy.failure();
        return result;
    }
    static void rootful(JsonNode security) throws IOException {
        if (!security.isArray()) throw DockerPolicy.failure();
        for (JsonNode item : security) if (!item.isTextual() || item.textValue().startsWith("name=rootless")) throw DockerPolicy.failure();
    }
    static Set<String> lines(String value) { Set<String> result = new HashSet<>(); value.lines().filter(s -> !s.isEmpty()).forEach(result::add); return result; }
    private static boolean trueOrMalformed(JsonNode node, String name) {
        JsonNode v = node.get(name); return v != null && (!v.isBoolean() || v.booleanValue());
    }
    private static JsonNode canonical(JsonNode node) {
        if (node.isObject()) {
            ObjectNode out = JsonNodeFactory.instance.objectNode();
            ArrayList<String> names = new ArrayList<>(); node.fieldNames().forEachRemaining(names::add); names.sort(String::compareTo);
            for (String name : names) out.set(name, canonical(node.get(name))); return out;
        }
        if (node.isArray()) { ArrayNode out = JsonNodeFactory.instance.arrayNode(); node.forEach(v -> out.add(canonical(v))); return out; }
        return node.deepCopy();
    }
}
