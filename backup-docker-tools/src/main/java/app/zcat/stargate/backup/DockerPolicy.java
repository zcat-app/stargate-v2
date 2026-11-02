// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Strict, read-only validation shared by the offline Docker adapters. */
final class DockerPolicy {
    static final List<String> BASE = List.of("app-data", "tor-data", "tor-control", "i2p-data", "i2p-control");
    static final List<String> NYM = List.of("nym-data", "nym-secrets");
    static final String LABEL = "org.stargate.offline-import", ROLE = "org.stargate.offline-import-role";
    private static final ObjectMapper JSON = new ObjectMapper().enable(JsonParser.Feature.STRICT_DUPLICATE_DETECTION).enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private DockerPolicy() {}
    static JsonNode parse(String value) throws IOException {
        if (value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 1024 * 1024) throw failure();
        JsonNode node = JSON.readTree(value); if (node == null) throw failure(); return node;
    }
    static String json(Object value) throws IOException { return JSON.writeValueAsString(value); }
    static List<String> roots(boolean nym) { var roots = new ArrayList<>(BASE); if (nym) roots.addAll(NYM); return List.copyOf(roots); }
    static void imageId(String id) throws IOException { if (id == null || !id.matches("sha256:[0-9a-f]{64}")) throw failure(); }
    static void token(String id) throws IOException { if (id == null || !id.matches("[0-9a-f]{32}")) throw failure(); }
    static void containerId(String id) throws IOException { if (id == null || !id.matches("[0-9a-f]{64}")) throw failure(); }
    static void attachments(Set<String> actual, Set<String> allowed) throws IOException {
        for (String id : actual) containerId(id); for (String id : allowed) containerId(id);
        if (!allowed.containsAll(actual)) throw failure();
    }
    record Selection(Map<String,String> volumes, Set<String> containers) {}
    static Selection readSelection(Path path, boolean nym, int uid) throws IOException {
        int fd = Linux.openRegular(Linux.absolute(path.toString()), 65536, true, uid);
        try {
            Linux.Stat before = Linux.stat(fd); byte[] data;
            try (InputStream stream = Files.newInputStream(Linux.fdPath(fd))) { data = stream.readNBytes(65537); }
            if (data.length > 65536 || !before.equals(Linux.stat(fd))) throw failure();
            try {
                String value = java.nio.charset.StandardCharsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                        .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(data)).toString();
                return selection(parse(value), nym);
            } catch (java.nio.charset.CharacterCodingException e) { throw failure(); }
        } finally { Linux.close(fd); }
    }
    static Selection selection(JsonNode json, boolean nym) throws IOException {
        if (!json.isObject() || !fields(json).equals(Set.of("version", "volumes", "containers"))
                || !json.path("version").isInt() || json.path("version").intValue() != 1) throw failure();
        JsonNode v = json.path("volumes"), c = json.path("containers");
        if (!v.isObject() || !fields(v).equals(Set.copyOf(roots(nym))) || !c.isArray() || c.size() > 16) throw failure();
        Map<String,String> names = new HashMap<>(); Set<String> unique = new HashSet<>(), writers = new HashSet<>();
        for (String role : roots(nym)) {
            JsonNode value = v.get(role); if (!value.isTextual() || !value.textValue().matches("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}") || !unique.add(value.textValue())) throw failure();
            names.put(role, value.textValue());
        }
        for (JsonNode id : c) {
            if (!id.isTextual()) throw failure(); containerId(id.textValue()); if (!writers.add(id.textValue())) throw failure();
        }
        return new Selection(Map.copyOf(names), Set.copyOf(writers));
    }
    static JsonNode importVolume(JsonNode v, String name, String token, String role) throws IOException {
        token(token);
        if (!v.isObject() || !text(v, "Name").equals(name) || !text(v, "Driver").equals("local") || !text(v, "Scope").equals("local")
                || !(v.path("Options").isMissingNode() || v.path("Options").isNull() || (v.path("Options").isObject() && v.path("Options").isEmpty()))) throw failure();
        JsonNode labels = v.path("Labels");
        if (!labels.isObject() || !fields(labels).equals(Set.of(LABEL, ROLE)) || !text(labels, LABEL).equals(token) || !text(labels, ROLE).equals(role)) throw failure();
        String created = text(v, "CreatedAt"), mount = text(v, "Mountpoint");
        if (created.isEmpty() || !mount.startsWith("/") || mount.startsWith("//")) throw failure();
        return project(v, "Name", "Driver", "Scope", "Options", "Labels", "CreatedAt", "Mountpoint");
    }
    static JsonNode captureVolume(JsonNode v, String name) throws IOException {
        if (!v.isObject() || !text(v, "Name").equals(name) || !text(v, "Driver").equals("local") || !text(v, "Scope").equals("local")
                || !(v.path("Options").isMissingNode() || v.path("Options").isNull() || (v.path("Options").isObject() && v.path("Options").isEmpty()))
                || text(v, "CreatedAt").isEmpty() || !text(v, "Mountpoint").startsWith("/") || json(v).getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 65536) throw failure();
        return project(v, "Name", "Driver", "Scope", "Options", "Mountpoint", "CreatedAt", "Labels");
    }
    static Set<String> fields(JsonNode node) { Set<String> names = new HashSet<>(); node.fieldNames().forEachRemaining(names::add); return names; }
    static String text(JsonNode node, String key) throws IOException { JsonNode value = node.get(key); if (value == null || !value.isTextual()) throw failure(); return value.textValue(); }
    static ObjectNode project(JsonNode node, String... names) {
        ObjectNode out = JSON.createObjectNode(); for (String name : names) out.set(name, node.has(name) ? node.get(name).deepCopy() : JSON.nullNode()); return out;
    }
    static IOException failure() { return new IOException("Offline Docker validation failed"); }
}
