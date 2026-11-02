// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Transactional controller for fresh, isolated stopped-volume imports. */
final class DockerImport {
    private static final String ENTRYPOINT = "/opt/java/bin/java";
    private static final String INIT = "app.zcat.stargate.backup.InitRoots";
    private static final String COPY = "app.zcat.stargate.backup.VolumeImport";
    private static final String CLASSPATH = "/tool/core.jar:/tool/adapter.jar";
    interface Journal { void record(String event, Map<String, ?> fields) throws Exception; }
    interface SourceGuard { void check() throws Exception; }
    record Plan(String token, String image, String source, String coreJar, String adapterJar, Map<String,String> hashes, boolean nym) {}
    private DockerImport() {}
    static void run(Plan plan, DockerTransport docker, Journal journal, SourceGuard sourceGuard) throws Exception {
        DockerPolicy.token(plan.token()); DockerPolicy.imageId(plan.image());
        for (String path : List.of(plan.source(), plan.coreJar(), plan.adapterJar())) DurableJournal.safePath(path);
        List<String> roots = DockerPolicy.roots(plan.nym());
        Map<String,String> names = new java.util.LinkedHashMap<>(), containers = Map.of(
                "init", "stargate-import-" + plan.token() + "-init", "copy", "stargate-import-" + plan.token() + "-copy");
        for (String role : roots) names.put(role, "stargate-import-" + plan.token() + "-" + role);
        if (!plan.hashes().keySet().equals(Set.of("core.jar", "adapter.jar")) || plan.hashes().values().stream().anyMatch(v -> !v.matches("[0-9a-f]{64}"))) throw DockerPolicy.failure();
        journal.record("planned", Map.ofEntries(Map.entry("schema", "java-volume-import-v1"), Map.entry("token", plan.token()), Map.entry("volumes", names),
                Map.entry("containers", containers), Map.entry("image", plan.image()), Map.entry("nym", plan.nym()), Map.entry("source", plan.source()),
                Map.entry("core_jar", plan.coreJar()), Map.entry("adapter_jar", plan.adapterJar()), Map.entry("sha256", plan.hashes())));
        JsonNode daemonNode = DockerPolicy.parse(docker.call("info", "--format", "{{json .ID}}"));
        if (!daemonNode.isTextual() || daemonNode.textValue().isEmpty()) throw DockerPolicy.failure();
        String daemon = daemonNode.textValue();
        CaptureSnapshot.rootful(DockerPolicy.parse(docker.call("info", "--format", "{{json .SecurityOptions}}")));
        JsonNode image = docker.inspect("image", plan.image()), cfg = image.path("Config");
        if (!DockerPolicy.text(image, "Id").equals(plan.image()) || !empty(cfg.path("Volumes"))) throw DockerPolicy.failure();
        Map<String,String> labels = new HashMap<>(HelperPolicy.stringMap(cfg.path("Labels"))); labels.put(DockerPolicy.LABEL, plan.token());
        if (!java.util.Collections.disjoint(names.values(), CaptureSnapshot.lines(docker.call("volume", "ls", "--format", "{{.Name}}")))
                || !java.util.Collections.disjoint(containers.values(), CaptureSnapshot.lines(docker.call("ps", "-a", "--format", "{{.Names}}")))) throw DockerPolicy.failure();
        sourceGuard.check(); journal.record("preflight", Map.of("daemon", daemon));
        Map<String,JsonNode> volumes = new HashMap<>(); Map<String,HelperPolicy.Spec> helpers = new HashMap<>();
        for (String role : roots) {
            guard(docker, plan, sourceGuard, daemon, names, volumes, helpers);
            String name = names.get(role); journal.record("volume_create_intent", Map.of("role", role, "name", name));
            if (!docker.call("volume", "create", "--driver", "local", "--label", DockerPolicy.LABEL + "=" + plan.token(),
                    "--label", DockerPolicy.ROLE + "=" + role, name).equals(name)) throw DockerPolicy.failure();
            JsonNode identity = DockerPolicy.importVolume(docker.inspect("volume", name), name, plan.token(), role);
            volumes.put(role, identity); journal.record("volume_created", Map.of("role", role, "identity", identity));
            guard(docker, plan, sourceGuard, daemon, names, volumes, helpers);
        }
        for (String role : List.of("init", "copy")) {
            guard(docker, plan, sourceGuard, daemon, names, volumes, helpers);
            boolean init = role.equals("init"); String user = init ? "0:0" : "10001:10001";
            Set<String> caps = init ? Set.of("CHOWN") : Set.of();
            Map<String,String> tmpfs = Map.of("/dest", init ? "mode=0700" : "uid=10001,gid=10001,mode=0700");
            List<String> command = new ArrayList<>(List.of("-XX:+PerfDisableSharedMem", "-XX:-CreateCoredumpOnCrash", "-XX:ErrorFile=/dev/null", "--enable-native-access=ALL-UNNAMED", "-cp", CLASSPATH, init ? INIT : COPY));
            if (init) command.addAll(roots); else { command.addAll(List.of("--source", "/source", "--destination", "/dest")); if (plan.nym()) command.add("--nym"); }
            Set<HelperPolicy.Mount> mounts = new HashSet<>(); List<String> mountArgs = new ArrayList<>();
            for (String root : roots) {
                mounts.add(new HelperPolicy.Mount("volume", names.get(root), "/dest/" + root, true));
                mountArgs.addAll(List.of("--mount", "type=volume,src=" + names.get(root) + ",dst=/dest/" + root + ",volume-nocopy"));
            }
            for (var binding : Map.of(plan.coreJar(), "/tool/core.jar", plan.adapterJar(), "/tool/adapter.jar").entrySet()) {
                mounts.add(new HelperPolicy.Mount("bind", binding.getKey(), binding.getValue(), false));
                mountArgs.addAll(List.of("--mount", "type=bind,src=" + binding.getKey() + ",dst=" + binding.getValue() + ",readonly"));
            }
            if (!init) {
                mounts.add(new HelperPolicy.Mount("bind", plan.source(), "/source", false));
                mountArgs.addAll(List.of("--mount", "type=bind,src=" + plan.source() + ",dst=/source,readonly"));
            }
            List<String> args = new ArrayList<>(List.of("create", "--name", containers.get(role), "--pull=never", "--no-healthcheck",
                    "--network", "none", "--read-only", "--user", user, "--userns", "host", "--cap-drop", "ALL"));
            if (init) args.addAll(List.of("--cap-add", "CHOWN"));
            args.addAll(List.of("--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m", "--memory-swap", "512m", "--cpus", "2",
                    "--ulimit", "core=0:0", "--ulimit", "fsize=" + ArchiveInspector.MAX_ARCHIVE + ":" + ArchiveInspector.MAX_ARCHIVE,
                    "--tmpfs", "/dest:" + tmpfs.get("/dest"), "--log-driver", "local", "--log-opt", "max-size=1m", "--log-opt", "max-file=1", "--log-opt", "compress=false",
                    "--label", DockerPolicy.LABEL + "=" + plan.token(), "--entrypoint", ENTRYPOINT));
            args.addAll(mountArgs); args.add(plan.image()); args.addAll(command);
            journal.record("container_create_intent", Map.of("role", role, "name", containers.get(role)));
            String id = docker.call(args.toArray(String[]::new)); DockerPolicy.containerId(id);
            JsonNode inspect = docker.inspect("container", id); String created = DockerPolicy.text(inspect, "Created");
            if (created.isEmpty() || helpers.values().stream().anyMatch(value -> value.id().equals(id))) throw DockerPolicy.failure();
            HelperPolicy.Spec spec = new HelperPolicy.Spec(id, created, containers.get(role), plan.image(), labels, user, List.of(ENTRYPOINT), List.copyOf(command), caps, tmpfs, mounts, Set.copyOf(names.values()));
            journal.record("container_created", Map.of("role", role, "id", id, "created", created));
            HelperPolicy.validate(inspect, spec); helpers.put(role, spec); guard(docker, plan, sourceGuard, daemon, names, volumes, helpers);
            journal.record("container_start_intent", Map.of("role", role, "id", id));
            String output = docker.call(1800, "start", "--attach", id);
            JsonNode finished = docker.inspect("container", id); HelperPolicy.validate(finished, spec); HelperPolicy.finished(finished);
            if (!output.equals(init ? "EMPTY_ROOTS_INITIALIZED" : "OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED")) throw DockerPolicy.failure();
            guard(docker, plan, sourceGuard, daemon, names, volumes, helpers);
            journal.record("container_finished", Map.of("role", role, "id", id));
        }
        journal.record("success", Map.of("volumes", names, "gate", "recovery-required"));
    }
    private static void guard(DockerTransport docker, Plan plan, SourceGuard sourceGuard, String daemon, Map<String,String> names,
                              Map<String,JsonNode> volumes, Map<String,HelperPolicy.Spec> helpers) throws Exception {
        sourceGuard.check();
        JsonNode current = DockerPolicy.parse(docker.call("info", "--format", "{{json .ID}}"));
        if (!current.isTextual() || !current.textValue().equals(daemon)) throw DockerPolicy.failure();
        for (var entry : volumes.entrySet()) {
            String name = names.get(entry.getKey());
            if (!DockerPolicy.importVolume(docker.inspect("volume", name), name, plan.token(), entry.getKey()).equals(entry.getValue())) throw DockerPolicy.failure();
            Set<String> attached = CaptureSnapshot.lines(docker.call("ps", "-a", "--no-trunc", "--filter", "volume=" + name, "--format", "{{.ID}}"));
            Set<String> expected = new HashSet<>(); for (HelperPolicy.Spec spec : helpers.values()) if (spec.volumeNames().contains(name)) expected.add(spec.id());
            if (!attached.equals(expected)) throw DockerPolicy.failure();
        }
    }
    private static boolean empty(JsonNode node) { return node.isMissingNode() || node.isNull() || (node.isContainerNode() && node.isEmpty()); }
}
