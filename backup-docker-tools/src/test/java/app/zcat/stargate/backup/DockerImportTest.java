// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Simulates every daemon response; never invokes a Docker CLI. */
class DockerImportTest {
    private static final String TOKEN = "0".repeat(32), IMAGE = "sha256:" + "a".repeat(64);
    private static final JsonNodeFactory J = JsonNodeFactory.instance;
    static class Fake implements DockerTransport {
        final Map<String,JsonNode> volumes = new HashMap<>(), containers = new HashMap<>();
        final Map<String,Set<String>> attachments = new HashMap<>();
        final List<String> calls = new ArrayList<>(); boolean failCreate, failContainerCreate, badCopyCaps, badCaptureCaps, changedVolume;
        public String call(long timeout, String... array) throws Exception {
            List<String> args = List.of(array); calls.add(String.join(" ", args));
            if (args.subList(0, Math.min(2,args.size())).equals(List.of("info", "--format"))) return args.get(2).contains("SecurityOptions") ? "[\"name=seccomp\"]" : "\"daemon\"";
            if (args.subList(0, Math.min(2,args.size())).equals(List.of("volume", "ls"))) return args.contains("--filter") ? "" : String.join("\n", volumes.keySet());
            if (args.subList(0, Math.min(2,args.size())).equals(List.of("network", "ls"))) return "";
            if (args.subList(0, Math.min(2,args.size())).equals(List.of("ps", "-a"))) {
                int filter = args.indexOf("--filter");
                if (filter >= 0 && args.get(filter + 1).startsWith("volume=")) {
                    String name = args.get(filter + 1).substring(7); List<String> result = new ArrayList<>(attachments.getOrDefault(name, Set.of()));
                    for (var entry : containers.entrySet()) for (JsonNode mount : entry.getValue().path("Mounts")) if (mount.path("Name").asText().equals(name)) result.add(entry.getKey());
                    return String.join("\n", result);
                }
                if(filter>=0 && args.get(filter+1).startsWith("id=")) {String id=args.get(filter+1).substring(3);return containers.containsKey(id)?id:"";}
                return "";
            }
            if (args.subList(0, Math.min(2,args.size())).equals(List.of("volume", "create"))) {
                if (failCreate) throw new java.io.IOException("Synthetic uncertain create");
                String name = args.getLast(), role = name.substring(("stargate-import-" + TOKEN + "-").length());
                ObjectNode v = J.objectNode(); v.put("Name",name).put("Driver","local").put("Scope","local").putNull("Options").put("CreatedAt","created-" + role).put("Mountpoint","/var/lib/docker/" + name);
                v.putObject("Labels").put(DockerPolicy.LABEL,TOKEN).put(DockerPolicy.ROLE,role); volumes.put(name,v); return name;
            }
            if (args.get(0).equals("create")) {
                if(failContainerCreate)throw new java.io.IOException("Synthetic uncertain create");
                String id = (containers.isEmpty() ? "1" : "2").repeat(64), user = option(args,"--user");
                ObjectNode c = J.objectNode(); c.put("Id",id).put("Created","time-"+id).put("Name","/"+option(args,"--name")).put("Image",IMAGE);
                ObjectNode cfg = c.putObject("Config"); String label=option(args,"--label");String[] labelPair=label.split("=",2);cfg.putObject("Labels").put(labelPair[0],labelPair[1]);cfg.put("User",user);
                cfg.putArray("Entrypoint").add("/opt/java/bin/java"); ArrayNode command = cfg.putArray("Cmd"); for (int i=args.indexOf(IMAGE)+1;i<args.size();i++) command.add(args.get(i));
                cfg.putObject("Healthcheck").putArray("Test").add("NONE"); ObjectNode h = c.putObject("HostConfig");
                h.put("NetworkMode","none").put("ReadonlyRootfs",true).put("Privileged",false); h.putArray("CapDrop").add("ALL");
                ArrayNode caps=h.putArray("CapAdd"); if(args.contains("--cap-add"))caps.add("CAP_"+option(args,"--cap-add"));else if(badCopyCaps)caps.add("CAP_CHOWN");if(badCaptureCaps)caps.add("CAP_CHOWN");h.putArray("SecurityOpt").add("no-new-privileges");
                h.put("UsernsMode","host").put("Memory",536870912).put("MemorySwap",536870912).put("NanoCpus",2_000_000_000L).put("PidsLimit",128).putNull("PortBindings").put("PublishAllPorts",false).put("PidMode","").put("IpcMode","private").put("UTSMode","");
                h.putArray("Devices"); h.putArray("VolumesFrom"); String[] tmp=option(args,"--tmpfs").split(":",2);h.putObject("Tmpfs").put(tmp[0],tmp[1]);
                ArrayNode limits=h.putArray("Ulimits"); limits.addObject().put("Name","core").put("Soft",0).put("Hard",0); limits.addObject().put("Name","fsize").put("Soft",ArchiveInspector.MAX_ARCHIVE).put("Hard",ArchiveInspector.MAX_ARCHIVE);
                ObjectNode log=h.putObject("LogConfig"); log.put("Type","local"); log.putObject("Config").put("max-size","1m").put("max-file","1").put("compress","false");
                ArrayNode mounts=c.putArray("Mounts"), options=h.putArray("Mounts");
                for (int i=0;i<args.size();i++) if (args.get(i).equals("--mount")) {
                    String[] pieces=args.get(++i).split(","); Map<String,String> fields=new HashMap<>(); for (String piece:pieces) if (piece.contains("=")) {String[] kv=piece.split("=",2); fields.put(kv[0],kv[1]);}
                    boolean vol=fields.get("type").equals("volume"), writable=!Arrays.asList(pieces).contains("readonly");
                    ObjectNode m=mounts.addObject(); m.put("Type",fields.get("type")).put(vol?"Name":"Source",fields.get("src")).put("Destination",fields.get("dst")).put("RW",writable);
                    if (vol) {ObjectNode o=options.addObject(); o.put("Type","volume").put("Source",fields.get("src")).put("ReadOnly",!writable); o.putObject("VolumeOptions").put("NoCopy",true);}
                }
                c.putObject("State").put("Running",false).put("Status","exited").put("OOMKilled",false).put("Dead",false).put("ExitCode",0); containers.put(id,c);
                if (changedVolume) ((ObjectNode)volumes.values().iterator().next()).put("CreatedAt","replaced"); return id;
            }
            if (args.get(0).equals("start")) {
                JsonNode c=containers.get(args.getLast());
                for(JsonNode v:c.path("Config").path("Cmd")) if(v.asText().endsWith("CaptureHelper")) return "OFFLINE_CAPTURE_ARCHIVE_READY";
                if(c.path("Config").path("User").asText().equals("0:0")) return "EMPTY_ROOTS_INITIALIZED";
                for(JsonNode v:c.path("Config").path("Cmd")) if(v.asText().endsWith("ArchiveImportHelper")) return "OFFLINE_ARCHIVE_STAGE_AND_IMPORT_FINISHED";
                return "OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED";
            }
            if(args.get(0).equals("rm")){containers.remove(args.getLast());return args.getLast();}
            throw new AssertionError(args);
        }
        public JsonNode inspect(String kind, String name) throws Exception {
            if (kind.equals("image")) return DockerPolicy.parse("{\"Id\":\""+IMAGE+"\",\"Config\":{\"Volumes\":null,\"Labels\":{}}}");
            return kind.equals("volume") ? volumes.get(name) : containers.get(name);
        }
        private static String option(List<String> args,String name) {return args.get(args.indexOf(name)+1);}
    }
    static final class Journal implements DockerImport.Journal {
        final List<String> events=new ArrayList<>(); final List<JsonNode> records=new ArrayList<>(); String fail;
        public void record(String event,Map<String,?> fields) throws Exception {
            if(event.equals(fail)) throw new java.io.IOException("Synthetic journal failure"); events.add(event);
            var record = new HashMap<String,Object>(); record.put("event",event); record.putAll(fields); records.add(DockerPolicy.parse(DockerPolicy.json(record)));
        }
    }
    private static DockerImport.Plan plan(boolean nym) { return new DockerImport.Plan(TOKEN,IMAGE,"/synthetic/source","/synthetic/core.jar","/synthetic/adapter.jar",Map.of("core.jar","1".repeat(64),"adapter.jar","2".repeat(64)),nym); }
    @Test void createsFiveOrSevenVolumesWithValidatedIsolatedHelpers() throws Exception {
        for (boolean nym : List.of(false,true)) {
            Fake d=new Fake(); Journal j=new Journal(); DockerImport.run(plan(nym),d,j,()->{});
            assertEquals(nym?7:5,d.volumes.size()); assertEquals(2,d.containers.size()); assertEquals("success",j.events.getLast());
            assertEquals(2,d.calls.stream().filter(s->s.startsWith("start --attach")).count());
            assertFalse(d.calls.stream().anyMatch(s->s.startsWith("rm ") || s.startsWith("volume rm")));
        }
    }
    @Test void failuresNeverStartAnUnvalidatedHelperOrGuessCleanup() throws Exception {
        Fake uncertain=new Fake(); uncertain.failCreate=true; Journal j=new Journal();
        assertThrows(Exception.class,()->DockerImport.run(plan(false),uncertain,j,()->{})); assertEquals("volume_create_intent",j.events.getLast());
        assertFalse(uncertain.calls.stream().anyMatch(s->s.startsWith("rm ") || s.startsWith("volume rm")));
        Fake caps=new Fake(); caps.badCopyCaps=true; Journal j2=new Journal(); assertThrows(Exception.class,()->DockerImport.run(plan(false),caps,j2,()->{}));
        assertEquals(1,caps.calls.stream().filter(s->s.startsWith("start --attach")).count());
        Fake replaced=new Fake(); replaced.changedVolume=true; Journal j3=new Journal(); assertThrows(Exception.class,()->DockerImport.run(plan(false),replaced,j3,()->{}));
        assertEquals(0,replaced.calls.stream().filter(s->s.startsWith("start --attach")).count());
        Fake journalFailure=new Fake(); Journal j4=new Journal(); j4.fail="volume_create_intent";
        assertThrows(Exception.class,()->DockerImport.run(plan(false),journalFailure,j4,()->{})); assertTrue(journalFailure.volumes.isEmpty());
    }
    @Test void handoffReconcilesIdentityAndReservesMissingNym() throws Exception {
        Fake d=new Fake(); Journal j=new Journal(); DockerImport.run(plan(false),d,j,()->{}); d.calls.clear();
        var path=java.nio.file.Path.of("/synthetic/stargate-import-"+TOKEN+".jsonl");
        Map<String,Object> result=ComposeHandoff.validate(j.records,path,d);
        assertEquals("stargate-recovery-"+TOKEN,result.get("name"));
        @SuppressWarnings("unchecked") Map<String,Map<String,Object>> volumes=(Map<String,Map<String,Object>>)result.get("volumes");
        assertEquals("stargate-unavailable-"+TOKEN+"-nym-data",volumes.get("nym-data").get("name"));
        assertFalse(d.calls.stream().anyMatch(s->s.startsWith("create ") || s.startsWith("start ") || s.startsWith("volume create")));
        ((ObjectNode)d.volumes.values().iterator().next()).put("CreatedAt","replaced");
        assertThrows(Exception.class,()->ComposeHandoff.validate(j.records,path,d));
        Fake d2=new Fake(); Journal j2=new Journal(); DockerImport.run(plan(false),d2,j2,()->{});
        j2.records.removeLast(); assertThrows(Exception.class,()->ComposeHandoff.validate(j2.records,path,d2));
    }
    @Test void retiredAndUnsupportedDirectSchemasAreRefusedBeforeAnyDaemonCall() throws Exception {
        for (boolean nym : List.of(false, true)) {
            Fake fixture = new Fake(); Journal journal = new Journal();
            DockerImport.run(plan(nym), fixture, journal, () -> {});
            for (String schema : new String[]{null, "", "java-volume-import-v0"}) {
                var planned = (ObjectNode)journal.records.getFirst();
                if (schema == null) planned.remove("schema"); else planned.put("schema", schema);
                var calls = new java.util.concurrent.atomic.AtomicInteger();
                DockerTransport forbidden = (timeout, arguments) -> {
                    calls.incrementAndGet(); throw new java.io.IOException("No daemon access permitted for an unsupported journal");
                };
                var path = java.nio.file.Path.of("/synthetic/stargate-import-" + TOKEN + ".jsonl");
                assertThrows(Exception.class, () -> ComposeHandoff.validate(journal.records, path, forbidden));
                assertEquals(0, calls.get(), "Unsupported direct journals must fail before daemon calls, including inspect");
            }
        }
    }
}
