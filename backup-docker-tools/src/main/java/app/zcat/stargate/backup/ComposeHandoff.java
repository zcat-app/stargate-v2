// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Read-only reconciliation of a completed Java import journal with its daemon. */
public final class ComposeHandoff {
    private ComposeHandoff() {}
    public static void main(String[] args) {
        if (args.length != 3 || !args[0].equals("--journal") || !args[2].equals("--ack-exclusive-local-daemon")) {
            System.err.println("Requires --journal FILE --ack-exclusive-local-daemon"); System.exit(2);
        }
        try {
            int uid = Linux.uid("geteuid"), gid = Linux.uid("getegid");
            if (uid == 0 || uid != Linux.uid("getuid") || gid != Linux.uid("getgid")) throw DockerPolicy.failure();
            Path path = DurableJournal.safePath(args[1]); List<JsonNode> events = readJournal(path, uid);
            if (!events.isEmpty() && events.getFirst().path("schema").asText().equals("java-authenticated-archive-import-v1")) checkArchiveSnapshots(path, events, uid, gid);
            else if (!events.isEmpty() && events.getFirst().path("schema").asText().equals("java-volume-import-v1")) checkSnapshots(path, events, uid, gid);
            System.out.println(DockerPolicy.json(validate(events, path, new DockerTransport.ProcessClient("docker"))));
        } catch (Exception e) { System.err.println("HANDOFF FAILED: keep all installations offline; inspect the private journal and resources."); System.exit(1); }
    }
    static List<JsonNode> readJournal(Path path, int uid) throws Exception {
        int fd = Linux.openRegular(DurableJournal.safePath(path.toString()), 65536, true, uid);
        try {
            Linux.Stat before = Linux.stat(fd); byte[] bytes;
            try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) { bytes = in.readNBytes(65537); }
            if (bytes.length > 65536 || !before.equals(Linux.stat(fd))) throw DockerPolicy.failure();
            String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
            if (text.isEmpty() || !text.endsWith("\n")) throw DockerPolicy.failure();
            List<JsonNode> events = new ArrayList<>(); for (String line : text.substring(0,text.length()-1).split("\n", -1)) {
                JsonNode event = DockerPolicy.parse(line); if (!event.isObject()) throw DockerPolicy.failure(); events.add(event);
            }
            return events;
        } finally { Linux.close(fd); }
    }
    private static void checkSnapshots(Path journal, List<JsonNode> events, int uid, int gid) throws Exception {
        if (events.isEmpty()) throw DockerPolicy.failure(); JsonNode planned = events.getFirst(); String token = DockerPolicy.text(planned, "token"); DockerPolicy.token(token);
        Path parent = journal.getParent().resolve("stargate-import-" + token + "-inputs");
        int directory = Linux.openDir(parent.toString(), true, uid);
        try {
            Linux.Stat d = Linux.stat(directory); if (d.gid() != Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
            for (String name : List.of("core.jar", "adapter.jar")) {
                String field = name.equals("core.jar") ? "core_jar" : "adapter_jar";
                if (!DockerPolicy.text(planned, field).equals(parent.resolve(name).toString())) throw DockerPolicy.failure();
                String expected = DockerPolicy.text(planned.path("sha256"), name);
                if (!expected.matches("[0-9a-f]{64}")) throw DockerPolicy.failure();
                int fd = Linux.openAt(directory, name, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                try {
                    Linux.Stat before = Linux.stat(fd);
                    if (!VolumeSnapshot.regular(before) || before.links() != 1 || before.uid() != Integer.toUnsignedLong(uid)
                            || before.gid() != Integer.toUnsignedLong(gid) || (before.mode() & 07777) != 0444 || before.size() > 64L * 1024 * 1024) throw DockerPolicy.failure();
                    MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[65536]; long size = 0;
                    try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) { int n; while ((n = in.read(buffer)) != -1) { size += n; if (size > 64L * 1024 * 1024) throw DockerPolicy.failure(); digest.update(buffer, 0, n); } }
                    if (size != before.size() || !before.equals(Linux.stat(fd)) || !expected.equals(HexFormat.of().formatHex(digest.digest()))) throw DockerPolicy.failure();
                } finally { Linux.close(fd); }
            }
        } finally { Linux.close(directory); }
    }
    private static void checkArchiveSnapshots(Path journal,List<JsonNode> events,int uid,int gid) throws Exception {
        if(events.size()<2) throw DockerPolicy.failure(); JsonNode planned=events.getFirst(), authenticated=events.get(1);
        String token=DockerPolicy.text(planned,"token");DockerPolicy.token(token);
        Path parent=journal.getParent().resolve("stargate-archive-"+token);
        if(!DockerPolicy.text(planned,"private_dir").equals(parent.toString())) throw DockerPolicy.failure();
        int dir=Linux.openDir(parent.toString(),true,uid);
        try {
            if(Linux.stat(dir).gid()!=Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
            for(String name:List.of("core.jar","adapter.jar","authenticated.tar")) {
                boolean spool=name.equals("authenticated.tar"); String expected=spool?DockerPolicy.text(authenticated,"sha256"):DockerPolicy.text(authenticated.path("helper_sha256"),name);
                if(!expected.matches("[0-9a-f]{64}")) throw DockerPolicy.failure();
                if(!spool && !DockerPolicy.text(authenticated,name.equals("core.jar")?"core_jar":"adapter_jar").equals(parent.resolve(name).toString())) throw DockerPolicy.failure();
                int fd=Linux.openAt(dir,name,Linux.RDONLY|Linux.NONBLOCK|Linux.NOFOLLOW|Linux.CLOEXEC,0);
                try {
                    Linux.Stat before=Linux.stat(fd);long limit=spool?ArchiveInspector.MAX_ARCHIVE:64L*1024*1024;
                    if(!VolumeSnapshot.regular(before)||before.links()!=1||before.uid()!=Integer.toUnsignedLong(uid)||before.gid()!=Integer.toUnsignedLong(gid)
                            ||(before.mode()&07777)!=0444||before.size()>limit) throw DockerPolicy.failure();
                    MessageDigest digest=MessageDigest.getInstance("SHA-256");byte[] buffer=new byte[65536];long size=0;
                    try(InputStream in=Files.newInputStream(Linux.fdPath(fd))){int n;while((n=in.read(buffer))!=-1){size+=n;if(size>limit)throw DockerPolicy.failure();digest.update(buffer,0,n);}}
                    if(size!=before.size()||!before.equals(Linux.stat(fd))||!expected.equals(HexFormat.of().formatHex(digest.digest())))throw DockerPolicy.failure();
                } finally {Linux.close(fd);}
            }
        } finally {Linux.close(dir);}
    }
    static Map<String,Object> validate(List<JsonNode> events, Path path, DockerTransport docker) throws Exception {
        if (events.size() < 3) throw DockerPolicy.failure(); JsonNode planned = events.getFirst();
        if (planned.path("event").asText().equals("archive_planned")) {
            if (!planned.path("schema").asText().equals("java-authenticated-archive-import-v1")) throw DockerPolicy.failure();
            return validateArchive(events,path,docker);
        }
        if (!DockerPolicy.text(planned,"event").equals("planned") || !DockerPolicy.text(planned,"schema").equals("java-volume-import-v1")) throw DockerPolicy.failure();
        String token = DockerPolicy.text(planned,"token"), image = DockerPolicy.text(planned,"image"); DockerPolicy.token(token); DockerPolicy.imageId(image);
        if (!path.getFileName().toString().equals("stargate-import-" + token + ".jsonl") || !planned.path("nym").isBoolean()) throw DockerPolicy.failure();
        boolean nym = planned.path("nym").booleanValue(); List<String> roots = DockerPolicy.roots(nym);
        Map<String,String> names = new LinkedHashMap<>(); for (String role : roots) names.put(role,"stargate-import-" + token + "-" + role);
        Map<String,String> containers = Map.of("init","stargate-import-"+token+"-init","copy","stargate-import-"+token+"-copy");
        if (!HelperPolicy.stringMap(planned.path("volumes")).equals(names) || !HelperPolicy.stringMap(planned.path("containers")).equals(containers)) throw DockerPolicy.failure();
        List<String> order = new ArrayList<>(List.of("planned","preflight")); for (String ignored : roots) order.addAll(List.of("volume_create_intent","volume_created"));
        for (String ignored : containers.keySet()) order.addAll(List.of("container_create_intent","container_created","container_start_intent","container_finished")); order.add("success");
        if (events.size()!=order.size()) throw DockerPolicy.failure();
        for (int i=0;i<order.size();i++) if (!DockerPolicy.text(events.get(i),"event").equals(order.get(i))) throw DockerPolicy.failure();
        JsonNode success = events.getLast(); if (!HelperPolicy.stringMap(success.path("volumes")).equals(names) || !DockerPolicy.text(success,"gate").equals("recovery-required")) throw DockerPolicy.failure();
        JsonNode daemon = DockerPolicy.parse(docker.call("info","--format","{{json .ID}}"));
        if (!daemon.isTextual() || daemon.textValue().isEmpty() || !daemon.textValue().equals(DockerPolicy.text(events.get(1),"daemon"))) throw DockerPolicy.failure();
        JsonNode imageInfo = docker.inspect("image",image), cfg = imageInfo.path("Config");
        if (!DockerPolicy.text(imageInfo,"Id").equals(image) || !empty(cfg.path("Volumes"))) throw DockerPolicy.failure();
        Map<String,String> labels = new HashMap<>(HelperPolicy.stringMap(cfg.path("Labels"))); labels.put(DockerPolicy.LABEL,token);
        for (int i=0;i<roots.size();i++) {
            String role=roots.get(i), name=names.get(role); JsonNode intent=events.get(2+i*2), created=events.get(3+i*2);
            if (!DockerPolicy.text(intent,"role").equals(role) || !DockerPolicy.text(intent,"name").equals(name) || !DockerPolicy.text(created,"role").equals(role)
                    || !created.path("identity").equals(DockerPolicy.importVolume(docker.inspect("volume",name),name,token,role))) throw DockerPolicy.failure();
        }
        int base=2+2*roots.size(); Map<String,String> ids=new HashMap<>();
        for (int i=0;i<2;i++) {
            String role=i==0?"init":"copy"; JsonNode intent=events.get(base+4*i), created=events.get(base+4*i+1), start=events.get(base+4*i+2), finish=events.get(base+4*i+3);
            String id=DockerPolicy.text(created,"id"), at=DockerPolicy.text(created,"created"); DockerPolicy.containerId(id);
            if (at.isEmpty() || !DockerPolicy.text(intent,"role").equals(role) || !DockerPolicy.text(intent,"name").equals(containers.get(role))
                    || !DockerPolicy.text(created,"role").equals(role) || !DockerPolicy.text(start,"role").equals(role) || !DockerPolicy.text(finish,"role").equals(role)
                    || !DockerPolicy.text(start,"id").equals(id) || !DockerPolicy.text(finish,"id").equals(id) || ids.containsValue(id)) throw DockerPolicy.failure();
            ids.put(role,id); HelperPolicy.Spec spec = spec(planned, role, id, at, image, labels, names, roots, containers.get(role));
            JsonNode helper = docker.inspect("container",id); HelperPolicy.validate(helper,spec); HelperPolicy.finished(helper);
        }
        for (String name : names.values()) {
            Set<String> attached=CaptureSnapshot.lines(docker.call("ps","-a","--no-trunc","--filter","volume="+name,"--format","{{.ID}}"));
            if (!attached.equals(Set.copyOf(ids.values()))) throw DockerPolicy.failure();
        }
        return project(docker,token,nym,names);
    }
    private static Map<String,Object> validateArchive(List<JsonNode> events,Path path,DockerTransport docker) throws Exception {
        JsonNode planned=events.getFirst(), authenticated=events.get(1);
        if(!DockerPolicy.text(planned,"schema").equals("java-authenticated-archive-import-v1") || !DockerPolicy.text(authenticated,"event").equals("authenticated")) throw DockerPolicy.failure();
        String token=DockerPolicy.text(planned,"token"),image=DockerPolicy.text(planned,"image"),digest=DockerPolicy.text(authenticated,"sha256");
        DockerPolicy.token(token);DockerPolicy.imageId(image);
        if(!digest.matches("[0-9a-f]{64}")||!path.getFileName().toString().equals("stargate-import-"+token+".jsonl")||!authenticated.path("nym").isBoolean()) throw DockerPolicy.failure();
        Path directory=path.getParent().resolve("stargate-archive-"+token);
        if(!DockerPolicy.text(planned,"private_dir").equals(directory.toString()))throw DockerPolicy.failure();
        boolean nym=authenticated.path("nym").booleanValue();List<String> roots=DockerPolicy.roots(nym),roles=new ArrayList<>(roots);roles.add("scratch");
        Map<String,String> names=new LinkedHashMap<>();for(String role:roles)names.put(role,"stargate-import-"+token+"-"+role);
        Map<String,String> containers=Map.of("init","stargate-import-"+token+"-init","archive","stargate-import-"+token+"-archive");
        if(!HelperPolicy.stringMap(authenticated.path("volumes")).equals(names)||!HelperPolicy.stringMap(authenticated.path("containers")).equals(containers)
                ||!DockerPolicy.text(authenticated,"core_jar").equals(directory.resolve("core.jar").toString())
                ||!DockerPolicy.text(authenticated,"adapter_jar").equals(directory.resolve("adapter.jar").toString()))throw DockerPolicy.failure();
        Map<String,String> hashes=HelperPolicy.stringMap(authenticated.path("helper_sha256"));
        if(!hashes.keySet().equals(Set.of("core.jar","adapter.jar"))||hashes.values().stream().anyMatch(v->!v.matches("[0-9a-f]{64}")))throw DockerPolicy.failure();
        List<String> order=new ArrayList<>(List.of("archive_planned","authenticated","preflight"));for(String ignored:roles)order.addAll(List.of("volume_create_intent","volume_created"));
        for(int i=0;i<2;i++)order.addAll(List.of("container_create_intent","container_created","container_start_intent","container_finished"));order.add("success");
        if(events.size()!=order.size())throw DockerPolicy.failure();for(int i=0;i<order.size();i++)if(!DockerPolicy.text(events.get(i),"event").equals(order.get(i)))throw DockerPolicy.failure();
        JsonNode success=events.getLast();if(!HelperPolicy.stringMap(success.path("volumes")).equals(names)||!DockerPolicy.text(success,"gate").equals("recovery-required"))throw DockerPolicy.failure();
        JsonNode daemon=DockerPolicy.parse(docker.call("info","--format","{{json .ID}}"));
        if(!daemon.isTextual()||daemon.textValue().isEmpty()||!daemon.textValue().equals(DockerPolicy.text(events.get(2),"daemon")))throw DockerPolicy.failure();
        JsonNode imageInfo=docker.inspect("image",image),cfg=imageInfo.path("Config");
        if(!DockerPolicy.text(imageInfo,"Id").equals(image)||!empty(cfg.path("Volumes")))throw DockerPolicy.failure();
        Map<String,String> labels=new HashMap<>(HelperPolicy.stringMap(cfg.path("Labels")));labels.put(DockerPolicy.LABEL,token);
        for(int i=0;i<roles.size();i++) {
            String role=roles.get(i),name=names.get(role);JsonNode intent=events.get(3+2*i),created=events.get(4+2*i);
            if(!DockerPolicy.text(intent,"role").equals(role)||!DockerPolicy.text(intent,"name").equals(name)||!DockerPolicy.text(created,"role").equals(role)
                    ||!created.path("identity").equals(DockerPolicy.importVolume(docker.inspect("volume",name),name,token,role)))throw DockerPolicy.failure();
        }
        int base=3+roles.size()*2;Map<String,String> ids=new HashMap<>();
        for(int i=0;i<2;i++) {
            String role=i==0?"init":"archive";JsonNode intent=events.get(base+4*i),created=events.get(base+4*i+1),start=events.get(base+4*i+2),finish=events.get(base+4*i+3);
            String cid=DockerPolicy.text(created,"id"),at=DockerPolicy.text(created,"created");DockerPolicy.containerId(cid);
            if(at.isEmpty()||!DockerPolicy.text(intent,"role").equals(role)||!DockerPolicy.text(intent,"name").equals(containers.get(role))
                    ||!DockerPolicy.text(created,"role").equals(role)||!DockerPolicy.text(start,"role").equals(role)||!DockerPolicy.text(finish,"role").equals(role)
                    ||!DockerPolicy.text(start,"id").equals(cid)||!DockerPolicy.text(finish,"id").equals(cid)||ids.containsValue(cid))throw DockerPolicy.failure();
            ids.put(role,cid);HelperPolicy.Spec spec=archiveSpec(authenticated,role,cid,at,image,labels,names,roots,roles,containers.get(role),directory,digest);
            JsonNode helper=docker.inspect("container",cid);HelperPolicy.validate(helper,spec);HelperPolicy.finished(helper);
        }
        for(String name:names.values()) if(!CaptureSnapshot.lines(docker.call("ps","-a","--no-trunc","--filter","volume="+name,"--format","{{.ID}}")).equals(Set.copyOf(ids.values())))throw DockerPolicy.failure();
        Map<String,String> mapped=new LinkedHashMap<>();for(String root:roots)mapped.put(root,names.get(root));return project(docker,token,nym,mapped);
    }
    private static HelperPolicy.Spec archiveSpec(JsonNode authenticated,String role,String id,String created,String image,Map<String,String> labels,Map<String,String> names,
                                                  List<String> roots,List<String> roles,String name,Path dir,String digest) throws Exception {
        boolean init=role.equals("init");String user=init?"0:0":"10001:10001";
        List<String> command=new ArrayList<>(List.of("-XX:+PerfDisableSharedMem","-XX:-CreateCoredumpOnCrash","-XX:ErrorFile=/dev/null","--enable-native-access=ALL-UNNAMED","-cp","/tool/core.jar:/tool/adapter.jar",
                init?"app.zcat.stargate.backup.InitRoots":"app.zcat.stargate.backup.ArchiveImportHelper"));
        if(init)command.addAll(roles);else command.addAll(List.of("stage",digest,authenticated.path("nym").booleanValue()?"1":"0"));
        Set<HelperPolicy.Mount> mounts=new HashSet<>();for(String v:roles)mounts.add(new HelperPolicy.Mount("volume",names.get(v),init||!v.equals("scratch")?"/dest/"+v:"/scratch",true));
        mounts.add(new HelperPolicy.Mount("bind",dir.resolve("core.jar").toString(),"/tool/core.jar",false));mounts.add(new HelperPolicy.Mount("bind",dir.resolve("adapter.jar").toString(),"/tool/adapter.jar",false));
        if(!init)mounts.add(new HelperPolicy.Mount("bind",dir.resolve("authenticated.tar").toString(),"/input.tar",false));
        return new HelperPolicy.Spec(id,created,name,image,labels,user,List.of("/opt/java/bin/java"),List.copyOf(command),init?Set.of("CHOWN"):Set.of(),
                Map.of("/dest",init?"mode=0700":"uid=10001,gid=10001,mode=0700"),mounts,Set.copyOf(names.values()));
    }
    private static HelperPolicy.Spec spec(JsonNode planned, String role, String id, String created, String image, Map<String,String> labels,
                                          Map<String,String> names, List<String> roots, String name) throws Exception {
        boolean init=role.equals("init"); String user=init?"0:0":"10001:10001";
        List<String> command=new ArrayList<>(List.of("-XX:+PerfDisableSharedMem","-XX:-CreateCoredumpOnCrash","-XX:ErrorFile=/dev/null","--enable-native-access=ALL-UNNAMED","-cp","/tool/core.jar:/tool/adapter.jar",
                init?"app.zcat.stargate.backup.InitRoots":"app.zcat.stargate.backup.VolumeImport"));
        if(init) command.addAll(roots); else {command.addAll(List.of("--source","/source","--destination","/dest")); if(planned.path("nym").booleanValue()) command.add("--nym");}
        Set<HelperPolicy.Mount> mounts=new HashSet<>(); for(String root:roots) mounts.add(new HelperPolicy.Mount("volume",names.get(root),"/dest/"+root,true));
        mounts.add(new HelperPolicy.Mount("bind",DockerPolicy.text(planned,"core_jar"),"/tool/core.jar",false));
        mounts.add(new HelperPolicy.Mount("bind",DockerPolicy.text(planned,"adapter_jar"),"/tool/adapter.jar",false));
        if(!init) mounts.add(new HelperPolicy.Mount("bind",DockerPolicy.text(planned,"source"),"/source",false));
        return new HelperPolicy.Spec(id,created,name,image,labels,user,List.of("/opt/java/bin/java"),List.copyOf(command),init?Set.of("CHOWN"):Set.of(),
                Map.of("/dest",init?"mode=0700":"uid=10001,gid=10001,mode=0700"),mounts,Set.copyOf(names.values()));
    }
    private static Map<String,Object> project(DockerTransport docker,String token,boolean nym,Map<String,String> names) throws Exception {
        String project="stargate-recovery-"+token,label="label=com.docker.compose.project="+project;
        for (List<String> args : List.of(List.of("ps","-a","--filter",label,"--format","{{.ID}}"),List.of("volume","ls","--filter",label,"--format","{{.Name}}"),List.of("network","ls","--filter",label,"--format","{{.ID}}")))
            if(!docker.call(args.toArray(String[]::new)).isBlank()) throw DockerPolicy.failure();
        for (List<String> args : List.of(List.of("ps","-a","--format","{{.Names}}"),List.of("volume","ls","--format","{{.Name}}"),List.of("network","ls","--format","{{.Name}}"))) {
            String prefix=project+(args.getFirst().equals("ps")?"-":"_");
            for(String value:CaptureSnapshot.lines(docker.call(args.toArray(String[]::new)))) if(value.startsWith(prefix)) throw DockerPolicy.failure();
        }
        Map<String,String> mapped=new LinkedHashMap<>(names);
        if(!nym) {
            Set<String> existing=CaptureSnapshot.lines(docker.call("volume","ls","--format","{{.Name}}"));
            for(String role:DockerPolicy.NYM) {String sentinel="stargate-unavailable-"+token+"-"+role; if(existing.contains(sentinel)) throw DockerPolicy.failure(); mapped.put(role,sentinel);}
        }
        return override(project,mapped);
    }
    static Map<String,Object> override(String project,Map<String,String> mapped) {
        Map<String,Object> volumes=new LinkedHashMap<>();
        mapped.forEach((role,name)->{Map<String,Object> item=new LinkedHashMap<>();item.put("external",true);item.put("name",name);volumes.put(role,item);});
        Map<String,Object> result=new LinkedHashMap<>();result.put("name",project);result.put("volumes",volumes);return result;
    }
    private static boolean empty(JsonNode node) { return node.isMissingNode() || node.isNull() || (node.isContainerNode() && node.isEmpty()); }
}
