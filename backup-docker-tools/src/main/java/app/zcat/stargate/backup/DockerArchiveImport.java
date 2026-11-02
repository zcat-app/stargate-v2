// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Daemon operations begin only after full authentication and staging preflight. */
final class DockerArchiveImport {
    record Plan(String token,String image,String directory,String spool,String digest,String core,String adapter,Map<String,String> hashes,boolean nym) {}
    private static final String ENTRY="/opt/java/bin/java", CP="/tool/core.jar:/tool/adapter.jar";
    private DockerArchiveImport() {}
    static void run(Plan plan,DockerTransport docker,DockerImport.Journal journal,DockerImport.SourceGuard metadataGuard,DockerImport.SourceGuard digestGuard) throws Exception {
        DockerPolicy.token(plan.token()); DockerPolicy.imageId(plan.image());
        if(!plan.digest().matches("[0-9a-f]{64}") || !plan.hashes().keySet().equals(Set.of("core.jar","adapter.jar"))
                || plan.hashes().values().stream().anyMatch(v->!v.matches("[0-9a-f]{64}"))) throw DockerPolicy.failure();
        for(String value:List.of(plan.directory(),plan.spool(),plan.core(),plan.adapter())) DurableJournal.safePath(value);
        java.nio.file.Path directory=java.nio.file.Path.of(plan.directory());
        if(!directory.getFileName().toString().equals("stargate-archive-"+plan.token())
                ||!plan.spool().equals(directory.resolve("authenticated.tar").toString())
                ||!plan.core().equals(directory.resolve("core.jar").toString())||!plan.adapter().equals(directory.resolve("adapter.jar").toString())) throw DockerPolicy.failure();
        List<String> roots=DockerPolicy.roots(plan.nym()), roles=new ArrayList<>(roots); roles.add("scratch");
        Map<String,String> names=new LinkedHashMap<>(); for(String role:roles) names.put(role,"stargate-import-"+plan.token()+"-"+role);
        Map<String,String> containers=Map.of("init","stargate-import-"+plan.token()+"-init","archive","stargate-import-"+plan.token()+"-archive");
        digestGuard.check();
        journal.record("authenticated",Map.of("sha256",plan.digest(),"nym",plan.nym(),"volumes",names,"containers",containers,"core_jar",plan.core(),"adapter_jar",plan.adapter(),"helper_sha256",plan.hashes()));
        JsonNode id=DockerPolicy.parse(docker.call("info","--format","{{json .ID}}")); if(!id.isTextual()||id.textValue().isEmpty()) throw DockerPolicy.failure(); String daemon=id.textValue();
        CaptureSnapshot.rootful(DockerPolicy.parse(docker.call("info","--format","{{json .SecurityOptions}}")));
        JsonNode image=docker.inspect("image",plan.image()), config=image.path("Config");
        if(!DockerPolicy.text(image,"Id").equals(plan.image()) || !empty(config.path("Volumes"))) throw DockerPolicy.failure();
        Map<String,String> labels=new HashMap<>(HelperPolicy.stringMap(config.path("Labels"))); labels.put(DockerPolicy.LABEL,plan.token());
        if(!java.util.Collections.disjoint(names.values(),CaptureSnapshot.lines(docker.call("volume","ls","--format","{{.Name}}")))
                || !java.util.Collections.disjoint(containers.values(),CaptureSnapshot.lines(docker.call("ps","-a","--format","{{.Names}}")))) throw DockerPolicy.failure();
        journal.record("preflight",Map.of("daemon",daemon)); Map<String,JsonNode> volumes=new HashMap<>(); Map<String,HelperPolicy.Spec> helpers=new HashMap<>();
        for(String role:roles) {
            guard(plan,docker,metadataGuard,daemon,names,volumes,helpers); String name=names.get(role);
            journal.record("volume_create_intent",Map.of("role",role,"name",name));
            if(!docker.call("volume","create","--driver","local","--label",DockerPolicy.LABEL+"="+plan.token(),"--label",DockerPolicy.ROLE+"="+role,name).equals(name)) throw DockerPolicy.failure();
            JsonNode identity=DockerPolicy.importVolume(docker.inspect("volume",name),name,plan.token(),role); volumes.put(role,identity);
            journal.record("volume_created",Map.of("role",role,"identity",identity)); guard(plan,docker,metadataGuard,daemon,names,volumes,helpers);
        }
        for(String role:List.of("init","archive")) {
            guard(plan,docker,metadataGuard,daemon,names,volumes,helpers); digestGuard.check();
            boolean init=role.equals("init"); String user=init?"0:0":"10001:10001"; Set<String> caps=init?Set.of("CHOWN"):Set.of();
            Map<String,String> tmpfs=Map.of("/dest",init?"mode=0700":"uid=10001,gid=10001,mode=0700");
            List<String> command=new ArrayList<>(List.of("-XX:+PerfDisableSharedMem","-XX:-CreateCoredumpOnCrash","-XX:ErrorFile=/dev/null","--enable-native-access=ALL-UNNAMED","-cp",CP,
                    init?"app.zcat.stargate.backup.InitRoots":"app.zcat.stargate.backup.ArchiveImportHelper"));
            if(init) command.addAll(roles); else command.addAll(List.of("stage",plan.digest(),plan.nym()?"1":"0"));
            Set<HelperPolicy.Mount> mounts=new HashSet<>(); List<String> mountsArgs=new ArrayList<>();
            for(String v:roles) {
                String dest=init||!v.equals("scratch")?"/dest/"+v:"/scratch";
                mounts.add(new HelperPolicy.Mount("volume",names.get(v),dest,true)); mountsArgs.addAll(List.of("--mount","type=volume,src="+names.get(v)+",dst="+dest+",volume-nocopy"));
            }
            Map<String,String> bindings=new LinkedHashMap<>(); bindings.put(plan.core(),"/tool/core.jar"); bindings.put(plan.adapter(),"/tool/adapter.jar"); if(!init) bindings.put(plan.spool(),"/input.tar");
            for(var binding:bindings.entrySet()) {mounts.add(new HelperPolicy.Mount("bind",binding.getKey(),binding.getValue(),false)); mountsArgs.addAll(List.of("--mount","type=bind,src="+binding.getKey()+",dst="+binding.getValue()+",readonly"));}
            List<String> args=new ArrayList<>(List.of("create","--name",containers.get(role),"--pull=never","--no-healthcheck","--network","none","--read-only","--user",user,"--userns","host","--cap-drop","ALL"));
            if(init) args.addAll(List.of("--cap-add","CHOWN"));
            args.addAll(List.of("--security-opt","no-new-privileges","--pids-limit","128","--memory","512m","--memory-swap","512m","--cpus","2",
                    "--ulimit","core=0:0","--ulimit","fsize="+ArchiveInspector.MAX_ARCHIVE+":"+ArchiveInspector.MAX_ARCHIVE,"--tmpfs","/dest:"+tmpfs.get("/dest"),
                    "--log-driver","local","--log-opt","max-size=1m","--log-opt","max-file=1","--log-opt","compress=false","--label",DockerPolicy.LABEL+"="+plan.token(),"--entrypoint",ENTRY));
            args.addAll(mountsArgs); args.add(plan.image()); args.addAll(command);
            journal.record("container_create_intent",Map.of("role",role,"name",containers.get(role)));
            String cid=docker.call(args.toArray(String[]::new)); DockerPolicy.containerId(cid); JsonNode inspect=docker.inspect("container",cid); String created=DockerPolicy.text(inspect,"Created");
            if(created.isEmpty()||helpers.values().stream().anyMatch(s->s.id().equals(cid))) throw DockerPolicy.failure();
            HelperPolicy.Spec spec=new HelperPolicy.Spec(cid,created,containers.get(role),plan.image(),labels,user,List.of(ENTRY),List.copyOf(command),caps,tmpfs,mounts,Set.copyOf(names.values()));
            journal.record("container_created",Map.of("role",role,"id",cid,"created",created)); HelperPolicy.validate(inspect,spec); helpers.put(role,spec);
            guard(plan,docker,metadataGuard,daemon,names,volumes,helpers); digestGuard.check(); journal.record("container_start_intent",Map.of("role",role,"id",cid));
            String output=docker.call(1800,"start","--attach",cid); JsonNode finished=docker.inspect("container",cid);
            HelperPolicy.validate(finished,spec); HelperPolicy.finished(finished);
            if(!output.equals(init?"EMPTY_ROOTS_INITIALIZED":"OFFLINE_ARCHIVE_STAGE_AND_IMPORT_FINISHED")) throw DockerPolicy.failure();
            guard(plan,docker,metadataGuard,daemon,names,volumes,helpers); digestGuard.check(); journal.record("container_finished",Map.of("role",role,"id",cid));
        }
        journal.record("success",Map.of("volumes",names,"gate","recovery-required"));
    }
    private static void guard(Plan plan,DockerTransport docker,DockerImport.SourceGuard source,String daemon,Map<String,String> names,Map<String,JsonNode> volumes,Map<String,HelperPolicy.Spec> helpers) throws Exception {
        source.check(); JsonNode id=DockerPolicy.parse(docker.call("info","--format","{{json .ID}}")); if(!id.isTextual()||!id.textValue().equals(daemon)) throw DockerPolicy.failure();
        for(var entry:volumes.entrySet()) {
            String name=names.get(entry.getKey()); if(!entry.getValue().equals(DockerPolicy.importVolume(docker.inspect("volume",name),name,plan.token(),entry.getKey()))) throw DockerPolicy.failure();
            Set<String> attached=CaptureSnapshot.lines(docker.call("ps","-a","--no-trunc","--filter","volume="+name,"--format","{{.ID}}"));
            Set<String> expected=new HashSet<>(); for(var helper:helpers.values()) if(helper.volumeNames().contains(name)) expected.add(helper.id());
            if(!attached.equals(expected)) throw DockerPolicy.failure();
        }
    }
    private static boolean empty(JsonNode value){return value.isNull()||value.isMissingNode()||(value.isContainerNode()&&value.isEmpty());}
}
