// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** Coordinates a read-only stopped-volume capture with exact helper reconciliation. */
final class DockerCapture {
    static final String LABEL="org.stargate.offline-capture",ENTRY="/opt/java/bin/java",CP="/tool/core.jar:/tool/adapter.jar";
    record Plan(String token,String image,DockerPolicy.Selection selection,boolean nym,String output,String outputParent,String journalDir,String identity,String core,String adapter,String spool,Map<String,String> hashes) {}
    interface Work {
        void guard(boolean empty) throws Exception;
        void prepare() throws Exception;
        void publish() throws Exception;
        void retain();
        String location();
        ArchiveInspector.Summary summary();
    }
    private DockerCapture() {}
    static void run(Plan plan,DockerTransport docker,DockerImport.Journal journal,Work work) throws Exception {
        run(plan,docker,journal,work,new Cancellation(Thread.currentThread()));
    }
    static void run(Plan plan,DockerTransport docker,DockerImport.Journal journal,Work work,Cancellation cancellation) throws Exception {
        DockerPolicy.token(plan.token());DockerPolicy.imageId(plan.image());
        if(!plan.selection().volumes().keySet().equals(Set.copyOf(DockerPolicy.roots(plan.nym())))||!plan.hashes().keySet().equals(Set.of("core.jar","adapter.jar"))
                ||plan.hashes().values().stream().anyMatch(v->!v.matches("[0-9a-f]{64}")))throw DockerPolicy.failure();
        for(String path:List.of(plan.output(),plan.outputParent(),plan.journalDir(),plan.identity(),plan.core(),plan.adapter(),plan.spool()))DurableJournal.safePath(path);
        if(!Path.of(plan.output()).getParent().equals(Path.of(plan.outputParent())))throw DockerPolicy.failure();
        String name="stargate-capture-"+plan.token(), cid=null; HelperPolicy.Spec spec=null; boolean uncertain=false;
        try {
            journal.record("capture_planned",Map.of("token",plan.token(),"volumes",plan.selection().volumes(),"writers",plan.selection().containers().stream().sorted().toList(),"image",plan.image(),"nym",plan.nym(),"output",plan.output(),"work",work.location(),"helper_sha256",plan.hashes()));
            CaptureSnapshot.rootful(DockerPolicy.parse(docker.call("info","--format","{{json .SecurityOptions}}")));
            JsonNode image=docker.inspect("image",plan.image()),cfg=image.path("Config");
            if(!DockerPolicy.text(image,"Id").equals(plan.image())||!empty(cfg.path("Volumes")))throw DockerPolicy.failure();
            Map<String,String> labels=new HashMap<>(HelperPolicy.stringMap(cfg.path("Labels")));labels.put(LABEL,plan.token());
            CaptureSnapshot.Snapshot before=CaptureSnapshot.inspect(docker,plan.selection(),Set.of(),null);
            for(JsonNode volume:before.volumes().values()) {
                Path mount=DurableJournal.safePath(DockerPolicy.text(volume,"Mountpoint"));
                for(String s:List.of(plan.outputParent(),plan.journalDir(),plan.identity())) {
                    Path input=DurableJournal.safePath(s);if(input.startsWith(mount)||mount.startsWith(input))throw DockerPolicy.failure();
                }
            }
            if(CaptureSnapshot.lines(docker.call("ps","-a","--format","{{.Names}}" )).contains(name))throw DockerPolicy.failure();
            work.guard(true);journal.record("capture_preflight",Map.of("daemon",before.daemon(),"volumes",before.volumes(),"writers",before.writers()));
            List<String> command=List.of("-XX:+PerfDisableSharedMem","-XX:-CreateCoredumpOnCrash","-XX:ErrorFile=/dev/null","--enable-native-access=ALL-UNNAMED","-cp",CP,"app.zcat.stargate.backup.CaptureHelper",plan.nym()?"1":"0");
            Set<HelperPolicy.Mount> mounts=new HashSet<>();List<String> mountArgs=new ArrayList<>();
            for(String role:DockerPolicy.roots(plan.nym())) {
                String volume=plan.selection().volumes().get(role),dest="/source/"+role;mounts.add(new HelperPolicy.Mount("volume",volume,dest,false));
                mountArgs.addAll(List.of("--mount","type=volume,src="+volume+",dst="+dest+",readonly,volume-nocopy"));
            }
            for(var binding:Map.of(plan.core(),"/tool/core.jar",plan.adapter(),"/tool/adapter.jar").entrySet()) {
                mounts.add(new HelperPolicy.Mount("bind",binding.getKey(),binding.getValue(),false));mountArgs.addAll(List.of("--mount","type=bind,src="+binding.getKey()+",dst="+binding.getValue()+",readonly"));
            }
            mounts.add(new HelperPolicy.Mount("bind",plan.spool(),"/capture.tar",true));mountArgs.addAll(List.of("--mount","type=bind,src="+plan.spool()+",dst=/capture.tar"));
            List<String> args=new ArrayList<>(List.of("create","--name",name,"--pull=never","--no-healthcheck","--network","none","--read-only","--user","0:0","--userns","host","--cap-drop","ALL","--cap-add","DAC_OVERRIDE",
                    "--security-opt","no-new-privileges","--pids-limit","128","--memory","512m","--memory-swap","512m","--cpus","2","--ulimit","core=0:0",
                    "--ulimit","fsize="+ArchiveInspector.MAX_ARCHIVE+":"+ArchiveInspector.MAX_ARCHIVE,"--tmpfs","/source:mode=0700","--log-driver","local","--log-opt","max-size=1m","--log-opt","max-file=1","--log-opt","compress=false",
                    "--label",LABEL+"="+plan.token(),"--entrypoint",ENTRY));
            args.addAll(mountArgs);args.add(plan.image());args.addAll(command);
            journal.record("helper_create_intent",Map.of("name",name));uncertain=true;String created=docker.call(args.toArray(String[]::new));DockerPolicy.containerId(created);
            if(plan.selection().containers().contains(created))throw DockerPolicy.failure();
            cid=created;uncertain=false;
            JsonNode inspect=docker.inspect("container",cid);String createdAt=DockerPolicy.text(inspect,"Created");if(createdAt.isEmpty())throw DockerPolicy.failure();
            spec=new HelperPolicy.Spec(cid,createdAt,name,plan.image(),labels,"0:0",List.of(ENTRY),command,Set.of("DAC_OVERRIDE"),Map.of("/source","mode=0700"),mounts,Set.copyOf(plan.selection().volumes().values()));
            journal.record("helper_created",Map.of("id",cid,"created",createdAt,"name",name));HelperPolicy.validate(inspect,spec);
            CaptureSnapshot.inspect(docker,plan.selection(),Set.of(cid),before);work.guard(true);
            journal.record("helper_start_intent",Map.of("id",cid));String output=docker.call(1800,"start","--attach",cid);
            JsonNode finished=docker.inspect("container",cid);HelperPolicy.validate(finished,spec);HelperPolicy.finished(finished);
            if(!output.equals("OFFLINE_CAPTURE_ARCHIVE_READY"))throw DockerPolicy.failure();
            CaptureSnapshot.inspect(docker,plan.selection(),Set.of(cid),before);work.guard(false);journal.record("helper_finished",Map.of("id",cid));
            HelperPolicy.Spec completed=spec; cancellation.cleanup(()->cleanup(docker,journal,completed));cid=null;spec=null;
            cancellation.check();work.prepare();CaptureSnapshot.inspect(docker,plan.selection(),Set.of(),before);cancellation.check();work.publish();
            journal.record("capture_success",Map.of("output",plan.output(),"archive",Map.of("entries",work.summary().entries(),"payload_bytes",work.summary().payloadBytes(),"nym",work.summary().nym())));
        } catch(Throwable failure) {
            boolean[] safe={!uncertain};String knownId=cid;HelperPolicy.Spec knownSpec=spec;
            try { cancellation.cleanup(()->{
                try{journal.record("capture_failed_or_interrupted",Map.of("output_unconfirmed",true));}catch(Throwable ignored){}
                if(knownId!=null) {
                    if(knownSpec==null)safe[0]=false;
                    else try{cleanup(docker,journal,knownSpec);}catch(Throwable e){safe[0]=false;failure.addSuppressed(e);}
                }
                if(!safe[0]) {work.retain();try{journal.record("capture_work_retained",Map.of("path",work.location()));}catch(Throwable ignored){}}
            }); } catch(Throwable cleanupFailure) {work.retain();failure.addSuppressed(cleanupFailure);}
            throw failure;
        }
    }
    private static void cleanup(DockerTransport docker,DockerImport.Journal journal,HelperPolicy.Spec spec)throws Exception {
        JsonNode before=docker.inspect("container",spec.id());HelperPolicy.validate(before,spec);JsonNode state=before.path("State");
        if(!state.path("Running").isBoolean())throw DockerPolicy.failure();
        if(state.path("Running").booleanValue()) {
            journal.record("helper_stop_intent",Map.of("id",spec.id()));docker.call("stop","--time","10",spec.id());
            before=docker.inspect("container",spec.id());HelperPolicy.validate(before,spec);if(!before.path("State").path("Running").isBoolean()||before.path("State").path("Running").booleanValue())throw DockerPolicy.failure();
        }
        journal.record("helper_remove_intent",Map.of("id",spec.id()));docker.call("rm",spec.id());
        if(!docker.call("ps","-a","--no-trunc","--filter","id="+spec.id(),"--format","{{.ID}}").isBlank())throw DockerPolicy.failure();
        journal.record("helper_removed",Map.of("id",spec.id()));
    }
    private static boolean empty(JsonNode value){return value.isNull()||value.isMissingNode()||(value.isContainerNode()&&value.isEmpty());}
}
