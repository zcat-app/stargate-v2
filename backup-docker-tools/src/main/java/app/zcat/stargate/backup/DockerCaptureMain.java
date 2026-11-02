// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;

/** Operator-invoked capture; no helper is removed without exact identity checks. */
public final class DockerCaptureMain {
    private DockerCaptureMain() {}
    public static void main(String[] args) {
        Thread caller=Thread.currentThread();CountDownLatch finished=new CountDownLatch(1);
        Cancellation cancellation=new Cancellation(caller);
        Thread hook=new Thread(()->{cancellation.request();try{finished.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}},"docker-capture-cleanup");
        Runtime.getRuntime().addShutdownHook(hook);int code;try{code=run(args,cancellation);}finally{finished.countDown();}
        try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException e){return;}System.exit(code);
    }
    static int run(String[] args) {return run(args,new Cancellation(Thread.currentThread()));}
    static int run(String[] args,Cancellation cancellation) {
        Set<String> names=Set.of("--source-config","--output","--journal-dir","--helper-image","--age","--age-sha256","--identity","--recipient","--core-jar","--adapter-jar");
        Set<String> acks=Set.of("--ack-writers-stopped","--ack-matching-set","--ack-exclusive-local-daemon","--ack-reviewed-helper-image");
        Map<String,String> values=new HashMap<>();Set<String> confirmed=new HashSet<>();boolean nym=false;
        for(int i=0;i<args.length;i++) {
            String name=args[i];if(name.equals("--nym")&&!nym){nym=true;continue;}if(acks.contains(name)&&confirmed.add(name))continue;
            if(!names.contains(name)||values.containsKey(name)||++i>=args.length)return usage();values.put(name,args[i]);
        }
        if(!values.keySet().equals(names)||!confirmed.equals(acks))return usage();String location="unavailable",workLocation="unavailable";
        try {
            if(!"Linux".equals(System.getProperty("os.name")))throw DockerPolicy.failure();int uid=Linux.uid("getuid"),euid=Linux.uid("geteuid"),gid=Linux.uid("getgid"),egid=Linux.uid("getegid");
            if(euid==0||uid!=euid||gid!=egid)throw DockerPolicy.failure();String image=values.get("--helper-image");DockerPolicy.imageId(image);
            Path output=DurableJournal.safePath(values.get("--output")),journalDir=DurableJournal.safePath(values.get("--journal-dir"));
            Path identity=DurableJournal.safePath(values.get("--identity")),age=DurableJournal.safePath(values.get("--age"));
            Path core=DurableJournal.safePath(values.get("--core-jar")),adapter=DurableJournal.safePath(values.get("--adapter-jar"));
            if(output.getParent()==null||identity.startsWith(output.getParent()))throw DockerPolicy.failure();
            String recipient=values.get("--recipient");if(!recipient.matches("age1[0-9a-z]{58}"))throw DockerPolicy.failure();
            DockerPolicy.Selection selection=DockerPolicy.readSelection(DurableJournal.safePath(values.get("--source-config")),nym,euid);
            byte[] nonce=new byte[16];new SecureRandom().nextBytes(nonce);String token=HexFormat.of().formatHex(nonce);
            workLocation=output.getParent().resolve(".stargate-capture-"+token).toString();
            AgeDecrypt.Session pinned=AgeDecrypt.open(age,values.get("--age-sha256"),identity,euid);
            try(AutoCloseable pinnedClose=()->cancellation.cleanup(pinned::close)) {
            DurableJournal journal=new DurableJournal(journalDir,"stargate-capture-",token,euid,egid);
            try(AutoCloseable journalClose=()->cancellation.cleanup(journal::close)) {
                location=journal.path.toString();
                try {
                    CaptureWork work=new CaptureWork(output,token,core,adapter,euid,egid);
                    try(AutoCloseable workClose=()->cancellation.cleanup(work::close)) {
                    DockerCapture.Plan plan=new DockerCapture.Plan(token,image,selection,nym,output.toString(),output.getParent().toString(),journalDir.toString(),identity.toString(),work.core.toString(),work.adapter.toString(),work.spool.toString(),work.hashes());
                    boolean selectedNym=nym;
                    DockerCapture.Work operations=new DockerCapture.Work(){
                        public void guard(boolean empty)throws Exception{work.guard(empty);}
                        public void prepare()throws Exception{work.prepare(pinned,recipient,selectedNym);}
                        public void publish()throws Exception{work.publish();}
                        public void retain(){work.retain=true;}
                        public String location(){return work.location.toString();}
                        public ArchiveInspector.Summary summary(){return work.summary();}
                    };
                    DockerCapture.run(plan,new DockerTransport.ProcessClient("docker"),journal::record,operations,cancellation);
                    }
                } catch(Exception failure) {
                    try{cancellation.cleanup(()->journal.record("capture_failed_or_interrupted",Map.of("output_unconfirmed",true)));}catch(Exception ignored){}
                    throw failure;
                }
            }
            }
            cancellation.check();
            System.out.println("OFFLINE_DOCKER_CAPTURE_ENCRYPTED_VERIFIED; private journal: "+location);return 0;
        }catch(Exception failure){System.err.println("CAPTURE FAILED: keep sources offline; inspect the private journal and work; any output is unconfirmed. Journal: "+location+"; work: "+workLocation);return 1;}
    }
    private static int usage(){System.err.println("Requires capture paths, helper image, native age inputs and all four capture acknowledgements.");return 2;}
}
