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

/** Authenticate and preflight before creating any isolated Docker resources. */
public final class DockerArchiveImportMain {
    private DockerArchiveImportMain() {}
    public static void main(String[] args) {
        Thread caller=Thread.currentThread(); CountDownLatch finished=new CountDownLatch(1);
        Thread hook=new Thread(()->{caller.interrupt();try{finished.await();}catch(InterruptedException e){Thread.currentThread().interrupt();}},"archive-import-cleanup");
        Runtime.getRuntime().addShutdownHook(hook); int code; try{code=run(args);}finally{finished.countDown();}
        try{Runtime.getRuntime().removeShutdownHook(hook);}catch(IllegalStateException e){return;} System.exit(code);
    }
    static int run(String[] args) {
        Set<String> names=Set.of("--archive","--identity","--age","--age-sha256","--private-dir","--helper-image","--core-jar","--adapter-jar");
        Set<String> acks=Set.of("--ack-exclusive-local-daemon","--ack-trusted-image","--ack-matching-state","--ack-plaintext-retention");
        Map<String,String> values=new HashMap<>(); Set<String> confirmed=new HashSet<>();
        for(int i=0;i<args.length;i++) {
            String name=args[i]; if(acks.contains(name)&&confirmed.add(name)) continue;
            if(!names.contains(name)||values.containsKey(name)||++i>=args.length) return usage(); values.put(name,args[i]);
        }
        if(!values.keySet().equals(names)||!confirmed.equals(acks)) return usage();
        String location="unavailable";
        try {
            if(!"Linux".equals(System.getProperty("os.name"))) throw DockerPolicy.failure();
            int uid=Linux.uid("getuid"),euid=Linux.uid("geteuid"),gid=Linux.uid("getgid"),egid=Linux.uid("getegid");
            if(euid==0||uid!=euid||gid!=egid) throw DockerPolicy.failure();
            String image=values.get("--helper-image"); DockerPolicy.imageId(image);
            Path base=DurableJournal.safePath(values.get("--private-dir")), archive=DurableJournal.safePath(values.get("--archive"));
            Path identity=DurableJournal.safePath(values.get("--identity")), age=DurableJournal.safePath(values.get("--age"));
            Path core=DurableJournal.safePath(values.get("--core-jar")), adapter=DurableJournal.safePath(values.get("--adapter-jar"));
            for(Path path:new Path[]{archive,identity,age,core,adapter}) if(path.startsWith(base)) throw DockerPolicy.failure();
            byte[] nonce=new byte[16];new SecureRandom().nextBytes(nonce);String token=HexFormat.of().formatHex(nonce);
            try(DurableJournal journal=new DurableJournal(base,"stargate-import-",token,euid,egid)) {
                location=journal.path.toString(); Path privateDir=base.resolve("stargate-archive-"+token);
                try {
                    journal.record("archive_planned",Map.of("schema","java-authenticated-archive-import-v1","token",token,"image",image,"private_dir",privateDir.toString()));
                    try(ArchiveInputs inputs=new ArchiveInputs(base,token,archive,identity,age,values.get("--age-sha256"),core,adapter,euid,egid)) {
                        DockerArchiveImport.Plan plan=new DockerArchiveImport.Plan(token,image,inputs.directory.toString(),inputs.spool.toString(),inputs.digest,
                                inputs.core.toString(),inputs.adapter.toString(),inputs.hashes,inputs.nym);
                        DockerArchiveImport.run(plan,new DockerTransport.ProcessClient("docker"),journal::record,inputs,inputs::guardDigest);
                    }
                } catch(Exception failure) {
                    try{journal.record("failed_or_interrupted",Map.of("instruction","Keep offline; retain and inspect all planned resources and plaintext; do not retry into these volumes."));}catch(Exception ignored){}
                    throw failure;
                }
            }
            if(Thread.currentThread().isInterrupted()) throw new InterruptedException();
            System.out.println("OFFLINE_ARCHIVE_IMPORT_CREATED_RECOVERY_REQUIRED; private journal: "+location); return 0;
        } catch(Exception failure) {
            System.err.println("ARCHIVE IMPORT FAILED: keep all copies offline; retain and inspect the private journal and resources: "+location);return 1;
        }
    }
    private static int usage(){System.err.println("Requires archive, identity, age, age-sha256, private-dir, helper-image, core-jar, adapter-jar and all four archive import acknowledgements.");return 2;}
}
