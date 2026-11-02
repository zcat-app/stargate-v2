package app.zcat.stargate.updater;
import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.Test;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import static app.zcat.stargate.updater.UpdateFiles.*;
import static org.junit.jupiter.api.Assertions.*;

/** Explicit opt-in: -Dtest=UpdateDockerProof. Only its unpredictable project is changed. */
class UpdateDockerProof {
 @Test void signedRoundTripRetainsSevenVolumes()throws Exception {
  Path source=Path.of("..").toRealPath();String nonce=UUID.randomUUID().toString().replace("-","");String project="sg-upgrade-proof-"+nonce;
  Path proof=source.resolve(".local-manager/upgrade-proof-"+nonce);directory(proof,"rwx------");
  Path endpoint=UpdateMain.localSocket(JSON.createObjectNode().put("dockerSocket","/run/docker.sock"));
  UpdateEngine.Commands run=(args,seconds)->{var cmd=new ArrayList<String>(List.of("/usr/bin/docker","--host","unix://"+endpoint));cmd.addAll(args);var builder=new ProcessBuilder(cmd);for(String variable:List.of("DOCKER_HOST","DOCKER_CONTEXT","DOCKER_TLS","DOCKER_TLS_VERIFY","DOCKER_CERT_PATH"))builder.environment().remove(variable);return UpdateMain.capture(builder,proof,seconds);};
  String base=JSON.readTree(run.run(List.of("image","inspect","ubuntu:24.04"),30)).get(0).path("RepoDigests").get(0).asText();String old=null,candidate=null;
  Path compose=proof.resolve("compose.json");var prefix=new ArrayList<>(List.of("compose","--project-name",project,"--file",compose.toString()));
  try {
   Files.writeString(proof.resolve("Dockerfile"),"FROM "+base+"\nCOPY version /stargate-version\nLABEL app.zcat.stargate.proof=\""+nonce+"\"\n");
   for(String version:List.of("old","new")){Files.writeString(proof.resolve("version"),version);run.run(List.of("build","--network","none","--quiet","--file",proof.resolve("Dockerfile").toString(),"--iidfile",proof.resolve(version+".id").toString(),proof.toString()),120);}
   old=Files.readString(proof.resolve("old.id")).trim();candidate=Files.readString(proof.resolve("new.id")).trim();Path archive=proof.resolve("candidate.tar");run.run(List.of("image","save","--output",archive.toString(),candidate),120);
   var model=JSON.createObjectNode();var services=model.putObject("services");
   for(String s:new TreeSet<>(SERVICES)){
    var svc=services.putObject(s).put("image",old).put("pull_policy","never").put("read_only",true).put("network_mode","none");svc.putArray("command").add("/bin/sh").add("-c").add("trap 'exit 0' TERM; while :; do sleep 1 & wait $$!; done");svc.putArray("cap_drop").add("ALL");svc.putArray("security_opt").add("no-new-privileges:true");var v=svc.putArray("volumes");
    switch(s){case "app"->{v.add("app-data:/data");v.add("tor-control:/run/tor-control");v.add("i2p-control:/run/i2p-control");}case "tor"->{v.add("tor-data:/var/lib/tor");v.add("tor-control:/run/tor-control");}case "i2p"->{v.add("i2p-data:/var/lib/i2pd");v.add("i2p-control:/run/i2p-control");}case "nym"->{v.add("nym-data:/data/nym");v.add("nym-secrets:/secrets");}}
   }
   var volumes=model.putObject("volumes");for(String v:List.of("app-data","tor-data","tor-control","i2p-data","i2p-control","nym-data","nym-secrets"))volumes.putObject(v);write(compose,model,false);
   var up=new ArrayList<>(prefix);up.addAll(List.of("up","--detach","--no-build","--pull","never","--wait"));run.run(up,120);
   var locations=Map.of("app",List.of("/data","/run/tor-control","/run/i2p-control"),"tor",List.of("/var/lib/tor"),"i2p",List.of("/var/lib/i2pd"),"nym",List.of("/data/nym","/secrets"));
   for(var e:locations.entrySet())for(String path:e.getValue())exec(run,prefix,e.getKey(),"/bin/sh","-c","printf '%s' '"+nonce+"' > '"+path+"/synthetic-state'");
   var key=KeyPairGenerator.getInstance("Ed25519").generateKeyPair();Path pub=proof.resolve("public.der");Files.write(pub,key.getPublic().getEncoded());var patches=JSON.createObjectNode();
   for(String p:List.of("containers/native/patches/glibc-CVE-2026-18374.patch","containers/i2p/identity-fail-closed.patch","containers/i2p/lifecycle-ack.patch","containers/nym/lifecycle.patch","containers/nym/security-dependencies.patch","containers/nym/shared-client.patch"))patches.put(p,hash(source.resolve(p)));
   String inspect=run.run(List.of("create","--network","none","--entrypoint","/never-start",old),30).trim();Path libc=proof.resolve("libc");try{run.run(List.of("cp",inspect+":/usr/lib/x86_64-linux-gnu/libc.so.6",libc.toString()),30);}finally{run.run(List.of("rm","--volumes",inspect),30);}String libcHash=hash(libc);
   var m=JSON.createObjectNode().put("schema",1).put("release","synthetic-"+nonce).put("sourceCommit","a".repeat(40)).put("createdAt",Instant.now().minusSeconds(10).toString()).put("expiresAt",Instant.now().plusSeconds(3600).toString()).put("statePolicy","no-migrations");m.set("patches",patches);var changes=m.putArray("changes");
   for(String s:List.of("app","tor"))changes.addObject().put("service",s).put("fromImage",old).put("toImage",candidate).put("fromVersion","fixture-old").put("toVersion","fixture-new").put("archive",archive.toUri().toString()).put("archiveSha256",hash(archive)).put("archiveBytes",Files.size(archive));
   byte[] release=JSON.writeValueAsBytes(m);Files.write(proof.resolve("release.json"),release);Files.write(proof.resolve("release.json.sig"),UpdateTest.sign(release,key));
   Path work=proof.resolve("work");directory(work,"rwx------");var c=JSON.createObjectNode().put("workDirectory",work.toString()).put("composeFile",compose.toString()).put("project",project).put("releaseUrl",proof.resolve("release.json").toUri().toString()).put("publicKeyFile",pub.toString()).put("publicKeySha256",hash(pub)).put("sourceDirectory",source.toString()).put("maxArchiveBytes",Files.size(archive)).put("waitSeconds",30).put("localArtifactDirectory",proof.toString());c.set("patches",patches);var keep=c.putObject("preserve");for(String s:List.of("app","tor"))keep.putObject(s).put("/usr/lib/x86_64-linux-gnu/libc.so.6",libcHash);Path settings=proof.resolve("config.json");write(settings,c,false);
   var engine=new UpdateEngine(settings,run);engine.refresh();String plan=engine.state.path("plan").asText();var before=engine.observe();
   Files.write(proof.resolve("release.json.sig"),new byte[64]);assertThrows(Exception.class,()->new UpdateEngine(settings,run).refresh());Files.write(proof.resolve("release.json.sig"),UpdateTest.sign(release,key));assertEquals(before,engine.observe());
   engine.refresh();assertNotEquals(plan,engine.state.path("plan").asText());final String stale=plan;assertThrows(Exception.class,()->engine.apply(stale,false));plan=engine.state.path("plan").asText();
   engine.apply(plan,false);assertEquals("INSTALLED",engine.state.path("phase").asText());var installed=engine.observe();exec(run,prefix,"app","/bin/sh","-c","printf '%s' 'latest-"+nonce+"' > /data/synthetic-state");
   engine.apply(plan,true);assertEquals("ROLLED_BACK",engine.state.path("phase").asText());var back=engine.observe();
   for(String s:List.of("i2p","nym")){assertEquals(before.path(s).path("id"),installed.path(s).path("id"));assertEquals(before.path(s).path("id"),back.path(s).path("id"));}
   for(var e:locations.entrySet())for(String path:e.getValue())assertEquals(e.getKey().equals("app")&&path.equals("/data")?"latest-"+nonce:nonce,exec(run,prefix,e.getKey(),"cat",path+"/synthetic-state"));
   // Real UID boundary: manager UID 10001 may create a readable request through its narrow mount.
   run.run(List.of("run","--rm","--network","none","--user","10001:10001","--mount","type=bind,src="+engine.inbox+",dst=/inbox",old,"/bin/sh","-c","umask 022; printf '%s' '{\"action\":\"refresh\",\"plan\":\"\"}' > /inbox/request.json"),30);
   assertEquals(10001,((Number)Files.getAttribute(engine.inbox.resolve("request.json"),"unix:uid")).intValue());engine.consume();assertEquals("PREPARED",engine.state.path("phase").asText());
   // Unrelated UID with only the parent mounted cannot traverse the private work directory.
   run.run(List.of("run","--rm","--network","none","--user","10003:10003","--mount","type=bind,src="+proof+",dst=/proof",old,"/bin/sh","-c","test ! -r /proof/work/public/status.json && test ! -w /proof/work/inbox"),30);
   var report=JSON.createObjectNode().put("result","PASS").put("project",project).put("oldImage",old).put("candidateImage",candidate).put("plan",plan).put("volumeMarkersVerified",7).put("latestStateRetainedOnRollback",true).put("unaffectedContainerIdsRetained",true).put("managerUidRequestConsumed",true).put("unrelatedUidDenied",true).put("disposableSigner",true).put("realNetworkRoutesTested",false);write(proof.resolve("result.json"),report,false);System.out.println("UPGRADE_DOCKER_PROOF "+proof.resolve("result.json"));
  }finally{
   if(Files.exists(compose)){var down=new ArrayList<>(prefix);down.addAll(List.of("down","--volumes","--timeout","5"));run.run(down,120);}
   if(old!=null)run.run(List.of("image","rm",old),30);if(candidate!=null)run.run(List.of("image","rm",candidate),30);
  }
 }
 static String exec(UpdateEngine.Commands run,List<String> prefix,String service,String...cmd)throws Exception{var a=new ArrayList<>(prefix);a.addAll(List.of("exec","--no-TTY",service));a.addAll(List.of(cmd));return run.run(a,30);}
}
