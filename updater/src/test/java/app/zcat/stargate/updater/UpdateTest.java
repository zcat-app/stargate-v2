package app.zcat.stargate.updater;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.*;
import java.time.Instant;
import java.util.*;
import static app.zcat.stargate.updater.UpdateFiles.*;
import static org.junit.jupiter.api.Assertions.*;

class UpdateTest {
    @TempDir Path tmp;
    static final String OLD="sha256:"+"1".repeat(64),NEW="sha256:"+"2".repeat(64);
    KeyPair pair=key();
    static KeyPair key(){try{return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();}catch(Exception e){throw new RuntimeException(e);}}
    static byte[] sign(byte[] bytes,KeyPair key)throws Exception{var s=Signature.getInstance("Ed25519");s.initSign(key.getPrivate());s.update(bytes);return s.sign();}
    ObjectNode manifest()throws Exception {
        var n=JSON.createObjectNode().put("schema",1).put("release","test-1").put("sourceCommit","a".repeat(40)).put("createdAt",Instant.now().minusSeconds(30).toString()).put("expiresAt",Instant.now().plusSeconds(3600).toString()).put("statePolicy","no-migrations");
        n.putObject("patches").put("containers/test.patch",hash("patch".getBytes()));
        n.putArray("changes").addObject().put("service","app").put("fromImage",OLD).put("toImage",NEW).put("fromVersion","1").put("toVersion","2").put("archive",tmp.resolve("image.tar").toUri().toString()).put("archiveBytes",5).put("archiveSha256",hash("image".getBytes()));return n;
    }
    @Test void signaturesPinExactBytesSignerExpiryAndStrictSchema()throws Exception {
        byte[] bytes=JSON.writeValueAsBytes(manifest()),sig=sign(bytes,pair),pub=pair.getPublic().getEncoded();
        assertEquals(hash(bytes),UpdateManifest.verify(bytes,sig,pub,hash(pub),Instant.now()).id());
        byte[] bad=bytes.clone();bad[15]^=1;assertThrows(Exception.class,()->UpdateManifest.verify(bad,sig,pub,hash(pub),Instant.now()));
        assertThrows(Exception.class,()->UpdateManifest.verify(bytes,sig,pub,"0".repeat(64),Instant.now()));
        var other=key();assertThrows(Exception.class,()->UpdateManifest.verify(bytes,sign(bytes,other),pub,hash(pub),Instant.now()));
        assertThrows(Exception.class,()->UpdateManifest.verify(bytes,sig,pub,hash(pub),Instant.now().plusSeconds(7200)));
        for(String field:List.of("unexpected","statePolicy")) {
            var m=manifest();m.put(field,"migrate");byte[] b=JSON.writeValueAsBytes(m);assertThrows(Exception.class,()->UpdateManifest.verify(b,sign(b,pair),pub,hash(pub),Instant.now()));
        }
        byte[] duplicate=new String(bytes).replace("\"schema\":1","\"schema\":1,\"schema\":1").getBytes();assertThrows(Exception.class,()->UpdateManifest.verify(duplicate,sign(duplicate,pair),pub,hash(pub),Instant.now()));
    }
    Fixture fixture()throws Exception{return new Fixture();}
    class Fixture {
        Path config,work,release;ObjectNode doc;Fake engine;List<List<String>> calls=new ArrayList<>();boolean failUp;
        Fixture()throws Exception {
            work=Files.createDirectory(tmp.resolve("work"),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            Files.createDirectory(tmp.resolve("containers"));Files.writeString(tmp.resolve("containers/test.patch"),"patch");Files.writeString(tmp.resolve("image.tar"),"image");
            Path pub=tmp.resolve("public.der");Files.write(pub,pair.getPublic().getEncoded());release=tmp.resolve("release.json");doc=manifest();signRelease();
            Path compose=tmp.resolve("compose.json");write(compose,JSON.createObjectNode(),false);
            var c=JSON.createObjectNode().put("workDirectory",work.toString()).put("composeFile",compose.toString()).put("project","test-updater").put("releaseUrl",release.toUri().toString()).put("publicKeyFile",pub.toString()).put("publicKeySha256",hash(pub)).put("sourceDirectory",tmp.toString()).put("maxArchiveBytes",1024).put("waitSeconds",10).put("localArtifactDirectory",tmp.toString());
            c.set("patches",doc.path("patches"));c.putObject("preserve").putObject("app").put("/lib/patched-libc",hash("libc".getBytes()));config=tmp.resolve("config.json");write(config,c,false);
            engine=new Fake(config,(args,seconds)->{calls.add(List.copyOf(args));if(args.contains("up")){if(failUp)throw new IllegalStateException("INJECTED_FAILURE");var active=json(work.resolve("active.compose.json"));engine.image=active.path("services").path("app").path("image").asText();return "";}if(args.equals(List.of("image","inspect",NEW)))return "[{\"Id\":\""+NEW+"\"}]";return "";});
        }
        void signRelease()throws Exception{byte[] b=JSON.writeValueAsBytes(doc);Files.write(release,b);Files.write(Path.of(release+".sig"),sign(b,pair));}
    }
    static class Fake extends UpdateEngine {
        String image=OLD;boolean drift,defaultsDrift;List<String> preserved=new ArrayList<>();
        Fake(Path config,Commands commands)throws Exception{super(config,commands);}
        @Override JsonNode render(){var n=JSON.createObjectNode();var s=n.putObject("services");new TreeSet<>(SERVICES).forEach(k->s.putObject(k));return n;}
        @Override ObjectNode observe(){var n=JSON.createObjectNode();for(String s:SERVICES){var v=n.putObject(s).put("id",s.equals("app")?(image.equals(OLD)?"a":"b").repeat(64):s).put("image",s.equals("app")?image:OLD).put("running",true);v.putArray("mounts").add("persistent-"+s);v.putObject("policy").put("privileged",false);}return n;}
        @Override void configurationMatches(JsonNode ignored){require(!drift,"CONFIGURATION_NOT_DEPLOYED");}
        @Override void preserved(String service,String image){preserved.add(image);}
        @Override void sameImageDefaults(String previous,String candidate){require(!defaultsDrift,"CANDIDATE_RUNTIME_DEFAULTS_CHANGED");}
    }
    @Test void realComposeHashOutputIsParsedAndDriftStillRejected()throws Exception {
        var fixture=fixture();String fingerprint="a".repeat(64);
        String normal=String.join("\n",new TreeSet<>(SERVICES).stream().map(service->service+" "+fingerprint).toList())+"\n";
        String[] output={normal};var observed=JSON.createObjectNode();var rendered=JSON.createObjectNode();var services=rendered.putObject("services");
        for(String service:SERVICES){
            services.putObject(service);
            var live=observed.putObject(service).put("composeHash",fingerprint);
            var host=live.putObject("policy").putObject("HostConfig");host.putNull("MemorySwappiness");host.putObject("RestartPolicy").put("Name","no").put("MaximumRetryCount",0);
        }
        var engine=new UpdateEngine(fixture.config,(args,seconds)->{
            if(args.contains("--hash"))return output[0];
            if(args.contains("--format")&&args.contains("json"))return JSON.writeValueAsString(rendered);
            throw new AssertionError("Unexpected command: "+args);
        });
        assertDoesNotThrow(()->engine.configurationMatches(observed));
        output[0]=normal.replace("\n","\r\n").replace(" ","\t");
        assertDoesNotThrow(()->engine.configurationMatches(observed));
        output[0]="app not-a-hash\n";
        assertEquals("INVALID_COMPOSE_HASH",assertThrows(IllegalArgumentException.class,()->engine.configurationMatches(observed)).getMessage());
        output[0]=normal;observed.withObject("app").put("composeHash","b".repeat(64));
        assertEquals("CONFIGURATION_NOT_DEPLOYED",assertThrows(IllegalArgumentException.class,()->engine.configurationMatches(observed)).getMessage());
    }
    @Test void previewInstallRollbackAndReplayKeepStateAndPriorImageBinding()throws Exception {
        var f=fixture();f.engine.refresh();String plan=f.engine.state.path("plan").asText();assertTrue(f.calls.isEmpty());
        Path userState=tmp.resolve("user-state");Files.writeString(userState,"paired-key-identity");
        f.engine.apply(plan,false);assertEquals("INSTALLED",f.engine.state.path("phase").asText());assertEquals(List.of(OLD,NEW),f.engine.preserved);
        assertThrows(Exception.class,()->f.engine.apply(plan,false));Files.writeString(userState,"paired-key-identity + latest traffic state");
        f.engine.apply(plan,true);assertEquals("ROLLED_BACK",f.engine.state.path("phase").asText());assertEquals(OLD,f.engine.image);assertEquals("paired-key-identity + latest traffic state",Files.readString(userState));
        assertThrows(Exception.class,()->f.engine.apply(plan,true));
        var mutations=f.calls.stream().filter(c->c.contains("up")).toList();assertEquals(2,mutations.size());
        for(var command:mutations){assertTrue(command.containsAll(List.of("--no-deps","--no-build","--pull","never","--wait")));assertEquals("app",command.getLast());assertFalse(command.contains("down"));}
    }
    @Test void rejectsStalePreviewConfigDriftPatchDriftAndDamagedArtifactBeforeServiceMutation()throws Exception {
        var f=fixture();f.engine.drift=true;assertThrows(Exception.class,()->f.engine.refresh());assertTrue(f.calls.isEmpty());f.engine.drift=false;f.engine.refresh();String id=f.engine.state.path("plan").asText();
        assertThrows(Exception.class,()->f.engine.apply("0".repeat(64),false));
        f.engine.drift=true;assertThrows(Exception.class,()->f.engine.apply(id,false));f.engine.drift=false;
        Files.writeString(tmp.resolve("containers/test.patch"),"changed");assertThrows(Exception.class,()->f.engine.apply(id,false));Files.writeString(tmp.resolve("containers/test.patch"),"patch");
        Files.writeString(tmp.resolve("image.tar"),"WRONG");assertThrows(Exception.class,()->f.engine.apply(id,false));assertTrue(f.calls.isEmpty());
    }
    @Test void failedReplacementAndInterruptedStateRequireExplicitRollback()throws Exception {
        var f=fixture();f.engine.refresh();String id=f.engine.state.path("plan").asText();f.failUp=true;
        assertThrows(Exception.class,()->f.engine.apply(id,false));assertEquals("INSTALL_FAILED",f.engine.state.path("phase").asText());assertThrows(Exception.class,()->f.engine.refresh());assertThrows(Exception.class,()->f.engine.apply(id,false));
        f.failUp=false;f.engine.state.put("phase","INSTALLING");f.engine.save();
        var restarted=new Fake(f.config,f.engine.commands);assertEquals("INSTALLING",restarted.state.path("phase").asText());assertThrows(Exception.class,()->restarted.apply(id,false));restarted.apply(id,true);assertEquals("ROLLED_BACK",restarted.state.path("phase").asText());
    }
    @Test void inboxRejectsUnknownFieldsAndNonregularOrOversizedRequests()throws Exception {
        var f=fixture();f.engine.refresh();
        Files.writeString(f.engine.inbox.resolve("request.json"),"{\"action\":\"install\",\"plan\":\""+f.engine.state.path("plan").asText()+"\",\"command\":\"evil\"}");f.engine.consume();assertTrue(f.calls.isEmpty());
        Files.createSymbolicLink(f.engine.inbox.resolve("request.json"),f.release);f.engine.consume();assertTrue(Files.exists(f.release));assertTrue(f.calls.isEmpty());
        Files.writeString(f.engine.inbox.resolve("request.json"),"x".repeat(257));f.engine.consume();assertTrue(f.calls.isEmpty());assertFalse(Files.exists(f.engine.inbox.resolve("request.json")));
    }
    @Test void reprepareAndInterruptedClaimsCannotReuseAnOldApproval()throws Exception {
        var f=fixture();f.engine.refresh();String old=f.engine.state.path("plan").asText();f.engine.refresh();String fresh=f.engine.state.path("plan").asText();assertNotEquals(old,fresh);assertThrows(Exception.class,()->f.engine.apply(old,false));
        Files.writeString(f.work.resolve("claimed-request.json"),"{\"action\":\"install\",\"plan\":\""+fresh+"\"}");
        var restarted=new Fake(f.config,f.engine.commands);assertEquals("REVIEW_REQUIRED",restarted.state.path("phase").asText());assertFalse(Files.exists(f.work.resolve("claimed-request.json")));assertThrows(Exception.class,()->restarted.apply(fresh,false));assertTrue(f.calls.isEmpty());
    }
    @Test void writableAncestorsAndOutOfBandResourceChangesAreRefused()throws Exception {
        Path unsafe=Files.createDirectory(tmp.resolve("unsafe"));Files.setPosixFilePermissions(unsafe,PosixFilePermissions.fromString("rwxrwxrwx"));Path privateFile=unsafe.resolve("file");write(privateFile,new byte[]{1},false);assertThrows(Exception.class,()->UpdateFiles.privateFile(privateFile));
        var service=JSON.createObjectNode();var host=JSON.createObjectNode();host.putObject("RestartPolicy").put("Name","no");UpdateEngine.resourcePolicy(service,host);host.put("Memory",536870912);assertThrows(Exception.class,()->UpdateEngine.resourcePolicy(service,host));host.put("Memory",0);host.put("PidsLimit",100);assertThrows(Exception.class,()->UpdateEngine.resourcePolicy(service,host));
    }
    @Test void opensslEncryptedEd25519SignerInteroperatesWithJavaVerifier()throws Exception {
        Path privateKey=tmp.resolve("private.pem"),pub=tmp.resolve("public.der"),doc=tmp.resolve("release.json"),sig=tmp.resolve("release.json.sig");Files.write(doc,JSON.writeValueAsBytes(manifest()));String pass=UUID.randomUUID().toString();
        openssl(pass,"genpkey","-algorithm","ED25519","-aes-256-cbc","-pass","stdin","-out",privateKey.toString());
        openssl(pass,"pkey","-in",privateKey.toString(),"-passin","stdin","-pubout","-outform","DER","-out",pub.toString());
        openssl(pass,"pkeyutl","-sign","-rawin","-inkey",privateKey.toString(),"-passin","stdin","-in",doc.toString(),"-out",sig.toString());
        assertEquals(hash(doc),UpdateManifest.verify(Files.readAllBytes(doc),Files.readAllBytes(sig),Files.readAllBytes(pub),hash(pub),Instant.now()).id());
    }
    @Test void changedCandidateDefaultsAreRefusedBeforeAnyReplacement()throws Exception {
        var f=fixture();var e=new UpdateEngine(f.config,(args,seconds)->args.getLast().equals(OLD)?"[{\"Config\":{\"User\":\"10001\"}}]":"[{\"Config\":{\"User\":\"0\"}}]");
        assertThrows(Exception.class,()->e.sameImageDefaults(OLD,NEW));assertTrue(f.calls.isEmpty());
        f.engine.refresh();String plan=f.engine.state.path("plan").asText();f.engine.defaultsDrift=true;
        assertThrows(Exception.class,()->f.engine.apply(plan,false));assertFalse(f.calls.stream().anyMatch(c->c.contains("up")));assertEquals(OLD,f.engine.image);assertEquals("PREPARED",f.engine.state.path("phase").asText());
        f.engine.defaultsDrift=false;f.engine.apply(plan,false);f.engine.apply(plan,true);assertEquals("ROLLED_BACK",f.engine.state.path("phase").asText());
    }
    void openssl(String pass,String...args)throws Exception {
        var command=new ArrayList<>(List.of("/usr/bin/openssl"));command.addAll(List.of(args));var p=new ProcessBuilder(command).redirectErrorStream(true).start();try(var stdin=p.getOutputStream()){stdin.write((pass+"\n").getBytes());}assertTrue(p.waitFor(10,java.util.concurrent.TimeUnit.SECONDS));assertEquals(0,p.exitValue(),()->{try{return new String(p.getInputStream().readAllBytes());}catch(Exception e){return "output unavailable";}});
    }
    @Test void expiryDuringDownloadAndTimeoutCannotAuthorizeFurtherActions()throws Exception {
        var f=fixture();f.doc.put("expiresAt",Instant.now().plusSeconds(1).toString());f.signRelease();
        var slow=new Fake(f.config,(args,seconds)->{if(args.size()>1&&args.get(0).equals("image")&&args.get(1).equals("load"))Thread.sleep(1100);return f.engine.commands.run(args,seconds);});
        slow.refresh();assertThrows(Exception.class,()->slow.apply(slow.state.path("plan").asText(),false));assertFalse(f.calls.stream().anyMatch(c->c.contains("up")));
        f.doc.put("expiresAt",Instant.now().plusSeconds(100).toString());f.signRelease();
        var uncertain=new Fake(f.config,(args,seconds)->{if(args.contains("up"))throw new IllegalStateException("DOCKER_COMMAND_TIMED_OUT");return f.engine.commands.run(args,seconds);});uncertain.refresh();String plan=uncertain.state.path("plan").asText();assertThrows(Exception.class,()->uncertain.apply(plan,false));assertEquals("UNCERTAIN",uncertain.state.path("phase").asText());assertThrows(Exception.class,()->uncertain.apply(plan,true));uncertain.reconcileRollback();assertEquals("ROLLED_BACK",uncertain.state.path("phase").asText());
    }
    @Test void unpublishedReleaseStagingDoesNotBreakTheCommittedTransaction()throws Exception {
        var f=fixture();f.engine.refresh();String original=f.engine.state.path("plan").asText();Path staging=Files.createDirectory(f.work.resolve("releases/.candidate-interrupted"));Files.writeString(staging.resolve("release.json"),"partial");
        var restarted=new Fake(f.config,f.engine.commands);assertNotNull(restarted.saved(false));assertEquals(original,restarted.state.path("plan").asText());f.doc.put("release","test-2");f.signRelease();restarted.refresh();assertNotEquals(original,restarted.state.path("plan").asText());assertNotNull(restarted.saved(false));
    }
    @Test void bindOrderingIsIrrelevantButBindingBytesAndLocalDaemonAuthorityMatter()throws Exception {
        var a=JSON.createObjectNode();a.putArray("Binds").add("volume-a:/a:rw").add("volume-b:/b:ro");var b=JSON.createObjectNode();b.putArray("Binds").add("volume-b:/b:ro").add("volume-a:/a:rw");assertEquals(UpdateEngine.normalizedHost(a),UpdateEngine.normalizedHost(b));b.withArray("Binds").set(0,JSON.getNodeFactory().textNode("volume-b:/b:rw"));assertNotEquals(UpdateEngine.normalizedHost(a),UpdateEngine.normalizedHost(b));
        Path socket=tmp.resolve("docker.sock");try(var server=java.nio.channels.ServerSocketChannel.open(java.net.StandardProtocolFamily.UNIX)){server.bind(java.net.UnixDomainSocketAddress.of(socket));var config=JSON.createObjectNode().put("dockerSocket",socket.toString());assertEquals(socket,UpdateMain.localSocket(config));config.put("dockerSocket","tcp://example.invalid:2375");assertThrows(Exception.class,()->UpdateMain.localSocket(config));config.put("dockerSocket",tmp.resolve("not-a-socket").toString());Files.writeString(tmp.resolve("not-a-socket"),"no");assertThrows(Exception.class,()->UpdateMain.localSocket(config));}
    }
    @Test void commandResponsesAreNotRetainedAsLogsOnSuccessOrFailure()throws Exception {
        Path output=Files.createDirectory(tmp.resolve("commands"));assertEquals("synthetic-secret",UpdateMain.capture(new ProcessBuilder("/bin/sh","-c","printf '%s' synthetic-secret"),output,5));
        assertThrows(Exception.class,()->UpdateMain.capture(new ProcessBuilder("/bin/sh","-c","printf '%s' synthetic-secret; exit 1"),output,5));
        try(var paths=Files.list(output)){assertEquals(0,paths.count());}
    }
}
