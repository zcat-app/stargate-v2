// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.image;

import com.fasterxml.jackson.databind.node.*;
import java.nio.file.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;
import static app.zcat.stargate.image.InputFiles.*;

class PreparationTest {
    @TempDir Path temp;
    static class Fixture implements RuntimeRoots.Source {
        String badTarget=null;boolean missing=false,fifo=false;
        public String image(){return "sha256:"+"a".repeat(64);}
        public String status(){var out=new StringBuilder();var names=new TreeSet<String>();RuntimeRoots.ROLES.values().forEach(names::addAll);for(String p:names)out.append("Package: ").append(p).append("\nVersion: 1.0-fixed\nSource: fixed-source\nStatus: install ok installed\nConffiles:\nDescription: test\n continuation preserved\n\n");return out.toString();}
        public List<String> paths(String name){return name.equals("i2pd")?List.of("/usr/lib/i2pd.so","/usr/share/doc/i2pd/copyright","/usr/share/i2pd/certificates/family","/usr/share/i2pd/certificates/family/test.crt"):List.of("/usr/lib/"+name+".so","/usr/share/doc/"+name+"/copyright");}
        public Map<String,RuntimeRoots.Metadata> metadata(List<String> paths){var result=new TreeMap<String,RuntimeRoots.Metadata>();for(String p:paths)result.put(p,new RuntimeRoots.Metadata(p.equals("usr/share/i2pd/certificates/family")?0040000:p.equals("usr/lib/libgcc-s1.so")?0120000:fifo&&p.equals("usr/bin/tor")?0010000:0100000,p.startsWith("usr/bin/")?0755:0644,data("/"+p).length));if(missing)result.remove("usr/bin/tor");return result;}
        static byte[] data(String path){return ("Exact bytes: "+path+"\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);}
        public byte[] read(String path,int limit){byte[] data=data(path);assertTrue(data.length<=limit);return data;}
        public String link(String path){return badTarget==null?"/usr/lib/libc6.so":badTarget;}
    }
    @Test void collectorPreservesBytesModesLicensesScannerRecordsAndDeferredLinks()throws Exception {
        var source=new Fixture();var collected=RuntimeRoots.collect(source,temp);
        assertFalse(Files.exists(temp.resolve("rootfs-app/usr/lib/libgcc-s1.so"),LinkOption.NOFOLLOW_LINKS));
        for(var role:RuntimeRoots.ROLES.entrySet()) {
            var report=collected.reports.path(role.getKey());assertEquals(source.image(),report.path("source_image_id").asText());
            Path root=temp.resolve("rootfs-"+role.getKey());
            for(String p:List.of("usr","usr/lib","etc","usr/share/stargate/licenses"))assertEquals(0755,((Number)Files.getAttribute(root.resolve(p),"unix:mode")).intValue()&0777);
            assertEquals(01777,((Number)Files.getAttribute(root.resolve("tmp"),"unix:mode")).intValue()&07777);
            for(String name:role.getValue())assertArrayEquals(Fixture.data("/usr/share/doc/"+name+"/copyright"),Files.readAllBytes(root.resolve("usr/share/stargate/licenses/"+name+".copyright")));
            assertTrue(Files.readString(root.resolve("var/lib/dpkg/status")).contains("\n continuation preserved\nX-Stargate-Runtime-Slice: yes"));
            for(var entry:report.path("files"))if(entry.has("sha256"))assertEquals(hash(root.resolve(entry.path("path").asText().substring(1))),entry.path("sha256").asText());
        }
        collected.finishLinks();assertEquals(Path.of("/usr/lib/libc6.so"),Files.readSymbolicLink(temp.resolve("rootfs-app/usr/lib/libgcc-s1.so")));
        assertEquals(0755,((Number)Files.getAttribute(temp.resolve("rootfs-tor/usr/bin/tor"),"unix:mode")).intValue()&0777);
        for(String p:List.of("owned-app/data","owned-app/run/i2p-control","owned-tor/var/lib/tor","owned-i2p/var/lib/i2pd"))assertEquals(0700,((Number)Files.getAttribute(temp.resolve(p),"unix:mode")).intValue()&0777);
    }
    @Test void collectorRejectsMissingSpecialAndEscapingSources()throws Exception {
        for(String kind:List.of("missing","fifo","escape")) {
            Path out=Files.createDirectory(temp.resolve(kind));var f=new Fixture();f.missing=kind.equals("missing");f.fifo=kind.equals("fifo");if(kind.equals("escape"))f.badTarget="../../../../outside";
            assertThrows(Exception.class,()->RuntimeRoots.collect(f,out));assertFalse(Files.exists(temp.resolve("outside")));
        }
        for(String path:List.of("/usr/lib/../escape.so","/usr//lib/test.so","/usr/lib/line\nbreak.so"))assertThrows(Exception.class,()->RuntimeRoots.canonical(path));
    }
    ObjectNode obj(){return JSON.createObjectNode();}
    void file(String path,String content)throws Exception {Path p=temp.resolve(path);Files.createDirectories(p.getParent());Files.writeString(p,content);}
    void record(String path,com.fasterxml.jackson.databind.JsonNode n)throws Exception{file(path,n.toString());}
    PrepareImageInputs.Options nativeFixture()throws Exception {
        file("containers/native/patches/fix.patch","libc patch");file("target/native/libc6_fixed_amd64.deb","synthetic libc package");
        var libc=obj().put("local_version","fixed");libc.putArray("patches").addObject().put("file","patches/fix.patch").put("sha256",hash(temp.resolve("containers/native/patches/fix.patch")));record("containers/native/glibc-inputs.json",libc);
        var nativeRecord=obj().put("local_version","fixed");nativeRecord.putObject("debs").put("libc6_fixed_amd64.deb",hash(temp.resolve("target/native/libc6_fixed_amd64.deb")));record("target/native/build-hashes.json",nativeRecord);
        var i2p=obj().put("sourceCommit","a".repeat(40));
        for(var e:Map.of("identity-fail-closed.patch","patchSha256","lifecycle-ack.patch","lifecyclePatchSha256","owner.c","ownerSourceSha256","Dockerfile.builder","builderDockerfileSha256").entrySet()){String path="containers/i2p/"+e.getKey();file(path,e.getKey());i2p.put(e.getValue(),hash(temp.resolve(path)));}
        for(var e:Map.of("i2pd-"+"a".repeat(40)+"/i2pd","binarySha256","stargate-i2p-owner","ownerBinarySha256").entrySet()){String path="target/i2p-isolation-build/"+e.getKey();file(path,e.getKey());i2p.put(e.getValue(),hash(temp.resolve(path)));}
        record("target/i2p-isolation-build/build-record.json",i2p);
        var nym=obj().put("sourceCommit","b".repeat(40)).put("cargoLockSha256","c".repeat(64)).put("builderBase","fixed-builder").put("verifierTestCommit","d".repeat(40)).put("verifierRegressionPassed",true).put("sharedClientRegressionPassed",true);
        file("containers/nym/security-dependencies.patch","nym security patch");nym.put("patchSha256",hash(temp.resolve("containers/nym/security-dependencies.patch")));record("containers/nym/security-build.json",nym);
        for(String kind:List.of("lifecycle","shared-client")) {
            file("containers/nym/"+kind+".patch",kind);var pin=obj().put("sourceCommit","b".repeat(40)).put("patchSha256",hash(temp.resolve("containers/nym/"+kind+".patch")));pin.putObject("sourceSha256").put("source.rs","e".repeat(64));record("containers/nym/"+kind+"-build.json",pin);
            String prefix=kind.equals("lifecycle")?"lifecycle":"sharedClient";nym.put(prefix+"PatchSha256",pin.path("patchSha256").asText());nym.set(prefix+"SourceSha256",pin.path("sourceSha256"));
        }
        file("nym/source/target/release/nym-socks5-client","synthetic nym executable");nym.put("binarySha256",hash(temp.resolve("nym/source/target/release/nym-socks5-client")));
        record("nym/build-record.json",nym);record("containers/nym-release.json",obj().put("commit","b".repeat(40)));
        return new PrepareImageInputs.Options(temp,temp.resolve("target/context"),temp.resolve("evidence"),temp.resolve("nym"),true);
    }
    @Test void nativeChecksRetainAllPatchAndRegressionGates()throws Exception {
        var o=nativeFixture();assertNotNull(PrepareImageInputs.verify(o));
        for(String path:List.of("containers/native/patches/fix.patch","target/native/libc6_fixed_amd64.deb","containers/i2p/lifecycle-ack.patch","target/i2p-isolation-build/stargate-i2p-owner","containers/nym/lifecycle.patch","containers/nym/shared-client.patch","nym/source/target/release/nym-socks5-client")) {
            byte[] saved=Files.readAllBytes(temp.resolve(path));Files.writeString(temp.resolve(path),"tampered");assertThrows(Exception.class,()->PrepareImageInputs.verify(o),path);Files.write(temp.resolve(path),saved);
        }
        Path rec=temp.resolve("nym/build-record.json");var original=(ObjectNode)json(rec);
        for(String flag:List.of("verifierRegressionPassed","sharedClientRegressionPassed")){var changed=original.deepCopy().put(flag,false);Files.writeString(rec,changed.toString());assertThrows(Exception.class,()->PrepareImageInputs.verify(o));Files.writeString(rec,original.toString());}
        var changed=original.deepCopy();changed.remove("sharedClientPatchSha256");Files.writeString(rec,changed.toString());assertThrows(Exception.class,()->PrepareImageInputs.verify(o));
    }
    @Test void failureBeforeHeavyWorkPreservesPreviousContext()throws Exception {
        var o=nativeFixture();file("containers/java-runtime.json","{\"version\":\"25.0.5\"}");previousContext();file("target/context/keep","previous usable context");file("containers/i2p/owner.c","tampered");
        var commands=new Commands(){public byte[] read(List<String> args,int limit){assertEquals("--version",args.getLast());return "openjdk 25.0.5 test\n".getBytes();}public void run(List<String> args){fail("No heavy commands on bad inputs");}};
        assertThrows(Exception.class,()->PrepareImageInputs.prepare(o,commands));assertEquals("previous usable context",Files.readString(temp.resolve("target/context/keep")));
    }
    @Test void publicationReplacesOnlyCompleteContextAndRefusesAliases()throws Exception {
        Path old=Files.createDirectory(temp.resolve("out"));Files.writeString(old.resolve("old"),"keep until success");Path stage=Files.createDirectory(temp.resolve("stage"));Files.writeString(stage.resolve("new"),"ready");
        PrepareImageInputs.publish(stage,old);assertTrue(Files.exists(old.resolve("new")));assertFalse(Files.exists(old.resolve("old")));
        Path link=temp.resolve("link");Files.createSymbolicLink(link,old);Path next=Files.createDirectory(temp.resolve("next"));assertThrows(Exception.class,()->PrepareImageInputs.publish(next,link));assertTrue(Files.exists(old.resolve("new")));
    }
    @Test void strictJsonAndLiteralArguments()throws Exception {
        file("bad.json","{\"version\":\"25.0.5\",\"version\":\"other\"}");assertThrows(Exception.class,()->json(temp.resolve("bad.json")));
        var o=PrepareImageInputs.options(new String[]{"--project",temp.toString(),"--output",temp.resolve("literal $value;out").toString(),"--nym"});assertEquals(temp.resolve("literal $value;out"),o.output());
        assertThrows(Exception.class,()->PrepareImageInputs.options(new String[]{"--project",temp.toString(),"--nym","--nym"}));
    }
    @Test void invalidEvidenceRefusesBeforeHeavyWorkAndKeepsOldContext()throws Exception {
        var o=nativeFixture();file("containers/java-runtime.json","{\"version\":\"25.0.5\"}");previousContext();file("target/context/keep","previous");file("evidence","not a directory");
        var commands=new Commands(){public byte[] read(List<String> args,int limit){return "openjdk 25.0.5 test\n".getBytes();}public void run(List<String> args){fail("No builds before output/evidence validation");}};
        assertThrows(Exception.class,()->PrepareImageInputs.prepare(o,commands));assertEquals("previous",Files.readString(temp.resolve("target/context/keep")));
    }
    void previousContext()throws Exception {for(String marker:List.of("jdk-source.sha256","app/proxy.jar","rootfs-app/usr/share/stargate/runtime-files.json"))file("target/context/"+marker,"previous fixture");}
    @Test void customOutputCannotReplaceSourcesOrAnUnrecognizedDirectory()throws Exception {
        var o=nativeFixture();var commands=new Commands(){public byte[] read(List<String> args,int limit){fail("Source output refused before any commands");return null;}public void run(List<String> args){fail("No commands");}};
        for(String path:List.of("docs","new-source","image-preparer","target")) {
            var bad=new PrepareImageInputs.Options(temp,temp.resolve(path),o.evidence(),o.nymBuild(),true);assertThrows(Exception.class,()->PrepareImageInputs.prepare(bad,commands));
        }
        file("target/context/important","not an image context");assertThrows(Exception.class,()->PrepareImageInputs.prepare(o,commands));assertEquals("not an image context",Files.readString(temp.resolve("target/context/important")));
    }
    @Test void imagePreparerUsesTheSameStrictJavaPinSchemaAsMonitor()throws Exception {
        file("containers/java-runtime.json","{\"version\":\"25.0.5\"}");assertEquals("25.0.5",PrepareImageInputs.javaBaseline(temp));
        for(String raw:List.of("{\"version\":\"25.0.5\",\"extra\":true}","{\"version\":\"25.0.5\",\"version\":\"25.0.6\"}","{}","{\"version\":\"other\"}")){file("containers/java-runtime.json",raw);assertThrows(Exception.class,()->PrepareImageInputs.javaBaseline(temp));}
    }
    @Test void existingI2pManifestWithoutPackageNameIsVerified()throws Exception {
        var manifest=JSON.createArrayNode();manifest.addObject().put("version","3.0.0-1noble1");var reports=obj();reports.putObject("i2p").putObject("packages").putObject("i2pd").put("Version","3.0.0-1noble1");
        PrepareImageInputs.checkPackageVersions(manifest,reports);((ObjectNode)manifest.get(0)).put("version","other");assertThrows(Exception.class,()->PrepareImageInputs.checkPackageVersions(manifest,reports));
    }
    @Test void dockerSourceUsesOneImmutableImageLiteralArgumentsAndCleanup()throws Exception {
        var calls=new ArrayList<List<String>>();String image="sha256:"+"a".repeat(64),id="b".repeat(64);
        var commands=new Commands(){public byte[] read(List<String> args,int limit){calls.add(List.copyOf(args));return (args.get(1).equals("run")?id+"\n":"exact bytes").getBytes();}public void run(List<String> args){calls.add(List.copyOf(args));}};
        try(var source=new RuntimeRoots.DockerSource(commands,image)){assertEquals(image,source.image());assertEquals("exact bytes",new String(source.read("/usr/lib/literal $value; file.so",100)));}
        assertTrue(calls.getFirst().containsAll(List.of("--pull=never","--read-only","--network","none","--cap-drop","ALL",image)));
        assertEquals(List.of("docker","exec",id,"cat","--","/usr/lib/literal $value; file.so"),calls.get(1));assertEquals(List.of("docker","rm","--force",id),calls.getLast());
        assertThrows(Exception.class,()->new RuntimeRoots.DockerSource(commands,"mutable:tag"));
    }
}
