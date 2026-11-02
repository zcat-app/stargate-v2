// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.image;

import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;
import static app.zcat.stargate.image.InputFiles.*;

/** Linux amd64 build-input preparation only. Never builds final images or deploys. */
public final class PrepareImageInputs {
    record Options(Path project,Path output,Path evidence,Path nymBuild,boolean nym) {}
    record NativeInputs(JsonNode libc,Path libcDeb,JsonNode libcHash,JsonNode i2p,JsonNode nym,JsonNode nymRelease) {}
    public static void main(String[] args)throws Exception {
        if(Arrays.asList(args).contains("--help")){System.out.println("Usage: bash tools/prepare-image-inputs.sh [--nym] [--nym-build-dir PATH] [--evidence PATH] [--output PATH]\nUses Java 25, Docker and existing verified native builds. Builds only the OS package source stage; no deployment.\nAn existing output is replaced only after successful preparation. Failure keeps it intact.");return;}
        var options=options(args);prepare(options,new SystemCommands());
    }
    static Options options(String[] args)throws Exception {
        Path root=null,out=null,evidence=null,nym=null;boolean include=false;var seen=new HashSet<String>();
        for(int i=0;i<args.length;i++) {
            String arg=args[i];require(seen.add(arg),"Repeated option: "+arg);
            if(arg.equals("--nym")){include=true;continue;}
            require(Set.of("--project","--output","--evidence","--nym-build-dir").contains(arg)&&i+1<args.length,"Unknown/incomplete option: "+arg);
            Path value=Path.of(args[++i]).toAbsolutePath().normalize();
            switch(arg){case "--project"->root=value;case "--output"->out=value;case "--evidence"->evidence=value;case "--nym-build-dir"->nym=value;default->throw new AssertionError();}
        }
        require(root!=null,"Use the Bash launcher");root=root.toRealPath();
        return new Options(root,out==null?root.resolve("target/container"):out,evidence==null?root.resolve("scratch/research/i2p"):evidence,nym==null?root.resolve("target/nym-build"):nym,include);
    }
    static NativeInputs verify(Options o)throws Exception {
        Path root=o.project();var libc=json(root.resolve("containers/native/glibc-inputs.json"));
        require(text(libc,"local_version").matches("[A-Za-z0-9.+~:-]+"),"Invalid libc version");
        for(var patch:libc.path("patches"))checked(root.resolve("containers/native").resolve(text(patch,"file")),patch.get("sha256"));
        Path deb=root.resolve("target/native/libc6_"+text(libc,"local_version")+"_amd64.deb");regular(deb);
        JsonNode nativeRecord=json(root.resolve("target/native/build-hashes.json"));require(nativeRecord.path("local_version").equals(libc.path("local_version")),"libc build version mismatch");checked(deb,nativeRecord.path("debs").get(deb.getFileName().toString()));
        JsonNode i2p=json(root.resolve("target/i2p-isolation-build/build-record.json"));
        require(text(i2p,"sourceCommit").matches("[a-f0-9]{40}"),"Invalid I2P commit");
        for(var entry:Map.of("identity-fail-closed.patch","patchSha256","lifecycle-ack.patch","lifecyclePatchSha256","owner.c","ownerSourceSha256","Dockerfile.builder","builderDockerfileSha256").entrySet())checked(root.resolve("containers/i2p/"+entry.getKey()),i2p.get(entry.getValue()));
        checked(root.resolve("target/i2p-isolation-build/i2pd-"+text(i2p,"sourceCommit")+"/i2pd"),i2p.get("binarySha256"));
        checked(root.resolve("target/i2p-isolation-build/stargate-i2p-owner"),i2p.get("ownerBinarySha256"));
        JsonNode nym=null,release=null;
        if(o.nym()) {
            release=json(root.resolve("containers/nym-release.json"));var security=json(root.resolve("containers/nym/security-build.json"));
            nym=json(o.nymBuild().resolve("build-record.json"));
            equalFields(nym,security,List.of("sourceCommit","patchSha256","cargoLockSha256","builderBase","verifierTestCommit"));
            checked(root.resolve("containers/nym/security-dependencies.patch"),security.get("patchSha256"));
            require(nym.path("verifierRegressionPassed").isBoolean()&&nym.path("verifierRegressionPassed").booleanValue(),"Nym certificate regression has not passed");
            for(String kind:List.of("lifecycle","shared-client")) {
                var pin=json(root.resolve("containers/nym/"+kind+"-build.json"));String prefix=kind.equals("lifecycle")?"lifecycle":"sharedClient";
                require(pin.has("sourceSha256")&&pin.path("sourceSha256").isObject()&&nym.path(prefix+"SourceSha256").equals(pin.path("sourceSha256"))&&nym.path(prefix+"PatchSha256").equals(pin.path("patchSha256")),"Nym "+kind+" build input mismatch");
                require(nym.path("sourceCommit").equals(pin.path("sourceCommit")),"Nym patch source commit mismatch");
                checked(root.resolve("containers/nym/"+kind+".patch"),pin.get("patchSha256"));
            }
            require(nym.path("sharedClientRegressionPassed").isBoolean()&&nym.path("sharedClientRegressionPassed").booleanValue(),"Nym shared-client regression has not passed");
            require(nym.path("sourceCommit").equals(release.path("commit")),"Nym release/source mismatch");
            checked(o.nymBuild().resolve("source/target/release/nym-socks5-client"),nym.get("binarySha256"));
        }
        return new NativeInputs(libc,deb,nativeRecord.path("debs").get(deb.getFileName().toString()),i2p,nym,release);
    }
    static void equalFields(JsonNode actual,JsonNode pin,List<String> fields)throws Exception {
        for(String field:fields)require(pin.hasNonNull(field)&&actual.hasNonNull(field)&&actual.get(field).equals(pin.get(field)),"Nym security build input mismatch: "+field);
    }
    static String javaBaseline(Path project)throws Exception {
        var pin=json(project.resolve("containers/java-runtime.json"));
        require(pin.isObject()&&pin.size()==1,"Java declaration must contain only version");String version=text(pin,"version");
        require(version.matches("25(?:\\.[0-9]+){2}"),"Invalid Java baseline");return version;
    }
    static void outputBoundary(Options o)throws Exception {
        Path project=o.project(),output=o.output(),target=project.resolve("target");
        require(!project.startsWith(output)&&(!output.startsWith(project)||(output.startsWith(target)&&!output.equals(target))),"Output inside the checkout must be a generated target subdirectory, never source");
        if(Files.exists(output,NOFOLLOW_LINKS)) {
            require(Files.isDirectory(output,NOFOLLOW_LINKS),"Existing output must be a real directory");
            for(String marker:List.of("jdk-source.sha256","app/proxy.jar","rootfs-app/usr/share/stargate/runtime-files.json"))require(Files.isRegularFile(output.resolve(marker),NOFOLLOW_LINKS),"Existing output is not a recognized generated image context");
        }
    }
    static void prepare(Options o,Commands commands)throws Exception {
        require(System.getProperty("os.name").equals("Linux")&&Set.of("amd64","x86_64").contains(System.getProperty("os.arch")),"Linux amd64 is required");
        outputBoundary(o);String pin=javaBaseline(o.project());
        String version=command(commands,Path.of(System.getProperty("java.home"),"bin/java").toString(),"--version");
        require(version.lines().findFirst().orElse("").startsWith("openjdk "+pin+" "),"Select verified Java "+pin+" baseline before preparation");
        var inputs=verify(o); // No downloads/builds occur until all native gates pass.
        Path parent=o.output().getParent();directories(parent);require(parent.toRealPath().equals(parent),"Output parent aliases are not supported");
        require(!o.evidence().startsWith(o.output())&&!o.output().startsWith(o.evidence()),"Evidence and context must be separate");
        directories(o.evidence());require(o.evidence().toRealPath().equals(o.evidence()),"Evidence directory aliases are not supported");
        // Prevent accidentally replacing source, selected native inputs or their ancestors.
        for(Path input:List.of(o.project().resolve("containers"),o.project().resolve("proxy"),o.project().resolve("manager"),o.project().resolve("monitor"),o.project().resolve("updater"),o.project().resolve("image-preparer"),o.project().resolve("tools"),o.project().resolve("LICENSES"),o.project().resolve("target/native"),o.project().resolve("target/i2p-isolation-build"),o.nymBuild()))
            require(!input.startsWith(o.output())&&!o.output().startsWith(input),"Output overlaps a source/native input");
        Path lockFile=parent.resolve("."+o.output().getFileName()+".preparation.lock");
        try(var channel=FileChannel.open(lockFile,StandardOpenOption.CREATE,StandardOpenOption.WRITE,NOFOLLOW_LINKS);var lock=channel.tryLock()) {
            require(lock!=null,"Image preparation is already running");
            require(!Files.exists(o.output(),NOFOLLOW_LINKS)||Files.isDirectory(o.output(),NOFOLLOW_LINKS),"Existing output must be a real directory");
            Path stage=Files.createTempDirectory(parent,".image-inputs-");boolean published=false;
            try {
                System.out.println("Verifications passed; preparing isolated build inputs.");
                Path java=stage.resolve("java");
                commands.run(List.of(Path.of(System.getProperty("java.home"),"bin/jlink").toString(),"--add-modules","java.se,jdk.crypto.ec,jdk.unsupported,jdk.zipfs,jdk.management","--strip-debug","--no-header-files","--no-man-pages","--compress=zip-6","--output",java.toString()));
                try(var paths=Files.walk(java)){for(Path p:paths.toList())if(!Files.isSymbolicLink(p))mode(p,Files.isDirectory(p,NOFOLLOW_LINKS)?0755:Files.isExecutable(p)?0755:0644);}
                Path cacerts=java.resolve("lib/security/cacerts");Files.delete(cacerts);Files.copy(Path.of(System.getProperty("java.home"),"lib/security/cacerts").toRealPath(),cacerts);mode(cacerts,0644);
                write(stage.resolve("jdk-source.sha256"),hash(Path.of(System.getProperty("java.home"),"lib/modules"))+"\n");
                Path app=stage.resolve("app");directories(app);write(app.resolve("dns.security"),"networkaddress.cache.ttl=1\nnetworkaddress.cache.negative.ttl=1\n");
                copy(o.project().resolve("proxy/target/stargate-proxy-0.1.0-SNAPSHOT.jar"),app.resolve("proxy.jar"));tree(o.project().resolve("manager/target/quarkus-app"),app.resolve("manager"));
                Files.createDirectory(stage.resolve("packages"));var manifest=JSON.createArrayNode();manifest.addAll((ArrayNode)json(o.project().resolve("containers/tor-packages.json")));manifest.addAll((ArrayNode)json(o.project().resolve("containers/i2p-packages.json")));
                var filenames=new HashSet<String>();
                for(var entry:manifest) {
                    URI url=URI.create(text(entry,"url"));require(url.getScheme().equals("https")&&url.getHost()!=null&&url.getUserInfo()==null&&url.getFragment()==null&&url.getQuery()==null,"HTTPS artifact URL required");
                    String name=Path.of(url.getPath()).getFileName().toString();require(name.matches("[A-Za-z0-9_.+~%-]+\\.deb")&&filenames.add(name),"Invalid/duplicate package filename");
                    Path file=stage.resolve("packages/"+name),cached=o.output().resolve("packages/"+name);
                    if(Files.exists(cached,NOFOLLOW_LINKS)){checked(cached,entry.get("sha256"));copy(cached,file);}else download(url,file);
                    checked(file,entry.get("sha256"));
                }
                copy(inputs.libcDeb(),stage.resolve("packages/"+inputs.libcDeb().getFileName()));
                checked(stage.resolve("packages/"+inputs.libcDeb().getFileName()),inputs.libcHash());
                copy(o.project().resolve("containers/torrc"),stage.resolve("torrc"));copy(o.project().resolve("containers/i2pd.conf"),app.resolve("i2pd.conf"));
                Path iid=stage.resolve(".os-image-id");
                commands.run(List.of("docker","build","--target","os-packages","--iidfile",iid.toString(),"--file",o.project().resolve("containers/Dockerfile").toString(),stage.toString()));
                String sourceImage=Files.readString(iid).strip();Files.delete(iid);
                RuntimeRoots.Collected collected;
                try(var source=new RuntimeRoots.DockerSource(commands,sourceImage)){collected=RuntimeRoots.collect(source,stage);}
                checkPackageVersions(manifest,collected.reports);
                for(String role:RuntimeRoots.ROLES.keySet())require(collected.reports.path(role).path("packages").path("libc6").path("Version").equals(inputs.libc().path("local_version")),"Source libc version mismatch");
                finish(o,inputs,stage,collected,version);
                // Evidence failures must precede replacement of the previous context.
                for(String name:List.of("runtime-files.json","image-inputs.json"))Files.copy(stage.resolve("preparation-evidence/"+name),o.evidence().resolve(name),StandardCopyOption.REPLACE_EXISTING);
                publish(stage,o.output());published=true;
                System.out.println("Prepared "+o.output()+". No final image built or deployment changed.");
            }finally{if(!published)remove(stage);}
        }
    }
    static void checkPackageVersions(ArrayNode manifest,ObjectNode reports)throws Exception {
        for(var entry:manifest) {
            // The existing single I2P manifest has no "package" field.
            String name=entry.path("package").asText("i2pd");JsonNode actual=reports.path(name.equals("i2pd")?"i2p":"tor").path("packages").path(name).path("Version");
            require(actual.equals(entry.path("version")),"Source package version mismatch: "+name+" expected "+entry.path("version").asText()+", observed "+actual.asText());
        }
    }
    static void finish(Options o,NativeInputs inputs,Path stage,RuntimeRoots.Collected collected,String version)throws Exception {
        Path built=o.project().resolve("target/i2p-isolation-build");
        copy(built.resolve("i2pd-"+text(inputs.i2p(),"sourceCommit")+"/i2pd"),stage.resolve("rootfs-i2p/usr/bin/i2pd"));checked(stage.resolve("rootfs-i2p/usr/bin/i2pd"),inputs.i2p().get("binarySha256"));
        copy(built.resolve("stargate-i2p-owner"),stage.resolve("rootfs-i2p/usr/bin/stargate-i2p-owner"));checked(stage.resolve("rootfs-i2p/usr/bin/stargate-i2p-owner"),inputs.i2p().get("ownerBinarySha256"));
        copy(built.resolve("build-record.json"),stage.resolve("rootfs-i2p/usr/share/stargate/i2p-build.json"));
        require(json(stage.resolve("rootfs-i2p/usr/share/stargate/i2p-build.json")).equals(inputs.i2p()),"I2P build record changed after validation");
        var report=(ObjectNode)collected.reports.get("i2p");report.set("localBinaryOverride",inputs.i2p());
        for(JsonNode record:report.path("files"))if(record.path("path").asText().equals("/usr/bin/i2pd"))((ObjectNode)record).put("sha256",hash(stage.resolve("rootfs-i2p/usr/bin/i2pd")));
        ((ArrayNode)report.get("files")).addObject().put("path","/usr/bin/stargate-i2p-owner").put("sha256",hash(stage.resolve("rootfs-i2p/usr/bin/stargate-i2p-owner"))).putArray("packages");
        if(o.nym()) {
            Path dest=stage.resolve("nym");directories(dest);
            copy(o.nymBuild().resolve("source/target/release/nym-socks5-client"),dest.resolve("nym-socks5-client"));mode(dest.resolve("nym-socks5-client"),0755);checked(dest.resolve("nym-socks5-client"),inputs.nym().get("binarySha256"));
            copy(o.project().resolve("LICENSES/Apache-2.0.txt"),dest.resolve("LICENSE-Apache-2.0"));copy(o.project().resolve("containers/nym-release.json"),dest.resolve("release.json"));copy(o.nymBuild().resolve("build-record.json"),dest.resolve("security-build.json"));
            require(json(dest.resolve("security-build.json")).equals(inputs.nym())&&json(dest.resolve("release.json")).equals(inputs.nymRelease()),"Nym build/release record changed after validation");
            write(dest.resolve("NOTICE"),"Nym SOCKS5 client, Copyright Nym Technologies SA; Apache-2.0. Source: https://github.com/nymtech/nym/tree/"+text(inputs.nymRelease(),"commit")+"\nLocally rebuilt with the Stargate security dependency, lifecycle and shared-client patches; not the unmodified upstream binary.\n");
            for(String path:List.of("data/nym","secrets")){Path dir=stage.resolve("owned-nym/"+path);directories(dir);mode(dir,0700);}
        }
        for(String role:RuntimeRoots.ROLES.keySet())writeJson(stage.resolve("rootfs-"+role+"/usr/share/stargate/runtime-files.json"),collected.reports.get(role));
        Path evidence=stage.resolve("preparation-evidence");directories(evidence);writeJson(evidence.resolve("runtime-files.json"),collected.reports);
        collected.finishLinks();
        var inventory=JSON.createObjectNode().put("java",version.strip()).put("source_java_home",System.getProperty("java.home"));var hashes=inventory.putObject("sha256");var links=inventory.putObject("symlinks");
        try(var paths=Files.walk(stage)){for(Path p:paths.sorted().toList()) {
            String name=stage.relativize(p).toString();
            if(Files.isSymbolicLink(p))links.put(name,Files.readSymbolicLink(p).toString());else if(Files.isRegularFile(p,NOFOLLOW_LINKS))hashes.put(name,hash(p));
        }}
        writeJson(evidence.resolve("image-inputs.json"),inventory);
    }
    static void download(URI uri,Path dest)throws Exception {
        var client=HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(60)).followRedirects(HttpClient.Redirect.NORMAL).build();
        var response=client.send(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(60)).GET().build(),HttpResponse.BodyHandlers.ofInputStream());
        try(var input=response.body();var workers=java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            require(response.statusCode()==200&&response.uri().getScheme().equals("https"),"Artifact download failed");
            var transfer=workers.submit(()->{try(var output=Files.newOutputStream(dest,StandardOpenOption.CREATE_NEW)){byte[] buffer=new byte[65536];long total=0;int count;while((count=input.read(buffer))!=-1){total+=count;require(total<=256L*1024*1024,"Artifact too large");output.write(buffer,0,count);}return true;}});
            try{transfer.get(60,java.util.concurrent.TimeUnit.SECONDS);}finally{input.close();transfer.cancel(true);}
        }
    }
    static void publish(Path stage,Path output)throws Exception {
        Path backup=stage.resolveSibling(stage.getFileName()+".previous");boolean moved=false;
        try {
            if(Files.exists(output,NOFOLLOW_LINKS)){require(Files.isDirectory(output,NOFOLLOW_LINKS),"Output changed type");Files.move(output,backup,StandardCopyOption.ATOMIC_MOVE);moved=true;}
            Files.move(stage,output,StandardCopyOption.ATOMIC_MOVE);
        }catch(Exception failure){if(moved)try{Files.move(backup,output,StandardCopyOption.ATOMIC_MOVE);}catch(Exception restore){failure.addSuppressed(restore);throw new IOException("Previous context retained at "+backup,failure);}throw failure;}
        if(moved)try{remove(backup);}catch(IOException cleanup){System.err.println("Prepared context committed; previous generated context could not be fully removed at "+backup+". Inspect this exact path before cleanup.");}
    }
}
