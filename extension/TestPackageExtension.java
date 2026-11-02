// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

public final class TestPackageExtension {
    static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    static Map<String,String> hashes(Path root)throws Exception {
        var result=new TreeMap<String,String>();try(var files=Files.walk(root)){for(Path p:files.filter(f->Files.isRegularFile(f,NOFOLLOW_LINKS)).toList())result.put(root.relativize(p).toString(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p))));}return result;
    }
    static void expectFailure(Path root,Map<String,String> before)throws Exception {
        boolean failed=false;try{PackageExtension.main(new String[]{root.toString()});}catch(Exception expected){failed=true;}
        check(failed,"expected refusal");check(before.equals(hashes(root.resolve("target"))),"failed packaging changed prior outputs");
    }
    public static void main(String[] args)throws Exception {
        Path source=Path.of(args[0]).toRealPath(),project=Files.createTempDirectory("stargate-package-test-");
        try {
            Path root=project.resolve("extension");Files.createDirectory(root);Files.createDirectory(project.resolve("LICENSES"));Files.copy(source.getParent().resolve("LICENSES/Apache-2.0.txt"),project.resolve("LICENSES/Apache-2.0.txt"));
            Files.createDirectory(project.resolve("docs"));Files.copy(source.getParent().resolve("docs/privacy-policy.md"),project.resolve("docs/privacy-policy.md"));
            for(String name:List.of("src","manifests"))try(var paths=Files.walk(source.resolve(name))){for(Path p:paths.sorted().toList()){Path dest=root.resolve(source.relativize(p));if(Files.isDirectory(p,NOFOLLOW_LINKS))Files.createDirectory(dest);else Files.copy(p,dest);}}
            Files.copy(source.resolve("NOTICE"),root.resolve("NOTICE"));PackageExtension.main(new String[]{root.toString()});
            for(String browser:List.of("firefox","brave")) {
                Path folder=root.resolve("target/"+browser),archive=root.resolve("target/stargate-"+browser+(browser.equals("firefox")?".xpi":".zip"));var expected=hashes(folder);var actual=new TreeMap<String,String>();
                try(var zip=new ZipFile(archive.toFile())){for(var e:zip.stream().toList()){check(!e.isDirectory()&&!e.getName().startsWith("/")&&!e.getName().contains(".."),"invalid ZIP member");try(var in=zip.getInputStream(e)){actual.put(e.getName(),HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(in.readAllBytes())));}}}
                check(expected.equals(actual),"ZIP payload mismatch");check(actual.containsKey("manifest.json")&&actual.containsKey("LICENSE")&&actual.containsKey("NOTICE"),"missing metadata");check(browser.equals("brave")==actual.containsKey("worker.js"),"browser worker mismatch");
                check(actual.get("PRIVACY.md").equals(hashes(project.resolve("docs")).get("privacy-policy.md")),"packaged privacy policy differs from reviewed policy");
                check(Files.readString(folder.resolve("privacy.html")).equals(PackageExtension.privacyPage(Files.readString(project.resolve("docs/privacy-policy.md")))),"local privacy page differs from reviewed policy");
            }
            String escaped=PackageExtension.privacyPage("# Policy\n\n<script>unsafe & \"quoted\"</script>\n");
            check(!escaped.contains("<script>")&&escaped.contains("&lt;script&gt;unsafe &amp; &quot;quoted&quot;&lt;/script&gt;"),"policy text interpreted as executable markup");
            var before=hashes(root.resolve("target"));Files.setLastModifiedTime(root.resolve("src/core.js"),FileTime.fromMillis(1000));PackageExtension.main(new String[]{root.toString()});check(before.equals(hashes(root.resolve("target"))),"non-reproducible package");
            TimeZone zone=TimeZone.getDefault();try{for(String id:List.of("Europe/Prague","UTC")){TimeZone.setDefault(TimeZone.getTimeZone(id));PackageExtension.main(new String[]{root.toString()});check(before.equals(hashes(root.resolve("target"))),"time zone changed package bytes");}}finally{TimeZone.setDefault(zone);}
            Path dns=root.resolve("src/dns.js");byte[] saved=Files.readAllBytes(dns);Files.delete(dns);expectFailure(root,before);Files.write(dns,saved);
            Path policy=project.resolve("docs/privacy-policy.md");byte[] policyBytes=Files.readAllBytes(policy);Files.delete(policy);expectFailure(root,before);Files.write(policy,policyBytes);
            Path brave=root.resolve("manifests/brave.json");String manifest=Files.readString(brave);var version=java.util.regex.Pattern.compile("\"version\"\\s*:\\s*\"([^\"]+)\"").matcher(manifest);check(version.find(),"missing version");String alternate=version.group(1).equals("0.0.0")?"0.0.1":"0.0.0";Files.writeString(brave,manifest.replace("\""+version.group(1)+"\"","\""+alternate+"\""));expectFailure(root,before);Files.writeString(brave,manifest);
            Files.delete(dns);Files.createSymbolicLink(dns,source.resolve("src/dns.js"));expectFailure(root,before);Files.delete(dns);Files.write(dns,saved);
            try(var c=FileChannel.open(root.resolve("target/.packaging.lock"),StandardOpenOption.WRITE);var lock=c.lock()){check(lock.isValid(),"lock missing");expectFailure(root,before);}
            Path publication=Files.createTempDirectory(project,"publication-");newOutputs(publication);int[] moves={0};boolean failed=false;
            try{PackageExtension.publish(publication,root.resolve("target"),(from,to)->{if(++moves[0]==3)throw new IOException("injected move failure");Files.move(from,to,StandardCopyOption.ATOMIC_MOVE);});}catch(IOException expected){failed=true;}
            check(failed&&before.equals(hashes(root.resolve("target"))),"publication rollback did not restore outputs");PackageExtension.remove(publication);
            publication=Files.createTempDirectory(project,"recovery-");newOutputs(publication);moves[0]=0;boolean retained=false;
            try{PackageExtension.publish(publication,root.resolve("target"),(from,to)->{if(++moves[0]>=3)throw new IOException("injected restoration failure");Files.move(from,to,StandardCopyOption.ATOMIC_MOVE);});}catch(PackageExtension.RecoveryFailure expected){retained=true;}
            check(retained&&Files.isDirectory(publication.resolve("previous/firefox")),"failed recovery lost backup");Files.move(publication.resolve("previous/firefox"),root.resolve("target/firefox"),StandardCopyOption.ATOMIC_MOVE);PackageExtension.remove(publication);check(before.equals(hashes(root.resolve("target"))),"retained backup was not recoverable");
            Path output=root.resolve("target/stargate-brave.zip"),outside=project.resolve("outside");Files.createDirectory(outside);Files.writeString(outside.resolve("sentinel"),"keep");Files.delete(output);Files.createSymbolicLink(output,outside);var linked=hashes(root.resolve("target"));expectFailure(root,linked);check(Files.readString(outside.resolve("sentinel")).equals("keep"),"followed output link");Files.delete(output);
            System.out.println("Packaging payload, ZIP, reproducibility and failure-boundary checks PASS");
        }finally{PackageExtension.remove(project);}
    }
    static void newOutputs(Path stage)throws IOException {
        for(String name:PackageExtension.OUTPUTS)if(name.endsWith(".zip")||name.endsWith(".xpi"))Files.writeString(stage.resolve(name),"new");else{Files.createDirectory(stage.resolve(name));Files.writeString(stage.resolve(name).resolve("new"),"new");}
    }
}
