// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
import java.io.*;
import java.nio.channels.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;
import java.util.zip.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

/** Packages executable sources unchanged and renders the local privacy policy. */
public final class PackageExtension {
    static final List<String> SHARED=List.of("core.js","observations.js","presentation.js","art.js","ipfs.js","ipfs-handler.html","ipfs-handler.js","quick-start.html","storage.js","webrtc.js","dns.js","background.js","ui.html","ui.js","ui.css","theme.css");
    static final List<String> OUTPUTS=List.of("firefox","brave","stargate-firefox.xpi","stargate-brave.zip");
    static final String WORKER="importScripts('core.js','observations.js','presentation.js','ipfs.js','storage.js','webrtc.js','dns.js','adapter.js','background.js');\n";
    static void require(boolean test,String code){if(!test)throw new IllegalArgumentException(code);}
    public static void main(String[] args)throws Exception {
        require(args.length==1,"Use bash extension/package.sh");
        Path root=Path.of(args[0]).toRealPath(),target=root.resolve("target");
        if(!Files.exists(target,NOFOLLOW_LINKS))Files.createDirectory(target);
        require(Files.isDirectory(target,NOFOLLOW_LINKS),"OUTPUT_DIRECTORY_REQUIRED");
        Path lockFile=target.resolve(".packaging.lock");
        require(!Files.exists(lockFile,NOFOLLOW_LINKS)||Files.isRegularFile(lockFile,NOFOLLOW_LINKS),"REGULAR_LOCK_REQUIRED");
        try(var channel=FileChannel.open(lockFile,StandardOpenOption.CREATE,StandardOpenOption.WRITE,NOFOLLOW_LINKS);var lock=channel.tryLock()) {
            require(lock!=null,"PACKAGING_ALREADY_RUNNING");
            Path stage=Files.createTempDirectory(target,".packaging-");
            boolean cleanup=true;
            try {
                String version=null;
                for(String browser:List.of("firefox","brave")) {
                    Path manifest=root.resolve("manifests/"+browser+".json");regular(manifest);
                    var match=Pattern.compile("\"version\"\\s*:\\s*\"([0-9]+(?:\\.[0-9]+){1,3})\"").matcher(Files.readString(manifest));
                    require(match.find(),"MANIFEST_VERSION_REQUIRED");String current=match.group(1);require(!match.find(),"DUPLICATE_MANIFEST_VERSION");
                    require(version==null||version.equals(current),"BROWSER_VERSIONS_DIFFER");version=current;
                    Path folder=stage.resolve(browser);Files.createDirectory(folder);mode(folder,"rwxr-xr-x");
                    for(String name:SHARED)copy(root.resolve("src/"+name),folder.resolve(name));
                    copy(root.resolve("src/adapter-"+browser+".js"),folder.resolve("adapter.js"));copy(manifest,folder.resolve("manifest.json"));
                    Path icons=root.resolve("src/icons");require(Files.isDirectory(icons,NOFOLLOW_LINKS),"ICONS_DIRECTORY_REQUIRED");
                    try(var paths=Files.walk(icons)) {
                        for(Path source:paths.sorted().toList()) {
                            Path dest=folder.resolve("icons").resolve(icons.relativize(source));
                            if(Files.isDirectory(source,NOFOLLOW_LINKS)){Files.createDirectory(dest);mode(dest,"rwxr-xr-x");}else copy(source,dest);
                        }
                    }
                    copy(root.resolve("NOTICE"),folder.resolve("NOTICE"));copy(root.getParent().resolve("LICENSES/Apache-2.0.txt"),folder.resolve("LICENSE"));
                    copy(root.getParent().resolve("docs/privacy-policy.md"),folder.resolve("PRIVACY.md"));
                    Path policy=folder.resolve("privacy.html");Files.writeString(policy,privacyPage(Files.readString(folder.resolve("PRIVACY.md"))));mode(policy,"rw-r--r--");
                    if(browser.equals("brave")){Path worker=folder.resolve("worker.js");Files.writeString(worker,WORKER);mode(worker,"rw-r--r--");}
                    Path archive=stage.resolve(browser.equals("firefox")?"stargate-firefox.xpi":"stargate-brave.zip");
                    try(var out=new ZipOutputStream(Files.newOutputStream(archive));var paths=Files.walk(folder)) {
                        out.setLevel(6);
                        for(Path file:paths.filter(p->Files.isRegularFile(p,NOFOLLOW_LINKS)).sorted().toList()) {
                            String name=folder.relativize(file).toString().replace(File.separatorChar,'/');
                            // Avoid the 1980 sentinel: ZipEntry adds a zone-dependent
                            // extended timestamp at that exact boundary (verified in JDK source).
                            var entry=new ZipEntry(name);entry.setTimeLocal(LocalDateTime.of(2000,1,1,0,0));out.putNextEntry(entry);Files.copy(file,out);out.closeEntry();
                        }
                    }
                    mode(archive,"rw-r--r--");
                }
                publish(stage,target);
                System.out.println(target.resolve("stargate-firefox.xpi"));System.out.println(target.resolve("stargate-brave.zip"));
            }catch(RecoveryFailure failure){cleanup=false;throw failure;}
            finally{if(cleanup)remove(stage);}
        }
    }
    static void regular(Path p)throws IOException {require(Files.isRegularFile(p,NOFOLLOW_LINKS)&&p.toAbsolutePath().normalize().equals(p.toRealPath()),"REGULAR_SOURCE_REQUIRED: "+p.getFileName());}
    // The policy uses headings and paragraphs only. Escape all text; never interpret
    // Markdown links or raw HTML. Both packaged forms derive from the same policy.
    static String privacyPage(String text) {
        var page=new StringBuilder("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"referrer\" content=\"no-referrer\"><title>Stargate privacy policy</title><style>body{font:1rem/1.6 system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem;color:#172336;background:#fff}h1,h2{line-height:1.25}p{overflow-wrap:anywhere}a{color:#164cb7;display:inline-block;min-height:44px;min-width:44px}a:focus-visible{outline:3px solid #164cb7;outline-offset:4px}</style></head><body><main>\n");
        for(String block:text.strip().split("\\R\\s*\\R")) {
            String tag=block.startsWith("## ")?"h2":block.startsWith("# ")?"h1":"p";
            String content=block.replaceFirst("^#{1,2} ","").replaceAll("\\R"," ");
            page.append('<').append(tag).append('>').append(content.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\"","&quot;")).append("</").append(tag).append(">\n");
        }
        return page.append("<p><a href=\"ui.html#help\">Back to Stargate help</a></p></main></body></html>\n").toString();
    }
    static void copy(Path from,Path to)throws IOException {regular(from);Files.copy(from,to);mode(to,"rw-r--r--");}
    static void mode(Path p,String permissions)throws IOException {if(Files.getFileStore(p).supportsFileAttributeView("posix"))Files.setPosixFilePermissions(p,PosixFilePermissions.fromString(permissions));}
    interface Rename {void move(Path from,Path to)throws IOException;}
    static void publish(Path stage,Path target)throws Exception {
        publish(stage,target,(from,to)->Files.move(from,to,StandardCopyOption.ATOMIC_MOVE));
    }
    static void publish(Path stage,Path target,Rename rename)throws Exception {
        for(String name:OUTPUTS) {
            Path existing=target.resolve(name);if(!Files.exists(existing,NOFOLLOW_LINKS))continue;
            require(name.endsWith(".zip")||name.endsWith(".xpi")?Files.isRegularFile(existing,NOFOLLOW_LINKS):Files.isDirectory(existing,NOFOLLOW_LINKS),"UNEXPECTED_OUTPUT_TYPE");
        }
        Path backup=stage.resolve("previous");Files.createDirectory(backup);var moved=new ArrayList<String>();var published=new ArrayList<String>();
        try {
            for(String name:OUTPUTS) {
                Path dest=target.resolve(name);if(Files.exists(dest,NOFOLLOW_LINKS)){rename.move(dest,backup.resolve(name));moved.add(name);}
                rename.move(stage.resolve(name),dest);published.add(name);
            }
        }catch(Exception failure) {
            // Restore only paths this invocation moved. Keep the stage if recovery itself fails.
            try {for(String name:published.reversed())remove(target.resolve(name));for(String name:moved.reversed())rename.move(backup.resolve(name),target.resolve(name));}
            catch(Exception restore){failure.addSuppressed(restore);throw new RecoveryFailure(stage,failure);}
            throw failure;
        }
    }
    static final class RecoveryFailure extends IOException {
        RecoveryFailure(Path stage,Exception cause){super("OUTPUT_RECOVERY_REQUIRES_INSPECTION: "+stage,cause);}
    }
    static void remove(Path directory)throws IOException {
        if(!Files.exists(directory,NOFOLLOW_LINKS))return;
        try(var paths=Files.walk(directory)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
    }
}
