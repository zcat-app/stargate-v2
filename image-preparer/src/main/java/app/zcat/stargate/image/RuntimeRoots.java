// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.image;

import com.fasterxml.jackson.databind.node.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import static app.zcat.stargate.image.InputFiles.*;

/** Selected files only; no archive is extracted on the host. Host links are deferred. */
final class RuntimeRoots {
    static final Map<String,List<String>> ROLES=new LinkedHashMap<>();
    static {
        ROLES.put("app",List.of("libc6","libgcc-s1","libstdc++6","zlib1g","ca-certificates","base-files"));
        ROLES.put("tor",List.of("libc6","libgcc-s1","zlib1g","libevent-2.1-7t64","libssl3t64","libsystemd0","liblzma5","libzstd1","libseccomp2","libcap2","libgcrypt20","liblz4-1","libgpg-error0","ca-certificates","base-files","tor","tor-geoipdb"));
        ROLES.put("i2p",List.of("libc6","libgcc-s1","libstdc++6","zlib1g","libssl3t64","libboost-json1.83.0","libboost-program-options1.83.0","libboost-url1.83.0","libminiupnpc17","ca-certificates","base-files","i2pd"));
    }
    record Metadata(int type,int mode,long size) {}
    record Link(Path destination,String target) {}
    interface Source {
        String image(); String status()throws Exception; List<String> paths(String name)throws Exception;
        Map<String,Metadata> metadata(List<String> paths)throws Exception;
        byte[] read(String path,int limit)throws Exception; String link(String path)throws Exception;
    }
    static final class DockerSource implements Source,AutoCloseable {
        final Commands commands; final String image,id;
        DockerSource(Commands commands,String image)throws Exception {
            require(image.matches("sha256:[a-f0-9]{64}"),"Immutable OS image ID required");this.commands=commands;this.image=image;
            id=command(commands,"docker","run","--detach","--pull=never","--read-only","--network","none","--cap-drop","ALL","--security-opt","no-new-privileges:true","--entrypoint","/bin/sleep",image,"infinity").strip();
            require(id.matches("[a-f0-9]{64}"),"Invalid source container ID");
        }
        public String image(){return image;}
        byte[] exec(int limit,String...args)throws Exception {var all=new ArrayList<>(List.of("docker","exec",id));all.addAll(List.of(args));return commands.read(all,limit);}
        String text(String...args)throws Exception {return new String(exec(8*1024*1024,args),StandardCharsets.UTF_8);}
        public String status()throws Exception{return text("cat","--","/var/lib/dpkg/status");}
        public List<String> paths(String name)throws Exception{return text("dpkg-query","-L",name).lines().toList();}
        public Map<String,Metadata> metadata(List<String> paths)throws Exception {
            var args=new ArrayList<>(List.of("stat","--printf=%f\t%a\t%s\n","--"));args.addAll(paths.stream().map(s->"/"+s).toList());
            var rows=text(args.toArray(String[]::new)).lines().toList();require(rows.size()==paths.size(),"Incomplete source metadata");
            var result=new LinkedHashMap<String,Metadata>();
            for(int i=0;i<paths.size();i++) {
                String[] row=rows.get(i).split("\t",-1);require(row.length==3&&row[0].matches("[a-f0-9]+")&&row[1].matches("[0-7]{3,4}")&&row[2].matches("[0-9]+"),"Invalid source metadata");
                result.put(paths.get(i),new Metadata(Integer.parseInt(row[0],16)&0170000,Integer.parseInt(row[1],8),Long.parseLong(row[2])));
            }return result;
        }
        public byte[] read(String path,int limit)throws Exception{return exec(limit,"cat","--",path);}
        public String link(String path)throws Exception {String s=text("readlink","--",path);require(s.endsWith("\n"),"Invalid readlink output");return s.substring(0,s.length()-1);}
        public void close()throws Exception {commands.run(List.of("docker","rm","--force",id));}
    }
    static String canonical(String input)throws Exception {
        require(!input.isEmpty()&&input.chars().noneMatch(c->c<32||c==127)&&!input.contains("\\"),"Invalid source path");
        String p=input.startsWith("./")?input.substring(2):input;while(p.startsWith("/"))p=p.substring(1);
        for(String part:p.split("/",-1))require(!part.isEmpty()&&!part.equals("..")&&!part.equals("."),"Unsafe source path");
        for(String alias:List.of("lib64","lib","bin","sbin"))if(p.startsWith(alias+"/"))return "usr/"+p;
        return p;
    }
    static Map<String,String> fields(String stanza)throws Exception {
        var out=new LinkedHashMap<String,String>();
        for(String line:stanza.split("\n"))if(!line.isEmpty()&&!Character.isWhitespace(line.charAt(0))) {
            int split=line.indexOf(": ");
            // dpkg emits empty fields such as "Conffiles:"; preserve them in
            // raw status, matching the previous collector's field projection.
            if(split<0){require(line.matches("[A-Za-z0-9-]+:"),"Malformed Debian control line");continue;}
            require(split>0,"Malformed Debian control line");require(out.putIfAbsent(line.substring(0,split),line.substring(split+2))==null,"Duplicate Debian control field");
        }return out;
    }
    static final class Collected {
        final ObjectNode reports; final List<Link> links;
        Collected(ObjectNode reports,List<Link> links){this.reports=reports;this.links=links;}
        void finishLinks()throws Exception {
            for(var link:links) {
                require(!Files.exists(link.destination(),LinkOption.NOFOLLOW_LINKS),"Link collides with output");
                Files.createSymbolicLink(link.destination(),Path.of(link.target()));
            }
        }
    }
    static Collected collect(Source source,Path output)throws Exception {
        var controls=new LinkedHashMap<String,String>();
        for(String block:source.status().strip().split("\n\n+")) {
            var f=fields(block);require(f.containsKey("Package"),"Package name missing");require(controls.putIfAbsent(f.get("Package"),block)==null,"Duplicate package stanza");
        }
        var names=new TreeSet<String>();ROLES.values().forEach(names::addAll);
        var selected=new LinkedHashMap<String,Set<String>>();var needed=new TreeSet<String>();
        for(String name:names) {
            require(controls.containsKey(name),"Required source package missing: "+name);var paths=new TreeSet<String>();
            for(String p:source.paths(name)) {
                boolean library=List.of("/usr/lib/","/usr/lib64/","/lib/","/lib64/").stream().anyMatch(p::startsWith)&&(p.contains(".so")||p.contains("/gconv/"));
                if(library||p.endsWith("/copyright")||p.startsWith("/usr/share/common-licenses/")||(name.equals("i2pd")&&p.startsWith("/usr/share/i2pd/certificates/")))paths.add(canonical(p));
            }
            switch(name) {
                case "ca-certificates"->paths.add("etc/ssl/certs/ca-certificates.crt");
                case "base-files"->paths.addAll(List.of("usr/lib/os-release","etc/lsb-release","etc/debian_version"));
                case "tor"->paths.add("usr/bin/tor"); case "tor-geoipdb"->paths.addAll(List.of("usr/share/tor/geoip","usr/share/tor/geoip6"));
                case "i2pd"->paths.add("usr/bin/i2pd"); default->{}
            }
            selected.put(name,paths);needed.addAll(paths);
        }
        var metadata=source.metadata(List.copyOf(needed));require(metadata.keySet().equals(needed),"Incomplete selected metadata");
        var reports=JSON.createObjectNode();var records=new HashMap<String,ArrayNode>();var links=new ArrayList<Link>();
        for(var role:ROLES.entrySet()) {
            Path root=output.resolve("rootfs-"+role.getKey());Files.createDirectory(root);mode(root,0755);
            var report=reports.putObject(role.getKey()).put("image_role",role.getKey()).put("source_image_id",source.image()).put("method","Runtime file subsets from authenticated Ubuntu/Tor packages; package control metadata is retained, not a claim that entire packages are installed.");
            var packages=report.putObject("packages");for(String name:role.getValue())packages.set(name,JSON.valueToTree(fields(controls.get(name))));
            records.put(role.getKey(),report.putArray("files"));
        }
        // Materialize regular files first, then generated metadata/licenses, then links.
        for(String path:needed) {
            var info=metadata.get(path);require(info!=null,"Missing source metadata");
            // dpkg lists nested certificate directories too. The former export
            // collector skipped them; parent scaffolding is created below.
            if(info.type()==0040000)continue;
            require(info.type()==0100000||info.type()==0120000,"Unsupported selected source file type: "+path);
            var owners=names.stream().filter(n->selected.get(n).contains(path)).toList();
            byte[] data=null;String target=null;
            if(info.type()==0100000) {
                require(info.size()>=0&&info.size()<=256*1024*1024,"Selected file too large");data=source.read("/"+path,(int)info.size());require(data.length==info.size(),"Source file size changed");
            }else {
                target=source.link("/"+path);require(!target.isEmpty()&&target.chars().noneMatch(c->c<32||c==127),"Invalid symlink target");
                Path inside=target.startsWith("/")?Path.of(target.substring(1)):Path.of(path).getParent().resolve(target);
                require(!inside.normalize().startsWith(".."),"Link escapes runtime root");
            }
            for(var role:ROLES.entrySet())if(owners.stream().anyMatch(role.getValue()::contains)) {
                Path dest=output.resolve("rootfs-"+role.getKey()).resolve(path);directories(dest.getParent());
                var record=records.get(role.getKey()).addObject().put("path","/"+path);record.set("packages",JSON.valueToTree(owners));
                if(data!=null){Files.write(dest,data,StandardOpenOption.CREATE_NEW);mode(dest,info.mode()&0777);record.put("sha256",hash(dest));}
                else {links.add(new Link(dest,target));record.put("symlink",target);}
            }
        }
        for(var role:ROLES.entrySet()) {
            Path root=output.resolve("rootfs-"+role.getKey());
            for(String alias:List.of("lib","lib64","bin","sbin")){directories(root.resolve("usr/"+alias));links.add(new Link(root.resolve(alias),"usr/"+alias));}
            links.add(new Link(root.resolve("etc/os-release"),"../usr/lib/os-release"));
            write(root.resolve("etc/passwd"),"root:x:0:0:root:/nonexistent:/nonexistent\nstargate:x:10001:10001:Stargate:/nonexistent:/nonexistent\n");
            write(root.resolve("etc/group"),"root:x:0:\nstargate:x:10001:\n");
            write(root.resolve("etc/nsswitch.conf"),"passwd: files\ngroup: files\nshadow: files\nhosts: files dns\nnetworks: files\n");
            Files.createDirectory(root.resolve("tmp"));mode(root.resolve("tmp"),01777);
            var database=new StringBuilder();for(String name:role.getValue())database.append(controls.get(name)).append("\nX-Stargate-Runtime-Slice: yes\n\n");
            write(root.resolve("var/lib/dpkg/status"),database.toString());
            for(String name:role.getValue()) {
                byte[] copyright=source.read("/usr/share/doc/"+name+"/copyright",8*1024*1024);
                Path file=root.resolve("usr/share/stargate/licenses/"+name+".copyright");directories(file.getParent());Files.write(file,copyright,StandardOpenOption.CREATE_NEW);mode(file,0644);
            }
        }
        write(output.resolve("rootfs-i2p/etc/i2pd/tunnels.conf"),"# No production server tunnels.\n");directories(output.resolve("rootfs-i2p/etc/i2pd/tunnels.d"));
        Map<String,List<String>> owned=Map.of("app",List.of("data","run/stargate","run/i2p-control"),"tor",List.of("var/lib/tor","run/tor-control"),"i2p",List.of("var/lib/i2pd","run/i2p-control"));
        for(var role:owned.entrySet())for(String path:role.getValue()){Path dir=output.resolve("owned-"+role.getKey()).resolve(path);directories(dir);mode(dir,0700);}
        return new Collected(reports,links);
    }
}
