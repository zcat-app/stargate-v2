// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.image;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

final class InputFiles {
    static final ObjectMapper JSON=JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    static void require(boolean ok,String message)throws IOException {if(!ok)throw new IOException(message);}
    static JsonNode json(Path file)throws IOException {
        regular(file); require(Files.size(file)<=4*1024*1024,"JSON input too large");
        return JSON.reader().with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).readTree(Files.readAllBytes(file));
    }
    static String text(JsonNode node,String key)throws IOException {
        var n=node.get(key);require(n!=null&&n.isTextual()&&!n.asText().isBlank(),"Missing text field: "+key);return n.asText();
    }
    static void regular(Path p)throws IOException {require(Files.isRegularFile(p,NOFOLLOW_LINKS)&&p.toAbsolutePath().normalize().equals(p.toRealPath()),"Regular source without aliases required: "+p);}
    static String hash(Path file)throws Exception {
        regular(file);var md=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(file,NOFOLLOW_LINKS)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)md.update(b,0,n);}return HexFormat.of().formatHex(md.digest());
    }
    static void checked(Path file,JsonNode expected)throws Exception {require(expected!=null&&expected.isTextual()&&expected.asText().matches("[a-f0-9]{64}")&&hash(file).equals(expected.asText()),"Checksum mismatch: "+file);}
    static void directories(Path p)throws IOException {
        var missing=new ArrayList<Path>();for(Path q=p;!Files.exists(q,NOFOLLOW_LINKS);q=q.getParent())missing.add(q);
        for(Path q:missing.reversed()){Files.createDirectory(q);mode(q,0755);}
        require(Files.isDirectory(p,NOFOLLOW_LINKS),"Directory required");
    }
    static void copy(Path from,Path to)throws IOException {regular(from);directories(to.getParent());Files.copy(from,to,StandardCopyOption.COPY_ATTRIBUTES,StandardCopyOption.REPLACE_EXISTING);}
    static void mode(Path p,int mode)throws IOException {Files.setAttribute(p,"unix:mode",mode,NOFOLLOW_LINKS);}
    static void write(Path p,String text)throws IOException {directories(p.getParent());Files.writeString(p,text,StandardOpenOption.CREATE_NEW);mode(p,0644);}
    static void writeJson(Path p,JsonNode n)throws IOException {write(p,JSON.writerWithDefaultPrettyPrinter().writeValueAsString(n)+"\n");}
    static void remove(Path root)throws IOException {
        if(!Files.exists(root,NOFOLLOW_LINKS))return;
        try(var paths=Files.walk(root)){for(Path p:paths.sorted(Comparator.reverseOrder()).toList())Files.delete(p);}
    }
    static void tree(Path from,Path to)throws IOException {
        require(Files.isDirectory(from,NOFOLLOW_LINKS)&&from.toRealPath().equals(from.toAbsolutePath().normalize()),"Source directory required");
        try(var paths=Files.walk(from)){for(Path p:paths.sorted().toList()) {
            Path dest=to.resolve(from.relativize(p));
            if(Files.isDirectory(p,NOFOLLOW_LINKS)){directories(dest);mode(dest,0755);}else copy(p,dest);
        }}
    }
    interface Commands {
        byte[] read(List<String> args,int limit)throws Exception;
        void run(List<String> args)throws Exception;
    }
    static final class SystemCommands implements Commands {
        public byte[] read(List<String> args,int limit)throws Exception {
            Process p=new ProcessBuilder(args).redirectError(ProcessBuilder.Redirect.INHERIT).start();
            p.getOutputStream().close();
            try(var workers=Executors.newVirtualThreadPerTaskExecutor()) {
                var result=workers.submit(()->{try(var in=p.getInputStream()){byte[] b=in.readNBytes(limit+1);if(b.length>limit){p.destroyForcibly();throw new IOException("Command output too large");}return b;}});
                try {byte[] bytes=result.get(120,TimeUnit.SECONDS);require(p.waitFor(30,TimeUnit.SECONDS)&&p.exitValue()==0,"Command failed: "+args.getFirst());return bytes;}
                finally{p.destroyForcibly();p.getInputStream().close();result.cancel(true);}
            }
        }
        public void run(List<String> args)throws Exception {
            Process p=new ProcessBuilder(args).inheritIO().start();
            try{require(p.waitFor(Duration.ofHours(1))&&p.exitValue()==0,"Command failed: "+args.getFirst());}finally{p.destroyForcibly();}
        }
    }
    static String command(Commands commands,String...args)throws Exception {return new String(commands.read(List.of(args),8*1024*1024),java.nio.charset.StandardCharsets.UTF_8);}
}
