// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.updater;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.*;
import static java.nio.file.LinkOption.NOFOLLOW_LINKS;

final class UpdateFiles {
    static final ObjectMapper JSON=JsonMapper.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();
    static final Set<String> SERVICES=Set.of("app","tor","i2p","nym");
    static final String HASH="[a-f0-9]{64}", IMAGE="sha256:"+HASH;
    static void require(boolean value,String code) {if(!value)throw new IllegalArgumentException(code);}
    static byte[] read(Path p,int max)throws IOException {
        require(Files.isRegularFile(p,NOFOLLOW_LINKS),"REGULAR_FILE_REQUIRED");
        try(var in=Files.newInputStream(p,NOFOLLOW_LINKS)){byte[] b=in.readNBytes(max+1);require(b.length<=max,"FILE_TOO_LARGE");return b;}
    }
    static JsonNode json(Path p)throws IOException {return JSON.readTree(read(p,262144));}
    static String hash(byte[] b)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(b));}
    static String hash(Path p)throws Exception {
        require(Files.isRegularFile(p,NOFOLLOW_LINKS),"REGULAR_FILE_REQUIRED");
        var md=MessageDigest.getInstance("SHA-256");try(var in=Files.newInputStream(p,NOFOLLOW_LINKS)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)md.update(b,0,n);}return HexFormat.of().formatHex(md.digest());
    }
    static void directory(Path p,String permissions)throws IOException {
        if(!Files.exists(p,NOFOLLOW_LINKS)){Files.createDirectory(p,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(permissions)));Files.setPosixFilePermissions(p,PosixFilePermissions.fromString(permissions));}
        require(Files.isDirectory(p,NOFOLLOW_LINKS)&&p.toRealPath().equals(p.toAbsolutePath().normalize()),"DIRECTORY_ALIAS_REJECTED");
        require(Files.getOwner(p).equals(Files.getOwner(Path.of("/proc/self"))),"OWNER_REQUIRED");
        require(Files.getPosixFilePermissions(p).equals(PosixFilePermissions.fromString(permissions)),"DIRECTORY_MODE_REQUIRED");
        trustedAncestors(p.getParent());
    }
    static void privateFile(Path p)throws IOException {
        require(Files.isRegularFile(p,NOFOLLOW_LINKS)&&Files.getOwner(p).equals(Files.getOwner(Path.of("/proc/self"))),"PRIVATE_FILE_REQUIRED");
        require(Files.getPosixFilePermissions(p).equals(PosixFilePermissions.fromString("rw-------")),"PRIVATE_FILE_MODE_REQUIRED");
        require(p.toAbsolutePath().normalize().equals(p.toRealPath()),"FILE_ALIAS_REJECTED");trustedAncestors(p.toAbsolutePath().getParent());
    }
    static void trustedAncestors(Path p)throws IOException {
        var self=Files.getOwner(Path.of("/proc/self"));
        for(Path dir=p;dir!=null;dir=dir.getParent()) {
            require(Files.isDirectory(dir,NOFOLLOW_LINKS),"DIRECTORY_ALIAS_REJECTED");var owner=Files.getOwner(dir);
            require(owner.equals(self)||((Number)Files.getAttribute(dir,"unix:uid")).intValue()==0,"UNTRUSTED_PARENT_OWNER");
            int mode=((Number)Files.getAttribute(dir,"unix:mode")).intValue();
            require((mode&0022)==0||((mode&01000)!=0&&((Number)Files.getAttribute(dir,"unix:uid")).intValue()==0),"WRITABLE_PARENT_REJECTED");
        }
    }
    static void write(Path p,JsonNode value,boolean publicFile)throws Exception {write(p,JSON.writeValueAsBytes(value),publicFile);}
    static void write(Path p,byte[] b,boolean publicFile)throws Exception {
        var privateMode=PosixFilePermissions.fromString("rw-------");
        Path tmp=Files.createTempFile(p.getParent(),".publish-","",PosixFilePermissions.asFileAttribute(privateMode));
        try {
            // Creation attributes are filtered by the process umask. Keep incomplete
            // content private, then set the final mode explicitly before publication.
            Files.setPosixFilePermissions(tmp,privateMode);
            try(var out=java.nio.channels.FileChannel.open(tmp,StandardOpenOption.WRITE)){
                var buffer=java.nio.ByteBuffer.wrap(b);while(buffer.hasRemaining())require(out.write(buffer)>0,"WRITE_STALLED");
                if(publicFile)Files.setPosixFilePermissions(tmp,PosixFilePermissions.fromString("rw-r--r--"));
                out.force(true);
            }
            Files.move(tmp,p,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);sync(p.getParent());
        }finally{Files.deleteIfExists(tmp);}
    }
    static void sync(Path p)throws IOException {try(var c=java.nio.channels.FileChannel.open(p,StandardOpenOption.READ)){c.force(true);}}
    static void keys(JsonNode n,String... names) {var allowed=Set.of(names);require(n.isObject(),"OBJECT_REQUIRED");n.fieldNames().forEachRemaining(k->require(allowed.contains(k),"UNKNOWN_FIELD"));}
    static String text(JsonNode n,String name,String pattern) {var v=n.path(name);require(v.isTextual()&&v.asText().matches(pattern),"INVALID_"+name.toUpperCase(Locale.ROOT));return v.asText();}
}
