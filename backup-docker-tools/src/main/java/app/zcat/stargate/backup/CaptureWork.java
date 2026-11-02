// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/** Private capture spool, snapshots, authenticated roundtrip and no-replace output. */
final class CaptureWork implements AutoCloseable {
    final Path location, spool, core, adapter; final String coreSha, adapterSha;
    private final Path outputParent; private final String outputName; private final int parent,dir,spoolFd,uid,gid;
    private final Linux.Stat parentInfo, directoryInfo, initialSpool, coreInfo, adapterInfo;
    private final Set<String> files=new LinkedHashSet<>(); boolean retain, published;
    private ArchiveInspector.Summary summary;
    CaptureWork(Path output,String token,Path coreJar,Path adapterJar,int uid,int gid) throws Exception {
        DockerPolicy.token(token); this.uid=uid;this.gid=gid;Path target=DurableJournal.safePath(output.toString());
        if(target.getFileName()==null)throw DockerPolicy.failure();outputParent=target.getParent();outputName=target.getFileName().toString();
        if(coreJar.startsWith(outputParent)||adapterJar.startsWith(outputParent)||coreJar.equals(adapterJar))throw DockerPolicy.failure();
        int p=Linux.openDir(outputParent.toString(),true,uid),d=-1,s=-1;
        try {
            if(Linux.stat(p).gid()!=Integer.toUnsignedLong(gid))throw DockerPolicy.failure();
            try {Files.readAttributes(Linux.fdPath(p).resolve(outputName),BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);throw DockerPolicy.failure();}
            catch(NoSuchFileException absent) { }
            String name=".stargate-capture-"+token;Linux.mkdir(p,name);d=Linux.openAt(p,name,Linux.RDONLY|Linux.DIRECTORY|Linux.NOFOLLOW|Linux.CLOEXEC,0);
            Linux.Stat work=Linux.stat(d);if(work.uid()!=Integer.toUnsignedLong(uid)||work.gid()!=Integer.toUnsignedLong(gid)||(work.mode()&07777)!=0700)throw DockerPolicy.failure();
            location=outputParent.resolve(name);spool=location.resolve("archive.tar");core=location.resolve("core.jar");adapter=location.resolve("adapter.jar");
            s=Linux.openAt(d,"archive.tar",Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);files.add("archive.tar"); Linux.chmod(s,0600);
            initialSpool=Linux.stat(s);if(!VolumeSnapshot.regular(initialSpool)||initialSpool.links()!=1||initialSpool.size()!=0||initialSpool.uid()!=Integer.toUnsignedLong(uid)||initialSpool.gid()!=Integer.toUnsignedLong(gid))throw DockerPolicy.failure();
            coreSha=PinnedInputs.snapshot(coreJar,d,"core.jar",uid);files.add("core.jar");adapterSha=PinnedInputs.snapshot(adapterJar,d,"adapter.jar",uid);files.add("adapter.jar");
            coreInfo=PinnedInputs.statSnapshot(d,"core.jar",uid,gid);adapterInfo=PinnedInputs.statSnapshot(d,"adapter.jar",uid,gid);
            Linux.sync(s);Linux.sync(d);Linux.sync(p);parentInfo=Linux.stat(p);directoryInfo=Linux.stat(d);parent=p;dir=d;spoolFd=s;
        } catch(Exception e) {
            if(s>=0)try{Linux.close(s);}catch(Exception x){e.addSuppressed(x);}if(d>=0)try{Linux.close(d);}catch(Exception x){e.addSuppressed(x);}try{Linux.close(p);}catch(Exception x){e.addSuppressed(x);}throw e;
        }
    }
    void guard(boolean empty) throws Exception {
        int reopenedParent=Linux.openDir(outputParent.toString(),true,uid);
        try {if(!parentInfo.equals(Linux.stat(reopenedParent)))throw DockerPolicy.failure();}finally{Linux.close(reopenedParent);}
        int reopened=Linux.openAt(parent,location.getFileName().toString(),Linux.RDONLY|Linux.DIRECTORY|Linux.NOFOLLOW|Linux.CLOEXEC,0);
        try {if(!directoryInfo.equals(Linux.stat(reopened)))throw DockerPolicy.failure();}finally{Linux.close(reopened);}
        if(!coreInfo.equals(PinnedInputs.statSnapshot(dir,"core.jar",uid,gid))||!adapterInfo.equals(PinnedInputs.statSnapshot(dir,"adapter.jar",uid,gid)))throw DockerPolicy.failure();
        int named=Linux.openAt(dir,"archive.tar",Linux.RDONLY|Linux.NONBLOCK|Linux.NOFOLLOW|Linux.CLOEXEC,0);
        try {
            Linux.Stat current=Linux.stat(spoolFd),path=Linux.stat(named);
            if(!current.equals(path)||current.devMajor()!=initialSpool.devMajor()||current.devMinor()!=initialSpool.devMinor()||current.inode()!=initialSpool.inode()
                    ||!VolumeSnapshot.regular(current)||current.links()!=1||current.uid()!=Integer.toUnsignedLong(uid)||current.gid()!=Integer.toUnsignedLong(gid)
                    ||(current.mode()&07777)!=0600||current.size()>ArchiveInspector.MAX_ARCHIVE||(empty && !current.equals(initialSpool)))throw DockerPolicy.failure();
        } finally {Linux.close(named);}
    }
    void prepare(AgeDecrypt.Session age,String recipient,boolean nym) throws Exception {
        guard(false);Linux.Stat before=Linux.stat(spoolFd);String digest=ArchivePreflight.digest(spoolFd,before);
        try(FileChannel source=FileChannel.open(Linux.fdPath(spoolFd),StandardOpenOption.READ)){summary=ArchiveInspector.inspect(source,null);}
        if(summary.nym()!=nym||!before.equals(Linux.stat(spoolFd)))throw DockerPolicy.failure();
        int encrypted=create("archive.age");
        try {age.encrypt(spoolFd,encrypted,recipient);}
        catch(AgeDecrypt.Uncertain failure){retain=true;throw failure;} finally{Linux.close(encrypted);}
        Linux.unlink(dir,"archive.tar",false);files.remove("archive.tar");
        int cipher=Linux.openAt(dir,"archive.age",Linux.RDONLY|Linux.NONBLOCK|Linux.NOFOLLOW|Linux.CLOEXEC,0);
        try {
            int verified=create("verified.tar");
            try {
                try {age.decrypt(cipher,verified);}catch(AgeDecrypt.Uncertain failure){retain=true;throw failure;}
                Linux.Stat stat=Linux.stat(verified);
                if(!digest.equals(ArchivePreflight.digest(verified,stat)))throw DockerPolicy.failure();
                try(FileChannel input=FileChannel.open(Linux.fdPath(verified),StandardOpenOption.READ)){if(!summary.equals(ArchiveInspector.inspect(input,null)))throw DockerPolicy.failure();}
            } finally {Linux.close(verified);}
        } finally {Linux.close(cipher);}
        Linux.unlink(dir,"verified.tar",false);files.remove("verified.tar");
    }
    void publish() throws IOException {
        Linux.link(dir,"archive.age",parent,outputName);published=true;
        try {Linux.sync(parent);}catch(IOException e){retain=true;throw e;}
    }
    ArchiveInspector.Summary summary(){return summary;}
    Map<String,String> hashes(){return Map.of("core.jar",coreSha,"adapter.jar",adapterSha);}
    private int create(String name) throws IOException {
        int fd=Linux.openAt(dir,name,Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);files.add(name);
        try {Linux.chmod(fd,0600);return fd;}catch(IOException e){try{Linux.close(fd);}catch(IOException close){e.addSuppressed(close);}throw e;}
    }
    public void close() throws IOException {
        boolean failed=retain,removed=false;
        try{Linux.close(spoolFd);}catch(IOException e){failed=true;}
        if(!retain)for(String file:Set.copyOf(files))try{Linux.unlink(dir,file,false);files.remove(file);}catch(IOException e){failed=true;}
        try{Linux.sync(dir);if(!failed){Linux.unlink(parent,location.getFileName().toString(),true);removed=true;Linux.sync(parent);}}
        catch(IOException e){failed=true;if(removed)try{Linux.mkdir(parent,location.getFileName().toString());Linux.sync(parent);}catch(IOException ignored){}}
        try{Linux.close(dir);}catch(IOException e){failed=true;}try{Linux.close(parent);}catch(IOException e){failed=true;}
        if(failed)throw new IOException("Private capture work retained or unconfirmed: "+location);
    }
}
