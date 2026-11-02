// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

/** Retained private plaintext and read-only helper snapshots for authenticated import. */
final class ArchiveInputs implements AutoCloseable, DockerImport.SourceGuard {
    final Path directory, spool, core, adapter;
    final String digest; final boolean nym; final Map<String,String> hashes;
    private final int root, dir, spoolFd, uid, gid;
    private final Linux.Stat rootInfo, directoryInfo, spoolInfo, coreInfo, adapterInfo;
    ArchiveInputs(Path privateDir, String token, Path archive, Path identity, Path age, String ageHash,
                  Path coreJar, Path adapterJar, int uid, int gid) throws Exception {
        DockerPolicy.token(token); this.uid=uid; this.gid=gid;
        Path base=DurableJournal.safePath(privateDir.toString());
        for(Path input : new Path[]{archive,identity,age,coreJar,adapterJar}) if(DurableJournal.safePath(input.toString()).startsWith(base)) throw DockerPolicy.failure();
        if(coreJar.equals(adapterJar)) throw DockerPolicy.failure();
        int r=Linux.openDir(base.toString(),true,uid), d=-1, s=-1;
        try {
            if(Linux.stat(r).gid()!=Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
            String name="stargate-archive-"+token; Linux.mkdir(r,name); Linux.sync(r);
            d=Linux.openAt(r,name,Linux.RDONLY|Linux.DIRECTORY|Linux.NOFOLLOW|Linux.CLOEXEC,0);
            Linux.Stat info=Linux.stat(d); if(info.uid()!=Integer.toUnsignedLong(uid)||info.gid()!=Integer.toUnsignedLong(gid)||(info.mode()&07777)!=0700) throw DockerPolicy.failure();
            directory=base.resolve(name); spool=directory.resolve("authenticated.tar"); core=directory.resolve("core.jar"); adapter=directory.resolve("adapter.jar");
            int cipher=Linux.openRegular(DurableJournal.safePath(archive.toString()),ArchiveInspector.MAX_ARCHIVE+32L*1024*1024,false,uid);
            try {
                s=Linux.openAt(d,"authenticated.tar",Linux.RDWR|Linux.CREAT|Linux.EXCL|Linux.NOFOLLOW|Linux.CLOEXEC,0600);
                Linux.Stat made=Linux.stat(s); if(!VolumeSnapshot.regular(made)||made.links()!=1||made.uid()!=Integer.toUnsignedLong(uid)||made.gid()!=Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
                Linux.chmod(s,0600); AgeDecrypt.decrypt(age,ageHash,identity,cipher,s,uid);
            } finally {Linux.close(cipher);}
            ArchivePreflight.Result result=ArchivePreflight.inspect(s); digest=result.sha256(); nym=result.summary().nym();
            Linux.chmod(s,0444); Linux.sync(s); spoolInfo=Linux.stat(s);
            String coreHash=PinnedInputs.snapshot(coreJar,d,"core.jar",uid), adapterHash=PinnedInputs.snapshot(adapterJar,d,"adapter.jar",uid);
            hashes=Map.of("core.jar",coreHash,"adapter.jar",adapterHash);
            coreInfo=PinnedInputs.statSnapshot(d,"core.jar",uid,gid); adapterInfo=PinnedInputs.statSnapshot(d,"adapter.jar",uid,gid);
            Linux.sync(d); Linux.sync(r); rootInfo=Linux.stat(r); directoryInfo=Linux.stat(d); root=r; dir=d; spoolFd=s;
            check(); guardDigest();
        } catch(Exception e) {
            if(s>=0) try {Linux.close(s);} catch(Exception x){e.addSuppressed(x);} if(d>=0) try {Linux.close(d);} catch(Exception x){e.addSuppressed(x);}
            try {Linux.close(r);} catch(Exception x){e.addSuppressed(x);} throw e;
        }
    }
    public void check() throws Exception {
        int reopened=Linux.openDir(directory.getParent().toString(),true,uid);
        try {
            if(!rootInfo.equals(Linux.stat(reopened))) throw DockerPolicy.failure();
            int child=Linux.openAt(reopened,directory.getFileName().toString(),Linux.RDONLY|Linux.DIRECTORY|Linux.NOFOLLOW|Linux.CLOEXEC,0);
            try {if(!directoryInfo.equals(Linux.stat(child))) throw DockerPolicy.failure();} finally {Linux.close(child);}
        } finally {Linux.close(reopened);}
        if(!spoolInfo.equals(Linux.stat(spoolFd)) || !spoolInfo.equals(statSpool())
                || !coreInfo.equals(PinnedInputs.statSnapshot(dir,"core.jar",uid,gid)) || !adapterInfo.equals(PinnedInputs.statSnapshot(dir,"adapter.jar",uid,gid))) throw DockerPolicy.failure();
    }
    private Linux.Stat statSpool() throws IOException {
        int fd=Linux.openAt(dir,"authenticated.tar",Linux.RDONLY|Linux.NONBLOCK|Linux.NOFOLLOW|Linux.CLOEXEC,0);
        try {
            Linux.Stat s=Linux.stat(fd);
            if(!VolumeSnapshot.regular(s)||s.links()!=1||s.size()>ArchiveInspector.MAX_ARCHIVE||s.uid()!=Integer.toUnsignedLong(uid)
                    ||s.gid()!=Integer.toUnsignedLong(gid)||(s.mode()&07777)!=0444) throw DockerPolicy.failure();
            return s;
        } finally {Linux.close(fd);}
    }
    void guardDigest() throws Exception { check(); ArchivePreflight.guard(spoolFd,spoolInfo,digest); }
    public void close() throws IOException {
        IOException failure=null; for(int fd:new int[]{spoolFd,dir,root}) try {Linux.close(fd);} catch(IOException e){if(failure==null) failure=e;else failure.addSuppressed(e);}
        if(failure!=null) throw failure;
    }
}
