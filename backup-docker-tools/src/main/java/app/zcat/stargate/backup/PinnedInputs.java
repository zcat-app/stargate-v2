// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

/** Pins the stopped source directory and private, read-only helper snapshots. */
final class PinnedInputs implements AutoCloseable, DockerImport.SourceGuard {
    private static final long MAX_JAR = 64L * 1024 * 1024;
    private static final int O_PATH = 0x200000;
    final Path source, directory, core, adapter;
    final String coreSha, adapterSha;
    private final int sourceFd, parent, snapshots;
    private final Linux.Stat sourceIdentity, parentIdentity, directoryIdentity, coreIdentity, adapterIdentity;
    PinnedInputs(Path source, Path journalDirectory, String token, Path coreJar, Path adapterJar, int sourceUid, int sourceGid, int callerUid, int callerGid) throws Exception {
        DockerPolicy.token(token); this.source = DurableJournal.safePath(source.toString());
        Path journal = DurableJournal.safePath(journalDirectory.toString());
        if (source.startsWith(journal) || journal.startsWith(source)) throw DockerPolicy.failure();
        Path corePath = DurableJournal.safePath(coreJar.toString()), adapterPath = DurableJournal.safePath(adapterJar.toString());
        if (corePath.equals(adapterPath) || corePath.startsWith(source) || adapterPath.startsWith(source)
                || corePath.startsWith(journal) || adapterPath.startsWith(journal)) throw DockerPolicy.failure();
        sourceFd = openSource(this.source);
        int p = -1, dir = -1;
        try {
            sourceIdentity = Linux.stat(sourceFd);
            if (!VolumeSnapshot.directory(sourceIdentity) || sourceIdentity.uid() != Integer.toUnsignedLong(sourceUid)
                    || sourceIdentity.gid() != Integer.toUnsignedLong(sourceGid) || (sourceIdentity.mode() & 07777) != 0700) throw DockerPolicy.failure();
            p = Linux.openDir(journal.toString(), true, callerUid); Linux.Stat info = Linux.stat(p);
            if (info.gid() != Integer.toUnsignedLong(callerGid)) throw DockerPolicy.failure();
            String name = "stargate-import-" + token + "-inputs";
            Linux.mkdir(p, name); dir = Linux.openAt(p, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            Linux.Stat made = Linux.stat(dir);
            if (made.uid() != Integer.toUnsignedLong(callerUid) || made.gid() != Integer.toUnsignedLong(callerGid) || (made.mode() & 07777) != 0700) throw DockerPolicy.failure();
            directory = journal.resolve(name); core = directory.resolve("core.jar"); adapter = directory.resolve("adapter.jar");
            coreSha = snapshot(coreJar, dir, "core.jar", callerUid); adapterSha = snapshot(adapterJar, dir, "adapter.jar", callerUid);
            coreIdentity = statSnapshot(dir, "core.jar", callerUid, callerGid); adapterIdentity = statSnapshot(dir, "adapter.jar", callerUid, callerGid);
            Linux.sync(dir); Linux.sync(p); parentIdentity = Linux.stat(p); directoryIdentity = Linux.stat(dir); parent = p; snapshots = dir;
            check();
        } catch (Exception e) {
            if (dir >= 0) try { Linux.close(dir); } catch (Exception close) { e.addSuppressed(close); }
            if (p >= 0) try { Linux.close(p); } catch (Exception close) { e.addSuppressed(close); }
            try { Linux.close(sourceFd); } catch (Exception close) { e.addSuppressed(close); }
            throw e;
        }
    }
    private static int openSource(Path source) throws IOException {
        if (source.getFileName() == null) throw DockerPolicy.failure();
        int parent = Linux.openDir(source.getParent().toString(), false, Linux.uid("geteuid"));
        try { return Linux.openAt(parent, source.getFileName().toString(), O_PATH | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0); }
        finally { Linux.close(parent); }
    }
    static String snapshot(Path path, int dir, String name, int uid) throws Exception {
        Path input = DurableJournal.safePath(path.toString()); int in = Linux.openRegular(input, MAX_JAR, false, uid);
        try {
            Linux.Stat before = Linux.stat(in); int out = Linux.openAt(dir, name, Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
            try {
                MessageDigest digest = MessageDigest.getInstance("SHA-256"); byte[] buffer = new byte[65536]; long bytes = 0;
                try (InputStream source = Files.newInputStream(Linux.fdPath(in)); OutputStream target = Files.newOutputStream(Linux.fdPath(out), StandardOpenOption.WRITE)) {
                    int n; while ((n = source.read(buffer)) != -1) { bytes += n; if (bytes > MAX_JAR) throw DockerPolicy.failure(); digest.update(buffer, 0, n); target.write(buffer, 0, n); }
                }
                if (!before.equals(Linux.stat(in)) || bytes != before.size()) throw DockerPolicy.failure();
                Linux.chmod(out, 0444); Linux.sync(out); return HexFormat.of().formatHex(digest.digest());
            } finally { Linux.close(out); }
        } finally { Linux.close(in); }
    }
    static Linux.Stat statSnapshot(int parent, String name, int uid, int gid) throws IOException {
        int fd = Linux.openAt(parent, name, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
        try {
            Linux.Stat s = Linux.stat(fd);
            if (!VolumeSnapshot.regular(s) || s.links() != 1 || s.size() > MAX_JAR || s.uid() != Integer.toUnsignedLong(uid)
                    || s.gid() != Integer.toUnsignedLong(gid) || (s.mode() & 07777) != 0444) throw DockerPolicy.failure();
            return s;
        } finally { Linux.close(fd); }
    }
    public void check() throws Exception {
        if (!sourceIdentity.equals(Linux.stat(sourceFd))) throw DockerPolicy.failure();
        int reopened = openSource(source);
        try { if (!sourceIdentity.equals(Linux.stat(reopened))) throw DockerPolicy.failure(); } finally { Linux.close(reopened); }
        int reopenedParent = Linux.openDir(directory.getParent().toString(), true, (int) parentIdentity.uid());
        try {
            if (!parentIdentity.equals(Linux.stat(reopenedParent))) throw DockerPolicy.failure();
            int reopenedDirectory = Linux.openAt(reopenedParent, directory.getFileName().toString(), Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try { if (!directoryIdentity.equals(Linux.stat(reopenedDirectory))) throw DockerPolicy.failure(); }
            finally { Linux.close(reopenedDirectory); }
        } finally { Linux.close(reopenedParent); }
        if (!coreIdentity.equals(statSnapshot(snapshots, "core.jar", (int) coreIdentity.uid(), (int) coreIdentity.gid()))
                || !adapterIdentity.equals(statSnapshot(snapshots, "adapter.jar", (int) adapterIdentity.uid(), (int) adapterIdentity.gid()))) throw DockerPolicy.failure();
    }
    Map<String,String> hashes() { return Map.of("core.jar", coreSha, "adapter.jar", adapterSha); }
    public void close() throws IOException {
        IOException failure = null;
        for (int fd : new int[]{snapshots, parent, sourceFd}) try { Linux.close(fd); } catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        if (failure != null) throw failure;
    }
}
