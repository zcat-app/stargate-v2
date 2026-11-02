// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.LinkedHashMap;
import java.util.Map;

/** A private no-replace journal: each intent is durable before its Docker action. */
final class DurableJournal implements AutoCloseable {
    private final int parent, fd;
    final Path path;
    private int bytes;
    DurableJournal(Path directory, String prefix, String token, int uid, int gid) throws IOException {
        DockerPolicy.token(token);
        if (!prefix.equals("stargate-import-") && !prefix.equals("stargate-capture-")) throw DockerPolicy.failure();
        Path normalized = safePath(directory.toString()); parent = Linux.openDir(normalized.toString(), true, uid);
        int handle = -1;
        try {
            Linux.Stat d = Linux.stat(parent);
            if (d.gid() != Integer.toUnsignedLong(gid)) throw DockerPolicy.failure();
            String name = prefix + token + ".jsonl"; path = normalized.resolve(name);
            handle = Linux.openAt(parent, name, Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
            Linux.Stat s = Linux.stat(handle);
            if (!VolumeSnapshot.regular(s) || s.uid() != Integer.toUnsignedLong(uid) || s.gid() != Integer.toUnsignedLong(gid) || s.links() != 1) throw DockerPolicy.failure();
            Linux.chmod(handle, 0600); Linux.sync(handle); Linux.sync(parent); fd = handle;
        } catch (IOException e) {
            if (handle >= 0) try { Linux.close(handle); } catch (IOException close) { e.addSuppressed(close); }
            try { Linux.close(parent); } catch (IOException close) { e.addSuppressed(close); }
            throw e;
        }
    }
    void record(String event, Map<String, ?> values) throws IOException {
        if (event == null || !event.matches("[a-z_]{1,64}") || values.containsKey("event")) throw DockerPolicy.failure();
        Map<String,Object> record = new LinkedHashMap<>(); record.put("event", event); record.putAll(values);
        byte[] data = (DockerPolicy.json(record) + "\n").getBytes(StandardCharsets.UTF_8);
        if (bytes + data.length > 65536) throw new IOException("Journal limit exceeded");
        try (OutputStream out = Files.newOutputStream(Linux.fdPath(fd), StandardOpenOption.WRITE, StandardOpenOption.APPEND)) { out.write(data); }
        Linux.sync(fd); bytes += data.length;
    }
    public void close() throws IOException {
        IOException failure = null;
        try { Linux.close(fd); } catch (IOException e) { failure = e; }
        try { Linux.close(parent); } catch (IOException e) { if (failure == null) failure = e; else failure.addSuppressed(e); }
        if (failure != null) throw failure;
    }
    static Path safePath(String value) throws IOException {
        if (value.indexOf(',') >= 0 || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) throw DockerPolicy.failure();
        return Linux.absolute(value);
    }
}
