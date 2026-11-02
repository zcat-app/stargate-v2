// Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.monitor;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.json.JsonWriteFeature;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.node.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

final class MonitorFiles {
    static final ObjectMapper JSON = new ObjectMapper(JsonFactory.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).enable(JsonWriteFeature.ESCAPE_NON_ASCII).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    static final int REPORT_LIMIT = 32 * 1024 * 1024;
    static final int UID = ((Number) attribute(Path.of("/proc/" + ProcessHandle.current().pid()), "uid")).intValue();
    static Object attribute(Path p, String name) {
        try { return Files.getAttribute(p, "unix:" + name, LinkOption.NOFOLLOW_LINKS); }
        catch (IOException e) { throw new IllegalArgumentException("metadata unavailable", e); }
    }
    static String now() { return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(); }
    static ObjectNode object() { return JSON.createObjectNode(); }
    static JsonNode canonical(JsonNode n) {
        if (n.isObject()) { var out = object(); new TreeSet<>(n.properties().stream().map(Map.Entry::getKey).toList()).forEach(k -> out.set(k, canonical(n.get(k)))); return out; }
        if (n.isArray()) { var out = JSON.createArrayNode(); n.forEach(v -> out.add(canonical(v))); return out; }
        return n;
    }
    static byte[] bytes(JsonNode n) throws IOException { return JSON.writeValueAsBytes(canonical(n)); }
    static String hash(byte[] bytes) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    static String fingerprint(JsonNode n) throws IOException { return hash(bytes(n)); }
    static Path directory(Path path, boolean privateMode) throws IOException {
        if (!path.isAbsolute() || !path.equals(path.normalize())) throw new IOException("absolute normalized directory required");
        Path current = path.getRoot();
        for (Path part : path) {
            current = current.resolve(part);
            if (!Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS)) throw new IOException("directory or symlink refused");
            int uid = ((Number)attribute(current,"uid")).intValue(), mode = ((Number)attribute(current,"mode")).intValue();
            if ((uid != 0 && uid != UID) || ((mode & 0022) != 0 && !(uid == 0 && (mode & 01000) != 0))) throw new IOException("unsafe directory owner or permissions");
        }
        if (privateMode && (((Number)attribute(path,"uid")).intValue() != UID || (((Number)attribute(path,"mode")).intValue() & 07777) != 0700)) throw new IOException("private directory required");
        return path;
    }
    static byte[] read(Path path, int limit, boolean privateFile) throws IOException {
        directory(path.getParent(), false);
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || ((Number)attribute(path,"nlink")).intValue() != 1) throw new IOException("regular single-link file required");
        int uid = ((Number)attribute(path,"uid")).intValue(), mode = ((Number)attribute(path,"mode")).intValue();
        if (privateFile ? uid!=UID || (mode&07777)!=0600 : (uid!=UID&&uid!=0)||(mode&0022)!=0) throw new IOException("unsafe file permissions");
        try (var channel = FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS)) {
            var out = java.nio.channels.Channels.newInputStream(channel).readNBytes(limit + 1);
            if (out.length > limit) throw new IOException("file exceeds existing contract");
            return out;
        }
    }
    static JsonNode json(Path path, int limit, boolean privateFile) throws IOException { return JSON.readTree(read(path, limit, privateFile)); }
    static void syncDirectory(Path directory) throws IOException { try (var c=FileChannel.open(directory, StandardOpenOption.READ)) { c.force(true); } }
    static void create(Path path, byte[] bytes) throws IOException {
        directory(path.getParent(), true);
        try (var c=FileChannel.open(path, Set.of(StandardOpenOption.WRITE,StandardOpenOption.CREATE_NEW,LinkOption.NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            var b=ByteBuffer.wrap(bytes);while(b.hasRemaining())c.write(b);c.force(true);
        }
        syncDirectory(path.getParent());
    }
    static void replace(Path path, JsonNode data) throws IOException {
        directory(path.getParent(), true);
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) read(path, REPORT_LIMIT, true);
        Path temporary=Files.createTempFile(path.getParent(),".java-monitor-",".tmp",PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        try {
            try(var c=FileChannel.open(temporary,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)) {var b=ByteBuffer.wrap(bytes(data));while(b.hasRemaining())c.write(b);c.force(true);}
            Files.move(temporary,path,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);syncDirectory(path.getParent());
        } finally {Files.deleteIfExists(temporary);}
    }
    // Keep the published inode stable for existing read-only container mounts.
    static void publish(Path path, JsonNode data) throws IOException {
        directory(path.getParent(),false);byte[] bytes=bytes(data);if(bytes.length>512)throw new IOException("public snapshot too large");
        if(Files.exists(path,LinkOption.NOFOLLOW_LINKS))read(path,512,false);
        try(var c=FileChannel.open(path,Set.of(StandardOpenOption.CREATE,StandardOpenOption.READ,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS),PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
            try(var lock=c.tryLock()) {if(lock==null)throw new IOException("snapshot busy");c.truncate(0);var b=ByteBuffer.wrap(bytes);while(b.hasRemaining())c.write(b);c.force(true);Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-r--r--"));c.force(true);}
        }
        syncDirectory(path.getParent());
    }
}
