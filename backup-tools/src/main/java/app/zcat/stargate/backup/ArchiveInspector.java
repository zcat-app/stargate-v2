// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.EOFException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Validates an already authenticated, stable USTAR stream without extracting it. */
public final class ArchiveInspector {
    static final long MAX_ARCHIVE = 8L * 1024 * 1024 * 1024;
    static final long MAX_FILE = 2L * 1024 * 1024 * 1024;
    static final int MAX_ENTRIES = 100_000, MAX_DEPTH = 32;
    static final Set<String> BASE = Set.of("app-data", "tor-data", "tor-control", "i2p-data", "i2p-control");
    static final Set<String> ALL = Set.of("app-data", "tor-data", "tor-control", "i2p-data", "i2p-control", "nym-data", "nym-secrets");
    private ArchiveInspector() {}

    public record Summary(int entries, long payloadBytes, boolean nym) {}
    /** When staging, ownership is checked against these caller IDs. */
    public record StagingOwner(long uid, long gid) {}

    /** Caller must hold a stable, fully authenticated file; this method does not authenticate data. */
    public static Summary inspect(SeekableByteChannel input, StagingOwner staging) throws IOException {
        long size = input.size();
        if (size > MAX_ARCHIVE || size % 512 != 0) throw invalid();
        input.position(0);
        Set<String> seen = new HashSet<>(), dirs = new HashSet<>(), roots = new HashSet<>();
        long payload = 0;
        byte[] header = new byte[512], buffer = new byte[65536];
        while (true) {
            readFully(input, header, 512);
            if (zero(header, 0, 512)) {
                readFully(input, header, 512);
                if (!zero(header, 0, 512)) throw invalid();
                int n;
                while ((n = input.read(ByteBuffer.wrap(buffer))) != -1) {
                    if (n == 0 || !zero(buffer, 0, n)) throw invalid();
                }
                break;
            }
            if (seen.size() >= MAX_ENTRIES) throw invalid();
            Entry e = parse(header);
            String name = e.name;
            String[] parts = name.split("/", -1);
            if (name.isEmpty() || name.startsWith("/") || name.indexOf('\\') >= 0 || parts.length > MAX_DEPTH
                    || name.getBytes(StandardCharsets.UTF_8).length > 255 || !ALL.contains(parts[0]) || seen.contains(name)) throw invalid();
            for (String part : parts) if (part.isEmpty() || part.equals(".") || part.equals("..")) throw invalid();
            if (name.codePoints().anyMatch(c -> c < 32 || c == 127)) throw invalid();
            if ((e.mode & ~0777L) != 0 || e.uid > 07777777L || e.gid > 07777777L) throw invalid();
            if (staging != null) {
                if (name.equals("app-data/volume-import-incomplete") || e.uid != staging.uid || e.gid != staging.gid
                        || (e.directory && (e.mode & 0700) != 0700) || (parts.length == 1 && e.mode != 0700)
                        || (!e.directory && (e.mode & 0400) == 0)
                        || (name.equals("app-data/recovery-incomplete") && (e.directory || e.mode != 0600))) throw invalid();
            }
            if (parts.length == 1) {
                if (!e.directory) throw invalid();
                roots.add(name);
            } else if (!dirs.contains(name.substring(0, name.lastIndexOf('/')))) throw invalid();
            if (e.size > MAX_FILE || (e.directory && e.size != 0)) throw invalid();
            seen.add(name);
            if (e.directory) dirs.add(name);
            long remaining = e.size;
            while (remaining > 0) {
                int amount = (int) Math.min(remaining, buffer.length);
                readFully(input, buffer, amount); remaining -= amount;
            }
            int padding = (int) ((512 - e.size % 512) % 512);
            readFully(input, buffer, padding);
            if (!zero(buffer, 0, padding)) throw invalid();
            payload += e.size;
        }
        if (!roots.equals(BASE) && !roots.equals(ALL)) throw invalid();
        return new Summary(seen.size(), payload, roots.equals(ALL));
    }

    private record Entry(String name, long mode, long uid, long gid, long size, long mtime, boolean directory) {}
    private static Entry parse(byte[] h) throws IOException {
        if (h[156] != '0' && h[156] != '5') throw invalid();
        boolean dir = h[156] == '5';
        String leaf = field(h, 0, 100), prefix = field(h, 345, 155);
        if (dir) while (leaf.endsWith("/")) leaf = leaf.substring(0, leaf.length() - 1);
        String name = prefix.isEmpty() ? leaf : prefix + "/" + leaf;
        Entry e = new Entry(name, number(h, 100, 8), number(h, 108, 8), number(h, 116, 8),
                number(h, 124, 12), number(h, 136, 12), dir);
        if (!Arrays.equals(h, canonical(e))) throw invalid();
        return e;
    }
    private static byte[] canonical(Entry e) throws IOException {
        byte[] h = new byte[512];
        String name = e.name + (e.directory ? "/" : ""), leaf = name, prefix = "";
        if (utf8(name).length > 100) {
            boolean found = false;
            for (int i = name.indexOf('/'); i >= 0; i = name.indexOf('/', i + 1)) {
                String p = name.substring(0, i), l = name.substring(i + 1);
                if (utf8(p).length <= 155 && utf8(l).length <= 100) { prefix = p; leaf = l; found = true; break; }
            }
            if (!found) throw invalid();
        }
        put(h, 0, 100, utf8(leaf)); put(h, 345, 155, utf8(prefix));
        octal(h, 100, 8, e.mode); octal(h, 108, 8, e.uid); octal(h, 116, 8, e.gid);
        octal(h, 124, 12, e.size); octal(h, 136, 12, e.mtime);
        Arrays.fill(h, 148, 156, (byte) ' '); h[156] = (byte) (e.directory ? '5' : '0');
        put(h, 257, 8, new byte[]{'u','s','t','a','r',0,'0','0'});
        long checksum = 0; for (byte b : h) checksum += b & 255;
        String sum = String.format(java.util.Locale.ROOT, "%06o", checksum);
        put(h, 148, 6, sum.getBytes(StandardCharsets.US_ASCII)); h[154] = 0;
        return h;
    }
    private static String field(byte[] h, int off, int length) throws IOException {
        int end = off; while (end < off + length && h[end] != 0) end++;
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(h, off, end - off)).toString(); }
        catch (CharacterCodingException ex) { throw invalid(); }
    }
    private static long number(byte[] h, int off, int length) throws IOException {
        long n = 0;
        for (int i = off; i < off + length - 1; i++) {
            if (h[i] < '0' || h[i] > '7') throw invalid();
            n = n * 8 + h[i] - '0';
        }
        if (h[off + length - 1] != 0) throw invalid();
        return n;
    }
    private static void octal(byte[] h, int off, int len, long n) throws IOException {
        String value = Long.toOctalString(n);
        if (n < 0 || value.length() > len - 1) throw invalid();
        Arrays.fill(h, off, off + len - 1, (byte) '0');
        put(h, off + len - 1 - value.length(), value.length(), value.getBytes(StandardCharsets.US_ASCII));
    }
    private static byte[] utf8(String s) { return s.getBytes(StandardCharsets.UTF_8); }
    private static void put(byte[] target, int offset, int limit, byte[] value) throws IOException {
        if (value.length > limit) throw invalid();
        System.arraycopy(value, 0, target, offset, value.length);
    }
    private static void readFully(SeekableByteChannel in, byte[] data, int n) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(data, 0, n);
        while (b.hasRemaining()) { int read = in.read(b); if (read < 0) throw new EOFException("Invalid archive"); if (read == 0) throw invalid(); }
    }
    private static boolean zero(byte[] b, int from, int length) {
        for (int i = from; i < from + length; i++) if (b[i] != 0) return false;
        return true;
    }
    private static IOException invalid() { return new IOException("Invalid archive"); }
}
