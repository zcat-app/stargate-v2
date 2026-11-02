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

/** Second pass over a spool already authenticated and checked by ArchiveInspector. */
final class StagedTarReader implements StagedArchive.Reader {
    private final SeekableByteChannel input;
    private long remaining, size;
    private boolean active, ended;
    StagedTarReader(SeekableByteChannel input) throws IOException {
        this.input = input;
        if (input.size() > ArchiveInspector.MAX_ARCHIVE || input.size() % 512 != 0) throw invalid();
        input.position(0);
    }
    public StagedArchive.Member next() throws IOException {
        if (active || ended) throw invalid();
        byte[] header = new byte[512]; readFully(header, 512);
        if (zero(header, 512)) {
            readFully(header, 512); if (!zero(header, 512)) throw invalid();
            byte[] rest = new byte[65536]; int n;
            while ((n = input.read(ByteBuffer.wrap(rest))) != -1) if (n == 0 || !zero(rest, n)) throw invalid();
            ended = true; return null;
        }
        long expected = number(header, 148, 7); // six octal digits and NUL
        if (header[155] != ' ') throw invalid();
        long checksum = 0; for (int i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? ' ' : header[i] & 255;
        if (checksum != expected || !Arrays.equals(Arrays.copyOfRange(header, 257, 265), new byte[]{'u','s','t','a','r',0,'0','0'})) throw invalid();
        boolean directory;
        if (header[156] == '0') directory = false; else if (header[156] == '5') directory = true; else throw invalid();
        String leaf = text(header, 0, 100), prefix = text(header, 345, 155);
        if (directory) while (leaf.endsWith("/")) leaf = leaf.substring(0, leaf.length() - 1);
        String name = prefix.isEmpty() ? leaf : prefix + "/" + leaf;
        long mode = number(header, 100, 8), uid = number(header, 108, 8), gid = number(header, 116, 8);
        size = number(header, 124, 12); long mtime = number(header, 136, 12);
        remaining = size; active = true;
        return new StagedArchive.Member(name, directory, size, (int) mode, uid, gid, mtime);
    }
    public int read(byte[] buffer, int offset, int length) throws IOException {
        if (!active || remaining == 0 || length <= 0) throw invalid();
        int n = input.read(ByteBuffer.wrap(buffer, offset, (int) Math.min(length, remaining)));
        if (n <= 0) throw new EOFException("Truncated staging spool"); remaining -= n; return n;
    }
    public void finishMember() throws IOException {
        if (!active || remaining != 0) throw invalid();
        int padding = (int) ((512 - size % 512) % 512); byte[] bytes = new byte[padding];
        readFully(bytes, padding); if (!zero(bytes, padding)) throw invalid(); active = false;
    }
    private void readFully(byte[] bytes, int length) throws IOException {
        ByteBuffer b = ByteBuffer.wrap(bytes, 0, length);
        while (b.hasRemaining()) { int n = input.read(b); if (n <= 0) throw new EOFException("Truncated staging spool"); }
    }
    private static String text(byte[] bytes, int offset, int length) throws IOException {
        int end = offset; while (end < offset + length && bytes[end] != 0) end++;
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes, offset, end - offset)).toString(); }
        catch (CharacterCodingException e) { throw invalid(); }
    }
    private static long number(byte[] bytes, int offset, int length) throws IOException {
        long n = 0; for (int i = 0; i < length - 1; i++) { byte b = bytes[offset + i]; if (b < '0' || b > '7') throw invalid(); n = n * 8 + b - '0'; }
        if (bytes[offset + length - 1] != 0) throw invalid(); return n;
    }
    private static boolean zero(byte[] bytes, int length) { for (int i = 0; i < length; i++) if (bytes[i] != 0) return false; return true; }
    private static IOException invalid() { return new IOException("Invalid staging spool"); }
}
