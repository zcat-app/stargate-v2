// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Descriptor-relative creation of bounded canonical USTAR from a stopped source set. */
final class ArchiveWriter {
    private static final int BLOCK = 65536;
    interface Faults { void at(String phase, String path) throws Exception; }
    static Faults faults = (phase, path) -> {};
    private final FileChannel output;
    private final MessageDigest digest;
    private final int uid, gid;
    private final Set<Identity> identities = new HashSet<>();
    private long budget = 10240, position;
    private int count;
    private record Identity(long major, long minor, long inode) {}
    private ArchiveWriter(FileChannel output, int uid, int gid) throws Exception {
        this.output = output; this.uid = uid; this.gid = gid; digest = MessageDigest.getInstance("SHA-256");
    }
    static byte[] write(int source, FileChannel target, boolean nym) throws Exception {
        return write(source, target, nym, Linux.uid("geteuid"), Linux.uid("getegid"));
    }
    // Explicit IDs allow synthetic ownership-boundary tests without changing real ownership.
    static byte[] write(int source, FileChannel target, boolean nym, int uid, int gid) throws Exception {
        ArchiveWriter writer = new ArchiveWriter(target, uid, gid); target.truncate(0); target.position(0);
        Set<String> roots = nym ? ArchiveInspector.ALL : ArchiveInspector.BASE;
        Linux.Stat before = Linux.stat(source);
        if (!Set.copyOf(VolumeSnapshot.names(source)).equals(roots)) throw new IOException("Unexpected source roots");
        for (String root : roots.stream().sorted().toList()) writer.visit(source, root, root, 1);
        if (!before.equals(Linux.stat(source))) throw new IOException("Source changed");
        writer.writeBytes(new byte[1024], 1024);
        int padding = (int) ((10240 - writer.position % 10240) % 10240);
        writer.writeBytes(new byte[padding], padding);
        if (writer.position > ArchiveInspector.MAX_ARCHIVE) throw new IOException("Archive limit exceeded");
        target.force(true); target.position(0); return writer.digest.digest();
    }
    private void visit(int parent, String leaf, String path, int depth) throws Exception {
        interrupted();
        if (++count > 100_000 || depth > 32 || path.getBytes(StandardCharsets.UTF_8).length > 255
                || path.indexOf('\\') >= 0 || path.startsWith("/") || path.codePoints().anyMatch(c -> c < 32 || c == 127)) throw new IOException("Unsupported source path");
        for (String part : path.split("/", -1)) if (part.isEmpty() || part.equals(".") || part.equals("..")) throw new IOException("Unsupported source path");
        int fd = Linux.openAt(parent, leaf, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
        try {
            Linux.Stat info = Linux.stat(fd); boolean directory = VolumeSnapshot.directory(info);
            if ((!directory && (!VolumeSnapshot.regular(info) || info.links() != 1)) || (depth == 1 && !directory)) throw new IOException("Unsupported source type");
            if (depth == 1 && (info.uid() != Integer.toUnsignedLong(uid) || info.gid() != Integer.toUnsignedLong(gid)
                    || (info.mode() & 07777) != 0700)) throw new IOException("Private caller-owned source roots required");
            if (!identities.add(new Identity(info.devMajor(), info.devMinor(), info.inode()))) throw new IOException("Repeated source inode");
            long length = directory ? 0 : info.size();
            if (length < 0 || length > ArchiveInspector.MAX_FILE || (info.mode() & 07000) != 0
                    || info.uid() > 07777777L || info.gid() > 07777777L || info.mtimeSec() < 0 || info.mtimeSec() > 077777777777L) throw new IOException("Unsupported source metadata");
            budget += 512 + ((length + 511) / 512) * 512;
            if (budget > ArchiveInspector.MAX_ARCHIVE) throw new IOException("Archive limit exceeded");
            writeBytes(header(path, info, directory, length), 512);
            if (directory) {
                for (String name : VolumeSnapshot.names(fd)) visit(fd, name, path + "/" + name, depth + 1);
            } else {
                faults.at("before-read", path);
                long remaining = length; byte[] bytes = new byte[BLOCK];
                try (InputStream in = Files.newInputStream(Linux.fdPath(fd))) {
                    while (remaining > 0) {
                        interrupted(); int n = in.read(bytes, 0, (int) Math.min(bytes.length, remaining));
                        if (n <= 0) throw new IOException("Source truncated");
                        writeBytes(bytes, n); remaining -= n;
                    }
                    if (in.read() != -1) throw new IOException("Source grew");
                }
                int padding = (int) ((512 - length % 512) % 512); writeBytes(new byte[padding], padding);
            }
            if (!info.equals(Linux.stat(fd))) throw new IOException("Source changed");
        } finally { Linux.close(fd); }
    }
    private void writeBytes(byte[] bytes, int size) throws IOException {
        digest.update(bytes, 0, size); ByteBuffer buffer = ByteBuffer.wrap(bytes, 0, size);
        while (buffer.hasRemaining()) if (output.write(buffer) <= 0) throw new IOException("Short archive write");
        position += size;
    }
    private static byte[] header(String path, Linux.Stat info, boolean directory, long size) throws IOException {
        String full = path + (directory ? "/" : ""), prefix = "", leaf = full;
        if (utf8(full).length > 100) {
            boolean found = false;
            for (int i = full.indexOf('/'); i >= 0; i = full.indexOf('/', i + 1)) {
                String p = full.substring(0, i), l = full.substring(i + 1);
                if (utf8(p).length <= 155 && utf8(l).length <= 100) { prefix = p; leaf = l; found = true; break; }
            }
            if (!found) throw new IOException("Name cannot be represented in USTAR");
        }
        byte[] h = new byte[512]; put(h, 0, 100, utf8(leaf)); put(h, 345, 155, utf8(prefix));
        number(h, 100, 8, info.mode() & 07777); number(h, 108, 8, info.uid()); number(h, 116, 8, info.gid());
        number(h, 124, 12, size); number(h, 136, 12, info.mtimeSec());
        Arrays.fill(h, 148, 156, (byte) ' '); h[156] = (byte) (directory ? '5' : '0');
        put(h, 257, 8, new byte[]{'u','s','t','a','r',0,'0','0'});
        long checksum = 0; for (byte b : h) checksum += b & 255;
        put(h, 148, 6, String.format(java.util.Locale.ROOT, "%06o", checksum).getBytes(StandardCharsets.US_ASCII)); h[154] = 0;
        return h;
    }
    private static byte[] utf8(String value) { return value.getBytes(StandardCharsets.UTF_8); }
    private static void put(byte[] target, int offset, int max, byte[] value) throws IOException {
        if (value.length > max) throw new IOException("USTAR field too long"); System.arraycopy(value, 0, target, offset, value.length);
    }
    private static void number(byte[] target, int offset, int length, long value) throws IOException {
        String number = Long.toOctalString(value); if (value < 0 || number.length() > length - 1) throw new IOException("USTAR number overflow");
        Arrays.fill(target, offset, offset + length - 1, (byte) '0');
        put(target, offset + length - 1 - number.length(), number.length(), number.getBytes(StandardCharsets.US_ASCII));
    }
    private static void interrupted() throws InterruptedException { if (Thread.currentThread().isInterrupted()) throw new InterruptedException(); }
}
