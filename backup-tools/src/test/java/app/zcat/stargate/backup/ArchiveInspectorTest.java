// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.SeekableByteChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;

class ArchiveInspectorTest {
    @TempDir Path temp;
    record Member(String name, char type, int mode, int uid, int gid, byte[] data) {}
    private static Member dir(String name) { return new Member(name, '5', 0700, 10001, 10001, new byte[0]); }
    static Member file(String name, String data) { return new Member(name, '0', 0600, 10001, 10001, data.getBytes(StandardCharsets.UTF_8)); }
    static List<Member> roots() {
        return new ArrayList<>(List.of(dir("app-data"), dir("i2p-control"), dir("i2p-data"), dir("tor-control"), dir("tor-data")));
    }
    // Independent fixture writer for a restricted canonical USTAR header.
    static byte[] archive(List<Member> members) throws IOException {
        var out = new ByteArrayOutputStream();
        for (Member m : members) {
            byte[] h = new byte[512];
            String full = m.name + (m.type == '5' ? "/" : "");
            byte[] name = full.getBytes(StandardCharsets.UTF_8);
            if (name.length > 100) {
                int split = full.indexOf('/');
                while (split >= 0 && full.substring(split + 1).getBytes(StandardCharsets.UTF_8).length > 100)
                    split = full.indexOf('/', split + 1);
                if (split < 0) throw new IllegalArgumentException("Unrepresentable fixture");
                byte[] prefix = full.substring(0, split).getBytes(StandardCharsets.UTF_8);
                System.arraycopy(prefix, 0, h, 345, prefix.length);
                name = full.substring(split + 1).getBytes(StandardCharsets.UTF_8);
            }
            System.arraycopy(name, 0, h, 0, name.length);
            num(h, 100, 8, m.mode); num(h, 108, 8, m.uid); num(h, 116, 8, m.gid);
            num(h, 124, 12, m.data.length); num(h, 136, 12, 12345);
            Arrays.fill(h, 148, 156, (byte) ' '); h[156] = (byte) m.type;
            System.arraycopy(new byte[]{'u','s','t','a','r',0,'0','0'}, 0, h, 257, 8);
            checksum(h); out.write(h); out.write(m.data);
            out.write(new byte[(512 - m.data.length % 512) % 512]);
        }
        out.write(new byte[1024]); return out.toByteArray();
    }
    private static void num(byte[] h, int off, int len, long value) {
        byte[] b = String.format(java.util.Locale.ROOT, "%0" + (len - 1) + "o", value).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(b, 0, h, off, b.length);
    }
    private static void checksum(byte[] h) {
        Arrays.fill(h, 148, 156, (byte) ' ');
        int sum = 0; for (byte b : h) sum += b & 255;
        byte[] bytes = String.format(java.util.Locale.ROOT, "%06o", sum).getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(bytes, 0, h, 148, 6); h[154] = 0;
    }
    private ArchiveInspector.Summary inspect(byte[] bytes, ArchiveInspector.StagingOwner owner) throws IOException {
        Path p = Files.createTempFile(temp, "archive", ".tar"); Files.write(p, bytes);
        try (SeekableByteChannel c = Files.newByteChannel(p, StandardOpenOption.READ)) { return ArchiveInspector.inspect(c, owner); }
    }
    private void reject(byte[] bytes) { assertThrows(IOException.class, () -> inspect(bytes, null)); }
    @Test void acceptsMetadataAndPayloadWithoutExtracting() throws Exception {
        var entries = roots(); entries.add(file("app-data/config", "payload"));
        var summary = inspect(archive(entries), null);
        assertEquals(new ArchiveInspector.Summary(6, 7, false), summary);
        entries.add(dir("nym-data")); entries.add(dir("nym-secrets"));
        assertTrue(inspect(archive(entries), null).nym());
    }
    @Test void requiresCompleteRootsAndOrderedParents() throws Exception {
        var entries = roots(); entries.removeLast(); reject(archive(entries));
        entries = roots(); entries.add(dir("nym-data")); reject(archive(entries));
        entries = roots(); entries.add(file("app-data/missing/child", "")); reject(archive(entries));
        entries = roots(); entries.add(dir("app-data")); reject(archive(entries));
    }
    @Test void rejectsUnsafePathsTypesAndModes() throws Exception {
        for (String path : List.of("../escape", "/absolute", "app-data/../escape", "app-data//bad", "app-data/./bad", "app-data\\bad", "app-data/control\ncharacter")) {
            var entries = roots(); entries.add(file(path, "")); reject(archive(entries));
        }
        for (char type : new char[]{'1', '2', '3', '4', '6', 'x', 'S'}) {
            var entries = roots(); entries.add(new Member("app-data/bad", type, 0600, 10001, 10001, new byte[0])); reject(archive(entries));
        }
        var entries = roots(); entries.add(new Member("app-data/bad", '0', 04600, 10001, 10001, new byte[0])); reject(archive(entries));
    }
    @Test void rejectsCorruptionPaddingAndConcatenation() throws Exception {
        var entries = roots(); entries.add(file("app-data/config", "x")); byte[] good = archive(entries);
        byte[] corrupt = good.clone(); corrupt[0] ^= 1; reject(corrupt);
        reject(Arrays.copyOf(good, good.length - 1));
        byte[] concat = Arrays.copyOf(good, good.length * 2); System.arraycopy(good, 0, concat, good.length, good.length); reject(concat);
        byte[] padding = good.clone(); padding[6 * 512 + 1] = 1; reject(padding);
        byte[] noncanonical = good.clone(); noncanonical[265] = 'a';
        // A valid checksum cannot make a nonempty uname canonical.
        byte[] h = Arrays.copyOf(noncanonical, 512); checksum(h); System.arraycopy(h, 0, noncanonical, 0, 512); reject(noncanonical);
        byte[] missingSecondTerminator = Arrays.copyOf(good, good.length - 512); reject(missingSecondTerminator);
    }
    @Test void acceptsCanonicalLongUtf8NameAndRejectsDepthAndFileSize() throws Exception {
        var entries = roots();
        String directory = "app-data/" + "a".repeat(90);
        entries.add(dir(directory)); entries.add(file(directory + "/café", "ok"));
        assertEquals(7, inspect(archive(entries), null).entries());
        var tooDeep = roots();
        String path = "app-data";
        for (int i = 0; i < 32; i++) { path += "/d"; tooDeep.add(dir(path)); }
        reject(archive(tooDeep));
        var oneFile = roots(); oneFile.add(file("app-data/file", ""));
        byte[] tooLarge = archive(oneFile);
        byte[] header = Arrays.copyOfRange(tooLarge, 5 * 512, 6 * 512);
        num(header, 124, 12, ArchiveInspector.MAX_FILE + 1); checksum(header);
        System.arraycopy(header, 0, tooLarge, 5 * 512, 512); reject(tooLarge);
    }
    @Test void stagingEnforcesOwnershipModesAndImportGate() throws Exception {
        var owner = new ArchiveInspector.StagingOwner(10001, 10001);
        var entries = roots(); entries.add(file("app-data/recovery-incomplete", "marker"));
        assertEquals(6, inspect(archive(entries), owner).entries());
        assertThrows(IOException.class, () -> inspect(archive(entries), new ArchiveInspector.StagingOwner(10002, 10001)));
        entries.add(file("app-data/volume-import-incomplete", "marker"));
        assertThrows(IOException.class, () -> inspect(archive(entries), owner));
        var unsafe = roots(); unsafe.add(new Member("app-data/no-rwx", '5', 0600, 10001, 10001, new byte[0]));
        assertThrows(IOException.class, () -> inspect(archive(unsafe), owner));
        var badMarker = roots(); badMarker.add(new Member("app-data/recovery-incomplete", '0', 0644, 10001, 10001, new byte[0]));
        assertThrows(IOException.class, () -> inspect(archive(badMarker), owner));
    }
    @Test void verificationAcceptsButStagingRejectsImportIneligibleModes() throws Exception {
        var owner = new ArchiveInspector.StagingOwner(10001, 10001);
        for (String root : ArchiveInspector.ALL) {
            var entries = roots(); entries.add(dir("nym-data")); entries.add(dir("nym-secrets"));
            for (int i = 0; i < entries.size(); i++) if (entries.get(i).name().equals(root))
                entries.set(i, new Member(root, '5', 0755, 10001, 10001, new byte[0]));
            byte[] bytes = archive(entries);
            assertEquals(7, inspect(bytes, null).entries(), root);
            assertThrows(IOException.class, () -> inspect(bytes, owner), root);
        }
        var entries = roots(); entries.add(new Member("tor-data/write-only", '0', 0200, 10001, 10001, new byte[]{1}));
        byte[] bytes = archive(entries);
        assertEquals(6, inspect(bytes, null).entries());
        assertThrows(IOException.class, () -> inspect(bytes, owner));
    }
}
