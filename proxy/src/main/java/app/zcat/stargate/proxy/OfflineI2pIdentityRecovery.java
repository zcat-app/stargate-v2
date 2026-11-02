// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.NamedParameterSpec;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

/** Operator-attested, stopped Compose staging only. Never starts a service. */
public final class OfflineI2pIdentityRecovery {
    static final String MARKER = "identity-recovery-incomplete";
    static final String PREPARING = "identity-recovery-preparing";
    private static final byte[] CERT = {5, 0, 4, 0, 7, 0, 0};
    private static final byte[] PUB_PREFIX = HexFormat.of().parseHex("302a300506032b6570032100");
    private static final byte[] CHALLENGE = "Stargate offline I2P identity validation v1".getBytes(StandardCharsets.US_ASCII);
    private static final Set<java.nio.file.attribute.PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<java.nio.file.attribute.PosixFilePermission> DIR = PosixFilePermissions.fromString("rwx------");
    private static final String USAGE = "Requires --staged-app DIR --staged-i2p-data DIR --staged-i2p-control DIR "
            + "--old-device ID --new-device ID --expected-b32-file FILE "
            + "--ack-authorized-fresh-pair --ack-all-copies-and-services-offline";
    private OfflineI2pIdentityRecovery() {}

    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }
    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length != 14 || !args[0].equals("--staged-app") || !args[2].equals("--staged-i2p-data")
                || !args[4].equals("--staged-i2p-control") || !args[6].equals("--old-device")
                || !args[8].equals("--new-device") || !args[10].equals("--expected-b32-file")
                || !args[12].equals("--ack-authorized-fresh-pair")
                || !args[13].equals("--ack-all-copies-and-services-offline")) {
            err.println(USAGE); return 2;
        }
        try {
            reassociate(Path.of(args[1]), Path.of(args[3]), Path.of(args[5]), args[7], args[9], Path.of(args[11]), new IO());
            out.println("I2P_IDENTITY_REASSOCIATED: staged copies remain offline; no service was started.");
            return 0;
        } catch (Exception e) {
            // Exception details, names, credentials and destination must never be logged.
            err.println("I2P_IDENTITY_RECOVERY_FAILED: keep all copies offline; inspect the staged transaction.");
            return 1;
        }
    }

    static void reassociate(Path app, Path data, Path control, String oldId, String newId, Path expected, IO io) throws Exception {
        if (!oldId.matches("[A-Za-z0-9_-]{1,64}") || !newId.matches("[A-Za-z0-9_-]{1,64}") || oldId.equals(newId)) fail();
        checkDirectory(app); checkDirectory(data); checkDirectory(control); checkPath(expected);
        if (app.startsWith(data) || data.startsWith(app) || app.startsWith(control) || control.startsWith(app)
                || data.startsWith(control) || control.startsWith(data) || Files.isSameFile(app, data)
                || Files.isSameFile(app, control) || Files.isSameFile(data, control)) fail();
        checkFile(expected, 1);
        if (Files.size(expected) > 128) fail();
        String wanted = Files.readString(expected, StandardCharsets.US_ASCII);
        if (!wanted.matches("[a-z2-7]{52}\\.b32\\.i2p\\n?")) fail();
        wanted = wanted.strip();
        Path config = app.resolve("proxy.properties"), desired = app.resolve("proxy-desired");
        checkFile(config, 1); checkFile(desired, 1);
        if (Files.size(config) > 262144 || Files.size(desired) > 32) fail();
        if (!Files.readString(desired, StandardCharsets.US_ASCII).equals("stopped\n")) fail();
        absent(app.resolve("volume-import-incomplete")); absent(app.resolve("recovery-incomplete"));
        // Only the supervisor's empty file or lifecycle's generation-only fleet is safe.
        checkFleet(control.resolve("tunnels.conf"));
        byte[] configDigest = sha(Files.readAllBytes(config));
        Properties properties = ProxyConfig.read(config);
        var profiles = ProxyConfig.profiles(properties);
        if (!"true".equals(properties.getProperty("i2p.deviceIsolation")) || profiles.containsKey(oldId) || !profiles.containsKey(newId)) fail();
        int next = number(properties.getProperty("i2p.nextPort"), 14447, 65536);
        Set<Integer> ports = new HashSet<>();
        for (String name : properties.stringPropertyNames()) {
            if (name.startsWith("profile.") && name.endsWith(".i2pPort")) {
                int port = number(properties.getProperty(name), 14447, 65535);
                if (port >= next || !ports.add(port)) fail();
            }
        }
        number(properties.getProperty("profile." + newId + ".i2pPort"), 14447, next - 1);
        String oldName = name(oldId), newName = name(newId);
        if (oldName.equals(newName)) fail();
        Path source = data.resolve(oldName), target = data.resolve(newName), marker = app.resolve(MARKER);
        Path preparing = app.resolve(PREPARING);
        boolean resume = exists(marker), preparingPresent = exists(preparing);
        String recorded = null;
        if (resume) {
            if (preparingPresent) {
                checkFile(marker, 2); checkFile(preparing, 2);
                if (!Files.isSameFile(marker, preparing)) fail();
            } else checkFile(marker, 1);
            if (Files.size(marker) > 512) fail();
            recorded = Files.readString(marker, StandardCharsets.US_ASCII);
            if (!recorded.matches("I2P-IDENTITY-1\\n" + oldName + "\\n" + newName + "\\n[a-f0-9]{64}\\n")) fail();
        }
        boolean sourcePresent = exists(source), targetPresent = exists(target);
        if ((!resume && (!sourcePresent || targetPresent)) || (resume && !sourcePresent && !targetPresent)) fail();
        if (sourcePresent && targetPresent && (!resume || !Files.isSameFile(source, target))) fail();
        int links = sourcePresent && targetPresent ? 2 : 1;
        Path key = sourcePresent ? source : target;
        checkFile(key, links);
        if (targetPresent) checkFile(target, links);
        byte[] bytes = readKey(key);
        String digest;
        byte[] fingerprint;
        try { digest = HexFormat.of().formatHex(sha(bytes)); fingerprint = validate(bytes); }
        finally { Arrays.fill(bytes, (byte) 0); }
        if (!base32(fingerprint).concat(".b32.i2p").equals(wanted)) fail();
        String plan = "I2P-IDENTITY-1\n" + oldName + "\n" + newName + "\n" + digest + "\n";
        if (resume && !plan.equals(recorded)) fail();
        if (!resume && preparingPresent) {
            // This name can only be retired for a matching, pre-publication plan.
            // An unrelated or malformed record is never adopted or removed.
            checkFile(preparing, 1);
            if (Files.size(preparing) > plan.length()) fail();
            byte[] partial = Files.readAllBytes(preparing), complete = plan.getBytes(StandardCharsets.US_ASCII);
            if (!Arrays.equals(partial, Arrays.copyOf(complete, partial.length))) fail();
        }
        // Inspect all managed device keys, including inactive ones. Reject malformed entries.
        Set<String> fingerprints = new HashSet<>();
        fingerprints.add(HexFormat.of().formatHex(fingerprint));
        try (var stream = Files.newDirectoryStream(data, "device-*.dat")) {
            int count = 0;
            for (Path other : stream) {
                String filename = other.getFileName().toString();
                if (!filename.matches("device-[a-f0-9]{64}\\.dat")) fail();
                // The temporary pair is one identity, not an additional managed key.
                if (sourcePresent && targetPresent && other.equals(target)) continue;
                if (++count > 100_000) fail();
                if (other.equals(source) || other.equals(target)) continue;
                checkFile(other, 1);
                byte[] otherBytes = readKey(other);
                try { if (!fingerprints.add(HexFormat.of().formatHex(validate(otherBytes)))) fail(); }
                finally { Arrays.fill(otherBytes, (byte) 0); }
            }
        }
        if (!MessageDigest.isEqual(configDigest, sha(Files.readAllBytes(config)))) fail();
        if (!resume) {
            if (preparingPresent) { io.delete(preparing); io.forceDirectory(app); }
            io.forceFile(source);
            publishPlan(marker, preparing, plan, io);
        } else {
            // A previous attempt may have failed while syncing or publishing the gate.
            io.forceFile(marker);
            io.forceDirectory(app);
            if (preparingPresent) { io.delete(preparing); io.forceDirectory(app); }
            checkFile(marker, 1);
        }
        if (!targetPresent) {
            io.link(target, source); // createLink fails if target exists; never overwrites.
        }
        checkFile(target, sourcePresent ? 2 : 1);
        if (!MessageDigest.isEqual(sha(readKey(target)), HexFormat.of().parseHex(digest))) fail();
        if (sourcePresent) {
            if (!Files.isSameFile(source, target)) fail();
            // A prior interrupted attempt may have linked the target without syncing it.
            // Make target publication durable before retiring the last old name.
            io.forceDirectory(data);
            io.delete(source);
            io.forceDirectory(data);
        } else {
            // This also makes a previously interrupted source removal durable.
            io.forceDirectory(data);
        }
        absent(app.resolve("volume-import-incomplete")); absent(source); checkFleet(control.resolve("tunnels.conf"));
        checkFile(target, 1);
        if (!MessageDigest.isEqual(sha(readKey(target)), HexFormat.of().parseHex(digest))) fail();
        // Validate that no relevant app state changed during the transaction.
        if (!MessageDigest.isEqual(configDigest, sha(Files.readAllBytes(config)))
                || !Files.readString(desired, StandardCharsets.US_ASCII).equals("stopped\n")) fail();
        checkFile(marker, 1);
        if (Files.size(marker) > 512 || !Files.readString(marker, StandardCharsets.US_ASCII).equals(plan)) fail();
        try {
            io.delete(marker); io.forceDirectory(app);
        } catch (IOException failure) {
            try { if (!exists(marker)) publishPlan(marker, preparing, plan, io); }
            catch (IOException restore) { failure.addSuppressed(restore); }
            throw failure;
        }
    }

    // Publish only a completely written and synced plan. Both names gate startup.
    private static void publishPlan(Path marker, Path preparing, String plan, IO io) throws IOException {
        byte[] content = plan.getBytes(StandardCharsets.US_ASCII);
        io.createPreparing(preparing, content);
        checkFile(preparing, 1);
        if (Files.size(preparing) != content.length || !MessageDigest.isEqual(Files.readAllBytes(preparing), content)) fail();
        io.publishMarker(marker, preparing); // hard-link creation never replaces an existing gate
        io.forceDirectory(marker.getParent());
        io.delete(preparing);
        io.forceDirectory(marker.getParent());
        checkFile(marker, 1);
    }

    private static int number(String value, int min, int max) throws IOException {
        if (value == null || !value.matches("[0-9]{1,5}")) { fail(); return 0; }
        int n = Integer.parseInt(value); if (n < min || n > max) fail(); return n;
    }
    private static String name(String id) throws Exception { return "device-" + HexFormat.of().formatHex(sha(id.getBytes(StandardCharsets.US_ASCII))) + ".dat"; }
    private static byte[] readKey(Path file) throws IOException { if (Files.size(file) != 679) fail(); return Files.readAllBytes(file); }
    private static byte[] destinationFingerprint(byte[] bytes) throws Exception {
        if (bytes.length != 679 || !Arrays.equals(Arrays.copyOfRange(bytes, 384, 391), CERT)) fail();
        return sha(Arrays.copyOf(bytes, 391));
    }
    static byte[] validate(byte[] bytes) throws Exception {
        byte[] fingerprint = destinationFingerprint(bytes), seed = Arrays.copyOfRange(bytes, 647, 679);
        try {
            boolean zero = true; for (byte b : seed) zero &= b == 0; if (zero) fail();
            var factory = KeyFactory.getInstance("Ed25519");
            var privateKey = factory.generatePrivate(new EdECPrivateKeySpec(NamedParameterSpec.ED25519, seed));
            byte[] encoded = Arrays.copyOf(PUB_PREFIX, PUB_PREFIX.length + 32);
            System.arraycopy(bytes, 352, encoded, PUB_PREFIX.length, 32);
            var publicKey = factory.generatePublic(new X509EncodedKeySpec(encoded));
            Signature sig = Signature.getInstance("Ed25519"); sig.initSign(privateKey); sig.update(CHALLENGE); byte[] signed = sig.sign();
            sig.initVerify(publicKey); sig.update(CHALLENGE); if (!sig.verify(signed)) fail();
            return fingerprint;
        } finally { Arrays.fill(seed, (byte) 0); }
    }
    private static byte[] sha(byte[] b) throws Exception { return MessageDigest.getInstance("SHA-256").digest(b); }
    private static String base32(byte[] input) {
        String alphabet = "abcdefghijklmnopqrstuvwxyz234567"; StringBuilder out = new StringBuilder(); int bits = 0, buffer = 0;
        for (byte b : input) { buffer = (buffer << 8) | (b & 255); bits += 8; while (bits >= 5) { bits -= 5; out.append(alphabet.charAt((buffer >>> bits) & 31)); } }
        if (bits > 0) out.append(alphabet.charAt((buffer << (5 - bits)) & 31)); return out.toString();
    }
    private static void checkPath(Path p) throws IOException {
        if (!p.isAbsolute() || !p.normalize().equals(p)) fail();
        for (Path x = p; x != null; x = x.getParent()) if (Files.isSymbolicLink(x)) fail();
    }
    // The shipped jlink image has no jdk.security.auth module. Linux procfs gives
    // real/effective IDs without an extra module; set-id and root runs fail closed.
    private static long[] callerIds() throws IOException {
        if (!"Linux".equals(System.getProperty("os.name"))) { fail(); }
        long[] ids = new long[2]; boolean uid = false, gid = false;
        for (String line : Files.readAllLines(Path.of("/proc/self/status"), StandardCharsets.US_ASCII)) {
            if (line.startsWith("Uid:") || line.startsWith("Gid:")) {
                String[] values = line.substring(4).trim().split("\\s+");
                if (values.length != 4) fail();
                long real = Long.parseLong(values[0]), effective = Long.parseLong(values[1]);
                if (real != effective || real != Long.parseLong(values[2])
                        || real != Long.parseLong(values[3]) || real == 0) fail();
                if (line.startsWith("Uid:")) { ids[0] = real; uid = true; }
                else { ids[1] = real; gid = true; }
            }
        }
        if (!uid || !gid) fail(); return ids;
    }
    private static void checkDirectory(Path p) throws IOException {
        checkPath(p);
        long[] ids = callerIds();
        if (!Files.isDirectory(p, LinkOption.NOFOLLOW_LINKS) || !Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS).equals(DIR)
                || ((Number) Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[0]
                || ((Number) Files.getAttribute(p, "unix:gid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[1]) fail();
    }
    private static void checkFile(Path p, int links) throws IOException {
        long[] ids = callerIds();
        if (!Files.isRegularFile(p, LinkOption.NOFOLLOW_LINKS) || !Files.getPosixFilePermissions(p, LinkOption.NOFOLLOW_LINKS).equals(FILE)
                || ((Number) Files.getAttribute(p, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[0]
                || ((Number) Files.getAttribute(p, "unix:gid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[1]
                || ((Number) Files.getAttribute(p, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).intValue() != links) fail();
    }
    private static boolean exists(Path p) throws IOException {
        try { Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); return true; }
        catch (NoSuchFileException e) { return false; }
    }
    private static void checkFleet(Path path) throws IOException {
        if (!exists(path)) return;
        checkFile(path, 1);
        if (Files.size(path) > 128) fail();
        String fleet = Files.readString(path, StandardCharsets.US_ASCII);
        if (!fleet.isEmpty() && !fleet.matches("\\[stargate-lifecycle\\]\\ngeneration=[a-f0-9]{32}\\n\\n")) fail();
    }
    private static void absent(Path p) throws IOException { if (exists(p)) fail(); }
    private static void fail() throws IOException { throw new IOException("INVALID_OFFLINE_IDENTITY_STATE"); }

    static class IO {
        void createPreparing(Path p, byte[] bytes) throws IOException {
            try (var channel = FileChannel.open(p, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
                    PosixFilePermissions.asFileAttribute(FILE))) {
                ByteBuffer data = ByteBuffer.wrap(bytes); while (data.hasRemaining()) channel.write(data); channel.force(true);
            }
        }
        void publishMarker(Path marker, Path preparing) throws IOException { Files.createLink(marker, preparing); }
        void forceFile(Path p) throws IOException { try (var c = FileChannel.open(p, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) { c.force(true); } }
        void link(Path target, Path source) throws IOException { Files.createLink(target, source); }
        void delete(Path p) throws IOException { Files.delete(p); }
        void forceDirectory(Path p) throws IOException { try (var c = FileChannel.open(p, StandardOpenOption.READ)) { c.force(true); } }
    }
}
