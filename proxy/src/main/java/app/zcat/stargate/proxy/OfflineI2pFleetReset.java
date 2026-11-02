// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.Set;

/** Resets only the control fleet on exclusively held, stopped Compose staging volumes. */
public final class OfflineI2pFleetReset {
    // The other recovery commands reject this record; the supervisor rejects the name.
    static final String GATE = "identity-recovery-incomplete";
    static final byte[] PLAN = "I2P-FLEET-RESET-1\n".getBytes(StandardCharsets.US_ASCII);
    private static final Set<PosixFilePermission> FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> DIR = PosixFilePermissions.fromString("rwx------");
    private OfflineI2pFleetReset() {}

    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }
    static int run(String[] args, PrintStream out, PrintStream err) {
        if (args.length != 5 || !args[0].equals("--staged-app") || !args[2].equals("--staged-i2p-control")
                || !args[4].equals("--ack-all-copies-and-services-offline")) {
            err.println("Requires --staged-app DIR --staged-i2p-control DIR --ack-all-copies-and-services-offline"); return 2;
        }
        try {
            reset(Path.of(args[1]), Path.of(args[3]), new IO());
            out.println("I2P_FLEET_RESET: staged copies remain offline; no service was started."); return 0;
        } catch (Exception failure) {
            err.println("I2P_FLEET_RESET_FAILED: keep all copies offline; inspect the staged transaction."); return 1;
        }
    }

    static void reset(Path app, Path control, IO io) throws IOException {
        checkDirectory(app); checkDirectory(control);
        if (app.startsWith(control) || control.startsWith(app) || Files.isSameFile(app, control)) fail();
        Path desired = app.resolve("proxy-desired"), config = app.resolve("proxy.properties");
        checkFile(desired); checkFile(config);
        if (Files.size(desired) > 32 || !Files.readString(desired, StandardCharsets.US_ASCII).equals("stopped\n")) fail();
        absent(app.resolve("volume-import-incomplete")); absent(app.resolve("recovery-incomplete")); absent(app.resolve("identity-recovery-preparing"));
        Path gate = app.resolve(GATE), fleet = control.resolve("tunnels.conf");
        if (exists(fleet)) { checkFile(fleet); if (Files.size(fleet) > 131072) fail(); }
        if (exists(gate)) {
            checkPlan(gate); io.forceFile(gate); io.forceDirectory(app);
        } else {
            // A partial record is a gate, but is not automatically adopted on retry.
            io.createGate(gate); checkPlan(gate); io.forceDirectory(app);
        }
        Path temp = null;
        try {
            temp = io.createEmpty(control);
            checkFile(temp); if (Files.size(temp) != 0) fail();
            io.replace(temp, fleet); temp = null;
            io.forceDirectory(control);
            checkFile(fleet); if (Files.size(fleet) != 0) fail();
            checkFile(desired); checkFile(config);
            if (!Files.readString(desired, StandardCharsets.US_ASCII).equals("stopped\n")) fail();
            absent(app.resolve("volume-import-incomplete")); absent(app.resolve("recovery-incomplete")); absent(app.resolve("identity-recovery-preparing")); checkPlan(gate);
            try { io.delete(gate); io.forceDirectory(app); }
            catch (IOException failure) {
                try { if (!exists(gate)) { io.createGate(gate); io.forceDirectory(app); } }
                catch (IOException restore) { failure.addSuppressed(restore); }
                throw failure;
            }
        } finally {
            if (temp != null) Files.deleteIfExists(temp);
        }
    }

    private static void checkPlan(Path gate) throws IOException {
        checkFile(gate);
        if (Files.size(gate) != PLAN.length || !Arrays.equals(Files.readAllBytes(gate), PLAN)) fail();
    }
    private static void checkDirectory(Path path) throws IOException {
        if (!path.isAbsolute() || !path.normalize().equals(path)) fail();
        for (Path p = path; p != null; p = p.getParent()) if (Files.isSymbolicLink(p)) fail();
        long[] ids = callerIds();
        if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(DIR)
                || ((Number) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[0]
                || ((Number) Files.getAttribute(path, "unix:gid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[1]) fail();
    }
    private static void checkFile(Path path) throws IOException {
        long[] ids = callerIds();
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(FILE)
                || ((Number) Files.getAttribute(path, "unix:uid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[0]
                || ((Number) Files.getAttribute(path, "unix:gid", LinkOption.NOFOLLOW_LINKS)).longValue() != ids[1]
                || ((Number) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() != 1) fail();
    }
    private static long[] callerIds() throws IOException {
        if (!"Linux".equals(System.getProperty("os.name"))) fail();
        long[] ids = new long[2]; boolean uid = false, gid = false;
        for (String line : Files.readAllLines(Path.of("/proc/self/status"), StandardCharsets.US_ASCII)) {
            if (line.startsWith("Uid:") || line.startsWith("Gid:")) {
                String[] values = line.substring(4).trim().split("\\s+");
                if (values.length != 4) fail();
                long id = Long.parseLong(values[0]);
                if (id == 0 || id != Long.parseLong(values[1]) || id != Long.parseLong(values[2]) || id != Long.parseLong(values[3])) fail();
                if (line.startsWith("Uid:")) { ids[0] = id; uid = true; } else { ids[1] = id; gid = true; }
            }
        }
        if (!uid || !gid) fail(); return ids;
    }
    private static boolean exists(Path p) throws IOException {
        try { Files.readAttributes(p, java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS); return true; }
        catch (NoSuchFileException e) { return false; }
    }
    private static void absent(Path p) throws IOException { if (exists(p)) fail(); }
    private static void fail() throws IOException { throw new IOException("INVALID_OFFLINE_FLEET_STATE"); }

    static class IO {
        void createGate(Path gate) throws IOException {
            try (var c = FileChannel.open(gate, Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS), PosixFilePermissions.asFileAttribute(FILE))) {
                ByteBuffer b = ByteBuffer.wrap(PLAN); while (b.hasRemaining()) c.write(b); c.force(true);
            }
        }
        Path createEmpty(Path control) throws IOException {
            Path temp = Files.createTempFile(control, ".fleet-reset-", ".tmp", PosixFilePermissions.asFileAttribute(FILE));
            try { forceFile(temp); return temp; }
            catch (IOException e) { Files.deleteIfExists(temp); throw e; }
        }
        void replace(Path temp, Path fleet) throws IOException { Files.move(temp, fleet, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING); }
        void forceFile(Path p) throws IOException { try (var c = FileChannel.open(p, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) { c.force(true); } }
        void forceDirectory(Path p) throws IOException { try (var c = FileChannel.open(p, StandardOpenOption.READ)) { c.force(true); } }
        void delete(Path p) throws IOException { Files.delete(p); }
    }
}
