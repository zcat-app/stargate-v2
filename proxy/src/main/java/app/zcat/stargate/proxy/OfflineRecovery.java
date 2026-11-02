// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.io.IOException;
import java.io.PrintStream;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;
import java.util.Set;

/** Compose-only preparation of stopped staged copies. Never contacts or starts a service. */
public final class OfflineRecovery {
    private static final Set<PosixFilePermission> PRIVATE_FILE = PosixFilePermissions.fromString("rw-------");
    private static final Set<PosixFilePermission> PRIVATE_DIRECTORY = PosixFilePermissions.fromString("rwx------");
    private static final String EXHAUSTED_I2P_NEXT_PORT = "65536";
    private static final byte[] INCOMPLETE = "Offline staged recovery incomplete; rerun before starting.\n".getBytes(StandardCharsets.US_ASCII);
    private static final String USAGE = "Usage: java -cp proxy.jar app.zcat.stargate.proxy.OfflineRecovery "
            + "--discard-restored-credentials --staged-config /absolute/staging/proxy.properties "
            + "[--highest-allocated-i2p-port N --ack-complete-i2p-port-history]\n"
            + "N is the highest numeric port ever allocated; 14446 means none. Complete history is operator-attested, not verified.\n"
            + "Requires stopped staged matching Compose volumes, original installation offline, and no concurrent writer.";

    private OfflineRecovery() {}

    public static void main(String[] args) { System.exit(run(args, System.out, System.err)); }

    static int run(String[] args, PrintStream out, PrintStream err) {
        if ((args.length != 3 && args.length != 6) || !args[0].equals("--discard-restored-credentials") || !args[1].equals("--staged-config")
                || (args.length == 6 && (!args[3].equals("--highest-allocated-i2p-port")
                    || !args[4].matches("[0-9]{1,5}") || !args[5].equals("--ack-complete-i2p-port-history")
                    || Integer.parseInt(args[4]) < 14446 || Integer.parseInt(args[4]) > 65535))) {
            err.println(USAGE);
            return 2;
        }
        try {
            String nextPort = args.length == 6 ? Integer.toString(Integer.parseInt(args[4]) + 1) : EXHAUSTED_I2P_NEXT_PORT;
            prepare(Path.of(args[2]), new AtomicFiles(), nextPort, args.length == 6);
            out.println("STAGED_RECOVERY_PREPARED: automatic forwarding startup disabled; administrator token rotated; re-pair every device. "
                    + (args.length == 3 ? "New isolated I2P device routes are blocked because later port history is unknown."
                    : "I2P port history is operator-attested and was not verified; the next port is above the supplied highest allocated port and may remain exhausted."));
            return 0;
        } catch (Exception e) {
            // Never print paths, properties, credentials, or exception details.
            err.println("STAGED_RECOVERY_FAILED: keep this installation offline; correct the cause and rerun.");
            return 1;
        }
    }

    static void prepare(Path config, AtomicFiles files) throws IOException {
        prepare(config, files, EXHAUSTED_I2P_NEXT_PORT, false);
    }

    static void prepare(Path config, AtomicFiles files, String nextPort) throws IOException {
        prepare(config, files, nextPort, true);
    }

    private static void prepare(Path config, AtomicFiles files, String nextPort, boolean attested) throws IOException {
        if (!nextPort.matches("[0-9]{1,5}") || Integer.parseInt(nextPort) < 14447 || Integer.parseInt(nextPort) > 65536)
            throw new IOException("INVALID_I2P_PORT_SEQUENCE");
        if (!config.isAbsolute() || !config.normalize().equals(config)
                || !config.getFileName().toString().equals("proxy.properties"))
            throw new IOException("ABSOLUTE_STAGED_CONFIG_REQUIRED");
        for (Path path = config; path != null; path = path.getParent()) {
            if (Files.isSymbolicLink(path)) throw new IOException("SYMLINK_NOT_ALLOWED");
        }
        Path directory = config.getParent();
        // Separate volume import and identity transactions cannot be bypassed by credential reset.
        for (String gate : new String[]{"volume-import-incomplete", "identity-recovery-incomplete", "identity-recovery-preparing"}) {
            try {
                Files.readAttributes(directory.resolve(gate),
                        java.nio.file.attribute.BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                throw new IOException("OFFLINE_RECOVERY_INCOMPLETE");
            } catch (java.nio.file.NoSuchFileException absent) { /* check the other gate */ }
        }
        if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS).equals(PRIVATE_DIRECTORY))
            throw new IOException("PRIVATE_STAGING_DIRECTORY_REQUIRED");
        checkFile(config);
        Path token = directory.resolve("admin-token");
        checkFile(token);
        if (Files.size(token) > 128 || !Files.readString(token).trim().matches("[A-Za-z0-9_-]{43}"))
            throw new IOException("INVALID_ADMIN_TOKEN");
        Path desired = directory.resolve("proxy-desired");
        Path manager = directory.resolve("manager.properties");
        Path incomplete = directory.resolve("recovery-incomplete");
        for (Path path : new Path[]{desired, manager, incomplete}) {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) checkFile(path);
        }
        Properties restored = ProxyConfig.read(config);
        if (attested) validateKnownPortHistory(restored, Integer.parseInt(nextPort) - 1);
        restored.keySet().removeIf(key -> ((String) key).startsWith("profile."));
        // The default quarantines unknown history, including if isolation is enabled later.
        // A different value requires explicit operator attestation at the CLI boundary.
        restored.setProperty("i2p.nextPort", nextPort);
        // Validate the isolation key and supported schema without DNS or listeners.
        if (!ProxyConfig.profiles(restored).isEmpty()) throw new IOException("CREDENTIAL_REMOVAL_FAILED");
        StringWriter writer = new StringWriter();
        restored.store(writer, "Stargate offline staged recovery: re-pair every device");
        byte[] sanitized = writer.toString().getBytes(StandardCharsets.UTF_8);
        if (sanitized.length > 262144) throw new IOException("CONFIGURATION_TOO_LARGE");
        byte[] random = new byte[32];new SecureRandom().nextBytes(random);
        String newToken = Base64.getUrlEncoder().withoutPadding().encodeToString(random) + "\n";

        // The supervisor refuses an incomplete transaction before initialization/listeners.
        files.replace(incomplete, INCOMPLETE);
        // Its automatic forwarding restart must be durably disabled BEFORE credential edits.
        files.replace(desired, "stopped\n".getBytes(StandardCharsets.US_ASCII));
        files.replace(config, sanitized);
        files.replace(token, newToken.getBytes(StandardCharsets.US_ASCII));
        files.delete(manager);
        files.forceDirectory(directory);
        Properties verified = ProxyConfig.read(config);
        if (!Files.readString(desired).equals("stopped\n") || !ProxyConfig.profiles(verified).isEmpty()
                || !nextPort.equals(verified.getProperty("i2p.nextPort"))
                || !Files.readString(token).equals(newToken) || Files.exists(manager, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("RECOVERY_VERIFICATION_FAILED");
        try {
            files.delete(incomplete);
            files.forceDirectory(directory);
        } catch (IOException failure) {
            // A failed final directory sync is not success. Reestablish the gate if possible.
            try { files.replace(incomplete, INCOMPLETE); }
            catch (IOException restoreFailure) { failure.addSuppressed(restoreFailure); }
            throw failure;
        }
    }

    /** An exhausted counter might be a previous quarantine rather than historical exhaustion. */
    private static void validateKnownPortHistory(Properties restored, int highestAllocated) throws IOException {
        String counter = restored.getProperty("i2p.nextPort");
        if (counter != null) {
            int value = checkedPort(counter, 14447, 65536);
            if (value != 65536 && value - 1 > highestAllocated) throw new IOException("I2P_HISTORY_CONTRADICTION");
        }
        for (String name : restored.stringPropertyNames()) {
            if (name.startsWith("profile.") && name.endsWith(".i2pPort")) {
                int value = checkedPort(restored.getProperty(name), 14447, 65535);
                if (value > highestAllocated) throw new IOException("I2P_HISTORY_CONTRADICTION");
            }
        }
    }

    private static int checkedPort(String value, int minimum, int maximum) throws IOException {
        if (!value.matches("[0-9]{1,5}")) throw new IOException("INVALID_I2P_HISTORY");
        int port = Integer.parseInt(value);
        if (port < minimum || port > maximum) throw new IOException("INVALID_I2P_HISTORY");
        return port;
    }

    private static void checkFile(Path path) throws IOException {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS).equals(PRIVATE_FILE)
                || !Files.getOwner(path, LinkOption.NOFOLLOW_LINKS).equals(Files.getOwner(path.getParent(), LinkOption.NOFOLLOW_LINKS))
                || ((Number) Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS)).longValue() != 1)
            throw new IOException("PRIVATE_REGULAR_FILE_REQUIRED");
    }

    /** No non-atomic fallback. Package visibility permits deterministic I/O failure tests. */
    static class AtomicFiles {
        void replace(Path target, byte[] content) throws IOException {
            Path temporary = Files.createTempFile(target.getParent(), ".recovery-", ".tmp",
                    PosixFilePermissions.asFileAttribute(PRIVATE_FILE));
            try {
                if (!Files.getOwner(temporary).equals(Files.getOwner(target.getParent())))
                    throw new IOException("STAGING_OWNER_REQUIRED");
                try (var channel = FileChannel.open(temporary, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)) {
                    ByteBuffer bytes = ByteBuffer.wrap(content);
                    while (bytes.hasRemaining()) channel.write(bytes);
                    channel.force(true);
                }
                move(temporary, target);
                forceDirectory(target.getParent());
            } finally {
                Files.deleteIfExists(temporary);
            }
        }

        void move(Path source, Path target) throws IOException {
            Files.move(source, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        }

        void delete(Path path) throws IOException { Files.deleteIfExists(path); }

        void forceDirectory(Path directory) throws IOException {
            try (var channel = FileChannel.open(directory, StandardOpenOption.READ)) { channel.force(true); }
        }
    }
}
