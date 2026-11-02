// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.io.IOException;
import java.io.InputStream;
import java.lang.foreign.Arena;
import java.lang.foreign.ValueLayout;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/** Offline archive packing, authenticated verification and gated staging. */
public final class OfflineVerify {
    private static final long MAX_CIPHERTEXT = ArchiveInspector.MAX_ARCHIVE + 32L * 1024 * 1024;
    private static final long MAX_BINARY = 32L * 1024 * 1024;
    private static final long TIMEOUT_NANOS = TimeUnit.MINUTES.toNanos(30);
    static long timeoutNanos = TIMEOUT_NANOS;
    private static final AtomicInteger ACTIVE = new AtomicInteger(-1);
    private static final AtomicBoolean SHUTTING_DOWN = new AtomicBoolean();
    private static final CountDownLatch CLEANED = new CountDownLatch(1);
    interface Faults { void at(String phase) throws IOException; }
    static Faults faults = phase -> {};
    private OfflineVerify() {}

    public static void main(String[] args) {
        Thread main = Thread.currentThread();
        Thread hook = new Thread(() -> {
            SHUTTING_DOWN.set(true);
            main.interrupt();
            try { CLEANED.await(); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
        }, "offline-verify-cleanup");
        Runtime.getRuntime().addShutdownHook(hook);
        int exit;
        try { exit = run(args); }
        finally { CLEANED.countDown(); }
        try { Runtime.getRuntime().removeShutdownHook(hook); }
        catch (IllegalStateException shuttingDown) { return; }
        System.exit(exit);
    }
    private static int run(String[] args) {
        Options options;
        try { options = options(args); }
        catch (IllegalArgumentException e) {
            System.err.println("Requires --age FILE --age-sha256 HEX --identity FILE followed by pack, verify or stage options"); return 2;
        }
        try {
            ArchiveInspector.Summary result = execute(options);
            if (SHUTTING_DOWN.get() || Thread.currentThread().isInterrupted()) throw new IOException("Interrupted");
            String status = options.command.equals("stage") ? "OFFLINE_STAGE_CREATED_RECOVERY_REQUIRED" : "ENCRYPTED_ARCHIVE_VERIFIED";
            System.out.printf("%s entries=%d payload_bytes=%d nym=%s%n", status, result.entries(), result.payloadBytes(), result.nym());
            return 0;
        } catch (Exception e) {
            Retained retained = retained(e);
            if (retained != null) {
                System.err.println("OFFLINE_BACKUP_FAILED: incomplete cleanup; inspect private location: " + retained.location + "; any output is unconfirmed"); return 1;
            }
            System.err.println("OFFLINE_BACKUP_FAILED: file, archive or process operation failed; output is unconfirmed"); return 1;
        }
    }
    private record Options(String binary, String hash, String identity, String command, String source, String destination, String recipient, boolean nym) {}
    private static Options options(String[] args) {
        if (args.length < 7 || !args[0].equals("--age") || !args[2].equals("--age-sha256") || !args[4].equals("--identity")) throw new IllegalArgumentException();
        String command = args[6];
        Set<String> allowed = switch (command) {
            case "pack" -> Set.of("--source", "--output", "--recipient");
            case "verify" -> Set.of("--archive", "--work-dir");
            case "stage" -> Set.of("--archive", "--output");
            default -> throw new IllegalArgumentException();
        };
        Map<String, String> values = new HashMap<>(); boolean nym = false;
        for (int i = 7; i < args.length; i++) {
            String name = args[i];
            if (name.equals("--nym") && command.equals("pack") && !nym) { nym = true; continue; }
            if (!allowed.contains(name) || values.containsKey(name) || ++i >= args.length) throw new IllegalArgumentException();
            values.put(name, args[i]);
        }
        if (!values.keySet().equals(allowed)) throw new IllegalArgumentException();
        return new Options(args[1], args[3], args[5], command, values.get(command.equals("pack") ? "--source" : "--archive"),
                values.get(command.equals("verify") ? "--work-dir" : "--output"), values.get("--recipient"), nym);
    }
    private static Retained retained(Throwable failure) {
        if (failure instanceof Retained r) return r;
        for (Throwable suppressed : failure.getSuppressed()) {
            Retained found = retained(suppressed); if (found != null) return found;
        }
        return failure.getCause() == null ? null : retained(failure.getCause());
    }
    private static ArchiveInspector.Summary execute(Options options) throws Exception {
        if (!"Linux".equals(System.getProperty("os.name"))) throw new IOException("Linux required");
        int uid = Linux.uid("getuid"), euid = Linux.uid("geteuid"), gid = Linux.uid("getgid"), egid = Linux.uid("getegid");
        if (euid == 0 || uid != euid || gid != egid) throw new IOException("Unprivileged invocation required");
        Path binary = Linux.absolute(options.binary), identity = Linux.absolute(options.identity), source = Linux.absolute(options.source), destination = Linux.absolute(options.destination);
        Path work = options.command.equals("verify") ? destination : destination.getParent();
        if (work == null || (!options.command.equals("verify") && destination.getFileName() == null)) throw new IOException("Output name required");
        if (identity.startsWith(work) || (options.command.equals("pack") && identity.startsWith(source))) throw new IOException("Separate identity required");
        if (options.command.equals("pack")) {
            if (source.startsWith(work) || work.startsWith(source) || !options.recipient.matches("age1[0-9a-z]{58}")) throw new IOException("Invalid source or recipient");
        } else if (source.startsWith(work)) throw new IOException("Separate archive required");
        if (!options.hash.matches("[0-9a-f]{64}")) throw new IOException("Invalid executable digest");
        int ageFd = -1, identityFd = -1;
        try {
            ageFd = Linux.openRegular(binary, MAX_BINARY, false, euid);
            Linux.Stat before = Linux.stat(ageFd);
            if ((before.uid() != 0 && before.uid() != Integer.toUnsignedLong(euid)) || (before.mode() & 06022) != 0 || (before.mode() & 0111) == 0) throw new IOException("Invalid executable permissions");
            if (!digestElf(ageFd).equals(options.hash) || !before.equals(Linux.stat(ageFd))) throw new IOException("Executable changed or digest mismatch");
            identityFd = Linux.openRegular(identity, 65536, true, euid);
            checkIdentity(identityFd);
            try (Work temporary = new Work(work, euid)) {
                if (options.command.equals("pack")) return pack(source, destination.getFileName().toString(), options.recipient, options.nym, ageFd, identityFd, temporary, euid);
                try (Held encrypted = new Held(Linux.openRegular(source, MAX_CIPHERTEXT, false, euid));
                     Held plain = temporary.create("verified.tar")) {
                    age(ageFd, identityFd, encrypted.fd, plain.fd, null, temporary);
                    try (FileChannel input = FileChannel.open(Linux.fdPath(plain.fd), StandardOpenOption.READ)) {
                        faults.at("before-inspect");
                        ArchiveInspector.Summary summary = ArchiveInspector.inspect(input, options.command.equals("stage") ? new ArchiveInspector.StagingOwner(euid, egid) : null);
                        if (options.command.equals("stage")) {
                            try { StagedArchive.stage(new StagedTarReader(input), temporary.dir, temporary.parent, destination.getFileName().toString(), euid, egid); }
                            catch (StagedArchive.Uncertain failure) { temporary.retain = true; throw failure; }
                        }
                        return summary;
                    }
                }
            }
        } finally {
            if (identityFd >= 0) Linux.close(identityFd);
            if (ageFd >= 0) Linux.close(ageFd);
        }
    }
    private static ArchiveInspector.Summary pack(Path source, String output, String recipient, boolean nym, int binary, int identity, Work work, int uid) throws Exception {
        byte[] expected;
        try (Held sourceRoot = new Held(Linux.openDir(source.toString(), true, uid)); Held plain = work.create("archive.tar")) {
            try (FileChannel channel = FileChannel.open(Linux.fdPath(plain.fd), StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                expected = ArchiveWriter.write(sourceRoot.fd, channel, nym);
            }
            try (Held encrypted = work.create("archive.age")) { age(binary, identity, plain.fd, encrypted.fd, recipient, work); }
        }
        work.remove("archive.tar");
        ArchiveInspector.Summary summary;
        try (Held encrypted = work.open("archive.age"); Held verified = work.create("verified.tar")) {
            age(binary, identity, encrypted.fd, verified.fd, null, work);
            if (!MessageDigest.isEqual(expected, digest(verified.fd))) throw new IOException("Archive roundtrip differs");
            try (FileChannel input = FileChannel.open(Linux.fdPath(verified.fd), StandardOpenOption.READ)) { faults.at("before-inspect"); summary = ArchiveInspector.inspect(input, null); }
        }
        work.remove("verified.tar");
        work.publish("archive.age", output);
        return summary;
    }
    private static byte[] digest(int fd) throws Exception {
        MessageDigest hash = MessageDigest.getInstance("SHA-256"); byte[] bytes = new byte[65536];
        try (InputStream input = java.nio.file.Files.newInputStream(Linux.fdPath(fd))) {
            int n; while ((n = input.read(bytes)) != -1) hash.update(bytes, 0, n);
        }
        return hash.digest();
    }
    private static String digestElf(int fd) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream in = java.nio.file.Files.newInputStream(Linux.fdPath(fd))) {
            byte[] first = in.readNBytes(4);
            if (!Arrays.equals(first, new byte[]{0x7f, 'E', 'L', 'F'})) throw new IOException("ELF required");
            digest.update(first); byte[] buf = new byte[65536]; long total = first.length; int n;
            while ((n = in.read(buf)) != -1) { total += n; if (total > MAX_BINARY) throw new IOException("Executable too large"); digest.update(buf, 0, n); }
        }
        return HexFormat.of().formatHex(digest.digest());
    }
    private static void checkIdentity(int fd) throws IOException {
        byte[] bytes;
        try (InputStream in = java.nio.file.Files.newInputStream(Linux.fdPath(fd))) { bytes = in.readNBytes(65537); }
        try {
            if (bytes.length > 65536) throw new IOException("Identity too large");
            for (byte b : bytes) if (b < 0) throw new IOException("Native identity required");
            String[] lines = new String(bytes, StandardCharsets.US_ASCII).split("\\r\\n|[\\n\\r\\u000b\\u000c\\u001c-\\u001e]", -1);
            String key = null;
            for (String line : lines) if (!line.isEmpty() && !line.startsWith("#")) {
                if (key != null) throw new IOException("One identity required");
                key = line;
            }
            if (key == null || !key.matches("AGE-SECRET-KEY-1[0-9A-Z]{58}")) throw new IOException("Native identity required");
        } finally { Arrays.fill(bytes, (byte) 0); }
    }
    private static void age(int binary, int identity, int source, int target, String recipient, Work work) throws Exception {
        int pid = -1; boolean reaped = false;
        try (Arena a = Arena.ofConfined()) {
            if (Thread.currentThread().isInterrupted() || SHUTTING_DOWN.get()) throw new InterruptedException();
            Linux.seekStart(source); Linux.seekStart(identity); Linux.seekStart(target);
            pid = Linux.spawnAge(binary, identity, source, target, ACTIVE, recipient);
            faults.at("after-age-spawn");
            long deadline = System.nanoTime() + timeoutNanos;
            var status = a.allocate(ValueLayout.JAVA_INT);
            while (true) {
                if (Thread.currentThread().isInterrupted() || SHUTTING_DOWN.get() || System.nanoTime() - deadline >= 0) throw new InterruptedException();
                int result = Linux.waitNoHang(pid, status);
                if (result == pid) {
                    reaped = true; ACTIVE.set(-1);
                    if (status.get(ValueLayout.JAVA_INT, 0) != 0) throw new IOException("Age process failed");
                    break;
                }
                Thread.sleep(50);
            }
            Linux.sync(target);
            if (Linux.stat(target).size() > (recipient == null ? ArchiveInspector.MAX_ARCHIVE : MAX_CIPHERTEXT)) throw new IOException("Output limit exceeded");
            Linux.seekStart(target);
        } finally {
            int active = ACTIVE.get();
            if (!reaped && active > 0) {
                try { Linux.kill(active); } catch (IOException ignored) { }
                try { Linux.waitForDeath(active); ACTIVE.set(-1); }
                catch (IOException failure) { work.retain = true; work.childUncertain = true; throw failure; }
            }
        }
    }
    private static final class Retained extends IOException {
        final Path location;
        Retained(Path location) { this.location = location; }
    }
    private static final class Held implements AutoCloseable {
        final int fd;
        Held(int fd) { this.fd = fd; }
        public void close() throws IOException { Linux.close(fd); }
    }
    private static final class Work implements AutoCloseable {
        final int parent, dir;
        final String name;
        final Path location;
        final Set<String> files = new LinkedHashSet<>();
        boolean retain, childUncertain;
        Work(Path directory, int uid) throws IOException {
            parent = Linux.openDir(directory.toString(), true, uid);
            byte[] random = new byte[16]; new SecureRandom().nextBytes(random);
            name = ".stargate-backup-" + HexFormat.of().formatHex(random); location = directory.resolve(name);
            boolean created = false; int fd = -1;
            try {
                Linux.mkdir(parent, name); created = true;
                fd = Linux.openAt(parent, name, Linux.RDONLY | Linux.DIRECTORY | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
                Linux.Stat s = Linux.stat(fd);
                if (s.uid() != Integer.toUnsignedLong(uid) || (s.mode() & 07777) != 0700) throw new IOException("Private work directory required");
                dir = fd;
            } catch (IOException e) {
                try { if (fd >= 0) Linux.close(fd); if (created) Linux.unlink(parent, name, true); Linux.sync(parent); }
                catch (IOException cleanup) { try { Linux.close(parent); } catch (IOException ignored) { } throw new Retained(location); }
                Linux.close(parent); throw e;
            }
        }
        Held create(String file) throws IOException {
            int fd = Linux.openAt(dir, file, Linux.RDWR | Linux.CREAT | Linux.EXCL | Linux.NOFOLLOW | Linux.CLOEXEC, 0600);
            files.add(file);
            try { Linux.chmod(fd, 0600); return new Held(fd); }
            catch (IOException e) { Linux.close(fd); throw e; }
        }
        Held open(String file) throws IOException {
            if (!files.contains(file)) throw new IOException("Unknown work file");
            int fd = Linux.openAt(dir, file, Linux.RDONLY | Linux.NONBLOCK | Linux.NOFOLLOW | Linux.CLOEXEC, 0);
            try {
                Linux.Stat info = Linux.stat(fd);
                if (!VolumeSnapshot.regular(info) || info.links() != 1 || info.size() > MAX_CIPHERTEXT) throw new IOException("Invalid work file");
                return new Held(fd);
            } catch (IOException e) { Linux.close(fd); throw e; }
        }
        void remove(String file) throws IOException { Linux.unlink(dir, file, false); files.remove(file); }
        void publish(String file, String output) throws IOException {
            if (!files.contains(file)) throw new IOException("Unknown work file");
            Linux.link(dir, file, parent, output);
            try { faults.at("after-pack-link"); Linux.sync(parent); }
            catch (IOException failure) { retain = true; throw new Retained(location); }
        }
        public void close() throws IOException {
            boolean failed = retain, removed = false;
            if (!childUncertain) for (String file : Set.copyOf(files)) {
                try { faults.at("cleanup-file"); remove(file); } catch (IOException e) { failed = true; }
            }
            try {
                Linux.sync(dir);
                if (!failed) { Linux.unlink(parent, name, true); removed = true; faults.at("after-work-rmdir"); Linux.sync(parent); }
            } catch (IOException e) {
                failed = true;
                if (removed) try { Linux.mkdir(parent, name); Linux.sync(parent); } catch (IOException ignored) { }
            }
            try { Linux.close(dir); } catch (IOException e) { failed = true; }
            try { Linux.close(parent); } catch (IOException e) { failed = true; }
            if (failed) throw new Retained(location);
        }
    }
}
