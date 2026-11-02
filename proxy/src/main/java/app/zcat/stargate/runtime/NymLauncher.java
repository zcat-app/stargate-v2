// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;

/** Native client owner; no native output (which can contain destinations) enters production logs. */
public final class NymLauncher {
    private static final Object LIFECYCLE = new Object();
    private static Process child;
    private static boolean closing;
    // Native tracked-task shutdown has a ten-second deadline. Leave time to reap it.
    private static final long SHUTDOWN_SECONDS = 20;
    private static final String ID = "stargate";
    private static final Path DATA = Path.of("/data/nym"), SECRET = Path.of("/secrets/key-passphrase");
    private static final Path CONFIG = DATA.resolve(".nym/socks5-clients/" + ID + "/config/config.toml");
    private static final Path STARTED = DATA.resolve("initialization-started");
    private static Process launch(String passphrase, String... arguments) throws Exception {
        var command = new ArrayList<>(List.of("/opt/nym/nym-socks5-client"));
        command.addAll(List.of(arguments));
        var builder = new ProcessBuilder(command).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(ProcessBuilder.Redirect.DISCARD);
        builder.environment().put("NYM_HOME_DIR", DATA.toString());
        builder.environment().put("NYM_CLIENT_KEY_PASSPHRASE", passphrase);
        builder.environment().put("RUST_LOG", "off");
        return startChild(builder);
    }
    static Process startChild(ProcessBuilder builder) throws java.io.IOException {
        synchronized (LIFECYCLE) {
            if (closing) throw new IllegalStateException();
            return child = builder.start();
        }
    }
    static void validateSecret(Path path) throws Exception {
        if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.size(path) > 512) throw new IllegalStateException();
        for (var permission : Files.getPosixFilePermissions(path))
            if (permission.name().startsWith("GROUP_") || permission.name().startsWith("OTHERS_")) throw new IllegalStateException();
        if (!Files.readString(path).trim().matches("[A-Za-z0-9_-]{43,128}")) throw new IllegalStateException();
    }
    /** Returns true only when the child exited successfully without launcher escalation.
     * Native exit zero alone does not certify a reply-store flush; verification inspects the DB. */
    static boolean stopChild(Process process, long timeout, TimeUnit unit) {
        if (process == null) return true;
        if (!process.isAlive()) return process.exitValue() == 0;
        process.destroy(); // SIGTERM, handled by the pinned native lifecycle patch.
        boolean interrupted = false;
        try {
            if (process.waitFor(timeout, unit)) {
                boolean clean = process.exitValue() == 0;
                System.err.println(clean ? "NYM_CHILD_STOPPED" : "NYM_CHILD_STOP_FAILED");
                return clean;
            }
        } catch (InterruptedException ignored) { interrupted = true; }
        System.err.println("NYM_CHILD_STOP_FORCED");
        process.destroyForcibly();
        try { process.waitFor(2, TimeUnit.SECONDS); }
        catch (InterruptedException ignored) { interrupted = true; }
        finally { if (interrupted) Thread.currentThread().interrupt(); }
        return false;
    }
    static Process beginShutdown() {
        synchronized (LIFECYCLE) { closing = true;return child; }
    }
    public static void main(String[] args) {
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            stopChild(beginShutdown(), SHUTDOWN_SECONDS, TimeUnit.SECONDS);
        }, "nym-shutdown"));
        try {
            Files.createDirectories(DATA);
            Files.setPosixFilePermissions(DATA, PosixFilePermissions.fromString("rwx------"));
            Files.setPosixFilePermissions(SECRET.getParent(), PosixFilePermissions.fromString("rwx------"));
            boolean initialized = Files.exists(CONFIG);
            boolean partial = Files.exists(STARTED) || Files.exists(DATA.resolve(".nym"));
            if (!initialized && partial) throw new IllegalStateException();
            if (!Files.exists(SECRET)) {
                if (initialized || partial) throw new IllegalStateException();
                byte[] bytes = new byte[48];new SecureRandom().nextBytes(bytes);
                Files.createFile(SECRET, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                Files.writeString(SECRET, Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) + "\n");
            }
            validateSecret(SECRET);
            String passphrase = Files.readString(SECRET).trim();
            if (!initialized) {
                String provider = System.getenv().getOrDefault("STARGATE_NYM_PROVIDER", "");
                if (!provider.matches("[1-9A-HJ-NP-Za-km-z]{32,50}\\.[1-9A-HJ-NP-Za-km-z]{32,50}@[1-9A-HJ-NP-Za-km-z]{32,50}")) throw new IllegalStateException();
                Files.createFile(STARTED, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                var init = launch(passphrase, "init", "--id", ID, "--provider", provider, "--use-reply-surbs", "true", "--host", "0.0.0.0", "--port", "1080", "--force-tls-gateway");
                if (!init.waitFor(180, TimeUnit.SECONDS)) { init.destroyForcibly();throw new IllegalStateException(); }
                if (init.exitValue() != 0 || !Files.isRegularFile(CONFIG)) throw new IllegalStateException();
            }
            String config = Files.readString(CONFIG);
            String section = "[core.debug.stats_reporting]";
            int start = config.indexOf(section);
            if (start < 0) throw new IllegalStateException();
            int end = config.indexOf("\n[", start + section.length());
            if (end < 0) end = config.length();
            String stats = config.substring(start, end);
            if (!stats.contains("enabled = true") && !stats.contains("enabled = false")) throw new IllegalStateException();
            config = config.substring(0, start) + stats.replace("enabled = true", "enabled = false") + config.substring(end);
            Files.writeString(CONFIG, config);
            // Tighten existing files; later native files inherit its umask. All remain inside the
            // 0700 Nym-only directory, including databases not encrypted by the passphrase.
            try (var paths = Files.walk(DATA)) {
                for (Path path : paths.toList()) {
                    if (Files.isSymbolicLink(path)) throw new IllegalStateException();
                    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(Files.isDirectory(path) ? "rwx------" : "rw-------"));
                }
            }
            System.out.println("NYM_CLIENT_STARTING");
            int result = launch(passphrase, "run", "--id", ID).waitFor();
            System.err.println("NYM_CLIENT_EXITED");
            System.exit(result == 0 ? 0 : 1);
        } catch (Exception ignored) {
            System.err.println("NYM_START_FAILED_CHECK_PRIVATE_STATE_AND_CONFIGURATION");
            System.exit(1);
        }
    }
}
