package app.zcat.stargate.simplexalert;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/** Owns only the dedicated SimpleX process. It observes no Stargate services. */
public final class SimplexRuntimeMain {
    private static final Path PROFILE = Path.of("/profile");
    private SimplexRuntimeMain() {}

    public static void main(String[] args) {
        try {
            validateProfile(PROFILE);
            // Validate destination syntax before starting the unauthenticated local API.
            new SimplexAlertTransport(URI.create("ws://127.0.0.1:17619/"),
                    System.getenv("SIMPLEX_ALERT_CONTACT_ID"), Duration.ofSeconds(10));
            Process child = builder(Path.of("/opt/simplex/simplex-chat"), PROFILE).start();
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                child.destroy();
                try {
                    if (!child.waitFor(10, TimeUnit.SECONDS)) child.destroyForcibly();
                } catch (InterruptedException e) {
                    child.destroyForcibly();
                    Thread.currentThread().interrupt();
                }
            }));
            System.exit(child.waitFor() == 0 ? 0 : 1);
        } catch (Exception e) {
            // Paths, keys, configuration, and upstream diagnostics stay out of logs.
            System.err.println("SIMPLEX_RUNTIME_START_FAILED");
            System.exit(1);
        }
    }

    static ProcessBuilder builder(Path binary, Path profile) {
        return new ProcessBuilder(binary.toString(), "-d", profile.resolve("db").toString(),
                "-p", "17619")
                .directory(profile.toFile())
                .redirectInput(ProcessBuilder.Redirect.from(Path.of("/dev/null").toFile()))
                .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                .redirectError(ProcessBuilder.Redirect.DISCARD);
    }

    static void validateProfile(Path profile) throws IOException {
        Set<PosixFilePermission> privateDirectory = Set.of(PosixFilePermission.OWNER_READ,
                PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_EXECUTE);
        if (!Files.isDirectory(profile, LinkOption.NOFOLLOW_LINKS)
                || !Files.getPosixFilePermissions(profile, LinkOption.NOFOLLOW_LINKS).equals(privateDirectory)
                || ((Number) Files.getAttribute(profile, "unix:uid", LinkOption.NOFOLLOW_LINKS)).intValue() != 10001) {
            throw new IOException("Profile permissions invalid");
        }
        try (var entries = Files.walk(profile)) {
            for (Path entry : entries.toList()) {
                if (Files.isSymbolicLink(entry)
                        || !(Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)
                        || Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS))
                        || ((Number) Files.getAttribute(entry, "unix:uid", LinkOption.NOFOLLOW_LINKS)).intValue() != 10001) {
                    throw new IOException("Profile entry invalid");
                }
            }
        }
        for (String db : new String[]{"db_chat.db", "db_agent.db"}) {
            if (!Files.isRegularFile(profile.resolve(db), LinkOption.NOFOLLOW_LINKS)
                    || Files.size(profile.resolve(db)) == 0) throw new IOException("Prepared profile required");
        }
    }
}
