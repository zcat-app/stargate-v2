package app.zcat.stargate.simplexalert;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class SimplexRuntimeMainTest {
    @TempDir Path temporary;

    @Test void launchUsesExactArgumentsWithoutAutomaticMigrationApproval() {
        Path binary = Path.of("/opt/simplex/simplex-chat");
        Path profile = Path.of("/profile");
        ProcessBuilder launch = SimplexRuntimeMain.builder(binary, profile);
        assertEquals(List.of("/opt/simplex/simplex-chat", "-d", "/profile/db", "-p", "17619"),
                launch.command());
        assertEquals(ProcessBuilder.Redirect.from(Path.of("/dev/null").toFile()), launch.redirectInput());
    }

    @Test void childOutputIsDiscardedFromStartEvenOnFailure() throws Exception {
        Path executable = temporary.resolve("noisy-process");
        Files.writeString(executable, "#!/bin/sh\nprintf sensitive-out\nprintf sensitive-error >&2\nexit 7\n");
        Files.setPosixFilePermissions(executable, PosixFilePermissions.fromString("rwx------"));
        Process child = SimplexRuntimeMain.builder(executable, temporary).start();
        assertTrue(child.waitFor(5, TimeUnit.SECONDS));
        assertEquals(7, child.exitValue());
        assertEquals(-1, child.getInputStream().read());
        assertEquals(-1, child.getErrorStream().read());
        try (var files = Files.list(temporary)) {
            assertEquals(1, files.count());
        }
    }

    @Test void missingOrPublicProfileFailsBeforeStartingProcess() throws Exception {
        assertThrows(Exception.class, () -> SimplexRuntimeMain.validateProfile(temporary.resolve("missing")));
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rwxr-xr-x"));
        assertThrows(Exception.class, () -> SimplexRuntimeMain.validateProfile(temporary));
    }

    @Test void profileSymlinkFailsBeforeStartingProcess() throws Exception {
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rwx------"));
        Path link = temporary.resolve("link");
        Files.createSymbolicLink(link, temporary);
        assertThrows(Exception.class, () -> SimplexRuntimeMain.validateProfile(link));
    }
}
