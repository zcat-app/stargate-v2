// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class SpawnNativeTest {
    @TempDir Path temp;
    @Test void ageChildInheritsPrivilegeAndResourceConstraintsOnly() throws Exception {
        String age = System.getenv("STARGATE_TEST_AGE"), keygen = System.getenv("STARGATE_TEST_AGE_KEYGEN");
        assumeTrue(age != null && keygen != null, "Explicit pinned native age binaries required");
        assertEquals("eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c", sha(Path.of(age)));
        assertEquals("0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899", sha(Path.of(keygen)));
        Path identity = temp.resolve("synthetic-key"), fifo = temp.resolve("input-fifo"), output = temp.resolve("output"), sentinel = temp.resolve("sentinel");
        Files.writeString(sentinel, "synthetic sentinel");
        Path keyInfo = temp.resolve("key-info");
        Process key = new ProcessBuilder(keygen, "--output", identity.toString()).redirectOutput(ProcessBuilder.Redirect.DISCARD).redirectError(keyInfo.toFile()).start();
        assertTrue(key.waitFor(15, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, key.exitValue());
        var match = java.util.regex.Pattern.compile("age1[0-9a-z]{58}").matcher(Files.readString(keyInfo)); assertTrue(match.find());
        Process mkfifo = new ProcessBuilder("/usr/bin/mkfifo", fifo.toString()).start(); assertTrue(mkfifo.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)); assertEquals(0, mkfifo.exitValue());
        String classes = Path.of(Linux.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(SpawnProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        for (boolean encrypt : List.of(false, true)) {
            var command = new java.util.ArrayList<>(List.of(Path.of(System.getProperty("java.home"), "bin", "java").toString(), "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, SpawnProbe.class.getName(), age, identity.toString(), fifo.toString(), output.toString() + (encrypt ? "-encrypt" : ""), sentinel.toString()));
            if (encrypt) command.add(match.group());
            Process p = new ProcessBuilder(command).start();
            try {
                assertTrue(p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS));
                assertEquals(0, p.exitValue(), new String(p.getErrorStream().readAllBytes()));
                assertEquals("SPAWN_CONSTRAINTS_CONFIRMED\n", new String(p.getInputStream().readAllBytes()));
            } finally {
                if (p.isAlive()) { p.descendants().forEach(ProcessHandle::destroyForcibly); p.destroyForcibly(); }
            }
        }
    }
    private static String sha(Path path) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))); }
}
