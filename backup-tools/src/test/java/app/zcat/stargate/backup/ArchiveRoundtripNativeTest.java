// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Connects the in-progress writer to native age and the verify command. */
class ArchiveRoundtripNativeTest {
    @TempDir Path temp;
    private record Result(int status, String out, String err) {}
    private Result run(List<String> command, Path stdin, Path stdout) throws Exception {
        Path out = stdout == null ? Files.createTempFile(temp, "out", ".txt") : stdout;
        Path err = Files.createTempFile(temp, "err", ".txt");
        ProcessBuilder builder = new ProcessBuilder(command).redirectOutput(out.toFile()).redirectError(err.toFile());
        if (stdin != null) builder.redirectInput(stdin.toFile());
        builder.environment().clear(); builder.environment().put("PATH", "/nonexistent"); builder.environment().put("LANG", "C");
        Process p = builder.start(); assertTrue(p.waitFor(30, java.util.concurrent.TimeUnit.SECONDS));
        return new Result(p.exitValue(), stdout == null ? Files.readString(out) : "", Files.readString(err));
    }
    @Test void nativeAgeAuthenticatesAnArchiveWrittenFromSyntheticRoots() throws Exception {
        String age = System.getenv("STARGATE_TEST_AGE"), keygen = System.getenv("STARGATE_TEST_AGE_KEYGEN");
        assumeTrue(age != null && keygen != null, "Explicit pinned native age binaries required");
        assertEquals("eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c", sha(Path.of(age)));
        assertEquals("0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899", sha(Path.of(keygen)));
        Path source = privateDirectory(temp.resolve("source")), work = privateDirectory(temp.resolve("work"));
        for (String root : ArchiveInspector.BASE) privateDirectory(source.resolve(root));
        Path content = Files.writeString(source.resolve("app-data/file"), "synthetic payload");
        Files.setPosixFilePermissions(content, PosixFilePermissions.fromString("rw-------"));
        Path key = temp.resolve("identity"); Result generated = run(List.of(keygen, "--output", key.toString()), null, null);
        assertEquals(0, generated.status); var matcher = Pattern.compile("age1[0-9a-z]{58}").matcher(generated.err); assertTrue(matcher.find());
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classes = Path.of(ArchiveWriter.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String tests = Path.of(ArchiveWriterProbe.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        Path tar = temp.resolve("synthetic.tar"), encrypted = temp.resolve("synthetic.age");
        Result packed = run(List.of(java, "--enable-native-access=ALL-UNNAMED", "-cp", classes + ":" + tests, ArchiveWriterProbe.class.getName(), source.toString(), tar.toString(), "base"), null, null);
        assertEquals(0, packed.status, packed.err);
        Result encrypt = run(List.of(age, "--encrypt", "--recipient", matcher.group()), tar, encrypted); assertEquals(0, encrypt.status, encrypt.err);
        Result verify = run(List.of(java, "--enable-native-access=ALL-UNNAMED", "-cp", classes, OfflineVerify.class.getName(), "--age", age,
                "--age-sha256", "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c", "--identity", key.toString(), "verify", "--archive", encrypted.toString(), "--work-dir", work.toString()), null, null);
        assertEquals(0, verify.status, verify.err); assertEquals("ENCRYPTED_ARCHIVE_VERIFIED entries=6 payload_bytes=17 nym=false\n", verify.out);
        try (var files = Files.list(work)) { assertEquals(0, files.count()); }
    }
    private static Path privateDirectory(Path path) throws Exception { Files.createDirectory(path); Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------")); return path; }
    private static String sha(Path path) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))); }
}
