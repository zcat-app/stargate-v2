// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.regex.Pattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/** Opt-in integration uses only newly generated synthetic keys and files. */
class OfflineVerifyNativeTest {
    private static final String AGE_HASH = "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c";
    private static final String KEYGEN_HASH = "0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899";
    @TempDir Path temp;
    Path age, keygen, identity, work, ciphertext;
    String recipient;
    record Result(int code, String out, String err) {}
    @BeforeEach void setup() throws Exception {
        String a = System.getenv("STARGATE_TEST_AGE"), k = System.getenv("STARGATE_TEST_AGE_KEYGEN");
        assumeTrue(a != null && k != null, "Explicit pinned age and age-keygen binaries required");
        age = Path.of(a); keygen = Path.of(k);
        assertEquals(AGE_HASH, sha(age)); assertEquals(KEYGEN_HASH, sha(keygen));
        work = Files.createDirectory(temp.resolve("work"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        identity = temp.resolve("identity");
        Result key = command(List.of(keygen.toString(), "--output", identity.toString()), null, null);
        assertEquals(0, key.code); var m = Pattern.compile("age1[0-9a-z]{58}").matcher(key.err); assertTrue(m.find()); recipient = m.group();
        // Exceeds an age chunk so corruption at the end occurs after plaintext
        // has already been emitted by the decryptor.
        var entries = ArchiveInspectorTest.roots(); entries.add(ArchiveInspectorTest.file("app-data/config", "x".repeat(179200)));
        Path tar = temp.resolve("input.tar"); Files.write(tar, ArchiveInspectorTest.archive(entries));
        ciphertext = temp.resolve("archive.age");
        Result encrypted = command(List.of(age.toString(), "--encrypt", "--recipient", recipient), tar, ciphertext);
        assertEquals(0, encrypted.code);
    }
    private static String sha(Path p) throws Exception { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(p))); }
    private Result command(List<String> args, Path input, Path output) throws Exception {
        Path err = Files.createTempFile(temp, "stderr", ".txt"), out = output == null ? Files.createTempFile(temp, "stdout", ".txt") : output;
        ProcessBuilder builder = new ProcessBuilder(args).redirectOutput(out.toFile()).redirectError(err.toFile());
        if (input != null) builder.redirectInput(input.toFile());
        builder.environment().clear(); builder.environment().put("PATH", "/nonexistent"); builder.environment().put("LANG", "C");
        Process process = builder.start(); assertTrue(process.waitFor(30, java.util.concurrent.TimeUnit.SECONDS));
        return new Result(process.exitValue(), output == null ? Files.readString(out) : "", Files.readString(err));
    }
    private Result verify(Path key, Path archive, String hash, Path scratch) throws Exception {
        String classes = Path.of(OfflineVerify.class.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        return command(List.of(java, "--enable-native-access=ALL-UNNAMED", "-cp", classes, OfflineVerify.class.getName(),
                "--age", age.toString(), "--age-sha256", hash, "--identity", key.toString(), "verify",
                "--archive", archive.toString(), "--work-dir", scratch.toString()), null, null);
    }
    private void clean() throws IOException { try (var paths = Files.list(work)) { assertEquals(0, paths.count()); } }
    @Test void nativeRoundTripAndLateTampering() throws Exception {
        Result good = verify(identity, ciphertext, AGE_HASH, work);
        assertEquals(0, good.code, good.err); assertEquals("ENCRYPTED_ARCHIVE_VERIFIED entries=6 payload_bytes=179200 nym=false\n", good.out); assertEquals("", good.err); clean();
        byte[] corrupted = Files.readAllBytes(ciphertext); corrupted[corrupted.length - 1] ^= 1;
        Path bad = temp.resolve("tampered.age"); Files.write(bad, corrupted);
        Result failed = verify(identity, bad, AGE_HASH, work);
        assertNotEquals(0, failed.code); assertTrue(failed.out.isEmpty()); assertFalse(failed.err.contains("tampered.age")); clean();
        Path truncated = temp.resolve("truncated.age"); Files.write(truncated, java.util.Arrays.copyOf(corrupted, corrupted.length - 20));
        assertNotEquals(0, verify(identity, truncated, AGE_HASH, work).code); clean();
        Path invalid = temp.resolve("invalid.tar"); Files.write(invalid, new byte[1024]);
        Path invalidCiphertext = temp.resolve("invalid.age");
        assertEquals(0, command(List.of(age.toString(), "--encrypt", "--recipient", recipient), invalid, invalidCiphertext).code);
        Result structurallyInvalid = verify(identity, invalidCiphertext, AGE_HASH, work);
        assertNotEquals(0, structurallyInvalid.code); assertTrue(structurallyInvalid.out.isEmpty()); clean();
    }
    @Test void rejectsWrongIdentityAndUnsafePathsPermissionsOrDigest() throws Exception {
        Path wrong = temp.resolve("wrong-key"); assertEquals(0, command(List.of(keygen.toString(), "--output", wrong.toString()), null, null).code);
        assertNotEquals(0, verify(wrong, ciphertext, AGE_HASH, work).code); clean();
        assertNotEquals(0, verify(identity, ciphertext, "0".repeat(64), work).code); clean();
        Files.setPosixFilePermissions(identity, PosixFilePermissions.fromString("rw-r--r--"));
        assertNotEquals(0, verify(identity, ciphertext, AGE_HASH, work).code); clean();
        Files.setPosixFilePermissions(identity, PosixFilePermissions.fromString("rw-------"));
        Path link = temp.resolve("linked"); Files.createSymbolicLink(link, identity);
        assertNotEquals(0, verify(link, ciphertext, AGE_HASH, work).code); clean();
        Path hardlink = temp.resolve("hardlink"); Files.createLink(hardlink, identity);
        assertNotEquals(0, verify(identity, ciphertext, AGE_HASH, work).code); Files.delete(hardlink); clean();
        Path parentLink = temp.resolve("linked-parent"); Files.createSymbolicLink(parentLink, temp);
        assertNotEquals(0, verify(parentLink.resolve("identity"), ciphertext, AGE_HASH, work).code); clean();
        Path inside = work.resolve("inside.age"); Files.copy(ciphertext, inside);
        assertNotEquals(0, verify(identity, inside, AGE_HASH, work).code); Files.delete(inside); clean();
        Files.writeString(identity, "AGE-PLUGIN-UNSUPPORTED\n", StandardCharsets.US_ASCII);
        assertNotEquals(0, verify(identity, ciphertext, AGE_HASH, work).code); clean();
    }
}
