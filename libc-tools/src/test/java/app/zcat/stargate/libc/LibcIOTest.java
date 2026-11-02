/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static app.zcat.stargate.libc.LibcIO.*;

class LibcIOTest {
    @TempDir Path root;
    @Test void processCapturesBinaryOutputStderrAndFailingStatus() throws Exception {
        var result = new Processes().run(List.of("sh", "-c", "printf '\\000\\377'; printf error >&2; exit 7"), null, Duration.ofSeconds(5));
        assertEquals(7, result.status()); assertArrayEquals(new byte[]{0, (byte)255}, result.stdout()); assertEquals("error", result.error());
    }
    @Test void timeoutIsFailureAndShellQuotingKeepsLiteralText() throws Exception {
        assertThrows(Exception.class, () -> new Processes().run(List.of("sh", "-c", "exec sleep 5"), null, Duration.ofMillis(50)));
        String literal = "spaces ' ; $(printf unintended)";
        var result = new Processes().run(List.of("sh", "-c", "printf '%s' " + quote(literal)), null, Duration.ofSeconds(5));
        assertEquals(0, result.status()); assertEquals(literal, result.text());
    }
    @Test void streamingRequiresBothProducerAndConsumerSuccess() throws Exception {
        var processes = new Processes();
        processes.pipeline(List.of("sh", "-c", "printf payload"), List.of("cat"));
        assertThrows(Exception.class, () -> processes.pipeline(List.of("sh", "-c", "printf payload; exit 9"), List.of("cat")));
        assertThrows(Exception.class, () -> processes.pipeline(List.of("sh", "-c", "printf payload"), List.of("sh", "-c", "cat >/dev/null; exit 8")));
    }
    @Test void cliIsWiredAndBadArgumentsCannotInvokeDocker() throws Exception {
        Runner forbidden = (c, i, t) -> { fail("No Docker permitted: " + c); return null; };
        assertEquals(0, LibcTools.execute(new String[]{"--project", root.toString(), "build", "--help"}, forbidden));
        assertEquals(0, LibcTools.execute(new String[]{"--project", root.toString(), "regression", "--help"}, forbidden));
        assertThrows(Exception.class, () -> LibcTools.execute(new String[]{"--project", root.toString(), "regression"}, forbidden));
        assertThrows(Exception.class, () -> LibcTools.execute(new String[]{"--project", root.toString(), "build", "--unknown"}, forbidden));
        assertThrows(Exception.class, () -> LibcTools.execute(new String[]{"--project", root.toString(), "diagnose", "--unknown"}, forbidden));
    }
}
