// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

class NymLauncherTest {
    private Process fixture(String handler) throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        Process p = new ProcessBuilder(java, "-XX:-UsePerfData", "-cp", classpath,
                NymSignalFixture.class.getName(), handler).start();
        assertEquals("ready", new BufferedReader(new InputStreamReader(p.getInputStream())).readLine());
        return p;
    }
    @Test void waitsForCooperativeSignalHandler() throws Exception {
        Process p = fixture("cooperative");
        try {
            assertTrue(NymLauncher.stopChild(p, 2, TimeUnit.SECONDS));
            assertFalse(p.isAlive());assertEquals(0,p.exitValue());
        } finally { p.destroyForcibly(); }
    }
    @Test void unresponsiveChildIsKilledAndReaped() throws Exception {
        Process p = fixture("ignore");
        try {
            assertFalse(NymLauncher.stopChild(p, 30, TimeUnit.MILLISECONDS));
            assertFalse(p.isAlive());assertNotEquals(0,p.exitValue());
        } finally { p.destroyForcibly(); }
    }
    @Test void interruptedWaitStillReapsAndRestoresInterrupt() throws Exception {
        Process p = fixture("ignore");
        try {
            Thread.currentThread().interrupt();
            assertFalse(NymLauncher.stopChild(p, 2, TimeUnit.SECONDS));
            assertFalse(p.isAlive());assertTrue(Thread.currentThread().isInterrupted());
        } finally { Thread.interrupted();p.destroyForcibly(); }
    }
    @Test void shutdownPreventsLateChildCreation() {
        NymLauncher.beginShutdown();
        assertThrows(IllegalStateException.class, () -> NymLauncher.startChild(new ProcessBuilder("/does-not-exist")));
    }
}
