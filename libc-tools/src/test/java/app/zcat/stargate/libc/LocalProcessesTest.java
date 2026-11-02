/* Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0 */
package app.zcat.stargate.libc;

import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.*;
import org.junit.jupiter.api.Test;

class LocalProcessesTest {
    @Test void capturesIdentityPublishedBetweenFileReadAndLeaderExit() {
        assertDoesNotThrow(() -> captureExitedLeader(true));
    }
    @Test void exitedLeaderWithoutPublishedIdentityFailsClosed() {
        IOException failure = assertThrows(IOException.class, () -> captureExitedLeader(false));
        assertEquals("Local process session identity was not captured", failure.getMessage());
    }
    private static void captureExitedLeader(boolean publish) throws Exception {
        // Exercise the exact observation boundary without scheduler timing or a real process.
        // The cancellation tests separately verify actual orphan/pipe cleanup.
        var type = Class.forName("app.zcat.stargate.libc.LocalProcesses$Session");
        var constructor = type.getDeclaredConstructor(); constructor.setAccessible(true);
        var session = constructor.newInstance();
        var groupField = type.getDeclaredField("groupFile"); groupField.setAccessible(true);
        Path group = (Path)groupField.get(session);
        var processField = type.getDeclaredField("process"); processField.setAccessible(true);
        processField.set(session, new Process() {
            @Override public boolean isAlive() {
                if (publish) {
                    // An already exited synthetic leader has no /proc entry to inspect.
                    try { Files.writeString(group, Long.toString(Long.MAX_VALUE)); }
                    catch (IOException failure) { throw new UncheckedIOException(failure); }
                }
                return false;
            }
            @Override public OutputStream getOutputStream() { return OutputStream.nullOutputStream(); }
            @Override public InputStream getInputStream() { return InputStream.nullInputStream(); }
            @Override public InputStream getErrorStream() { return InputStream.nullInputStream(); }
            @Override public int waitFor() { return 0; }
            @Override public int exitValue() { return 0; }
            @Override public void destroy() { }
        });
        try {
            var capture = type.getDeclaredMethod("capture"); capture.setAccessible(true);
            try { capture.invoke(session); }
            catch (InvocationTargetException failure) {
                if (failure.getCause() instanceof Exception cause) throw cause;
                throw failure;
            }
        } finally {
            Files.deleteIfExists(group); Files.delete(group.getParent());
        }
    }
}
