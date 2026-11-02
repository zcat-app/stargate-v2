// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OfflineRecoveryGateTest {
    @TempDir Path directory;

    @Test void gateRejectsAnyIncompleteMarkerIncludingDanglingLinks() throws Exception {
        Supervisor.requireRecoveryComplete(directory);
        Files.writeString(directory.resolve("recovery-incomplete"), "");
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
        Files.delete(directory.resolve("recovery-incomplete"));
        Files.createSymbolicLink(directory.resolve("recovery-incomplete"), directory.resolve("missing"));
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
    }

    @Test void identityGateRejectsRegularFileAndDanglingLink() throws Exception {
        Path marker = directory.resolve("identity-recovery-incomplete");
        Files.writeString(marker, "incomplete\n");
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
        Files.delete(marker);
        Files.createSymbolicLink(marker, directory.resolve("missing"));
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
    }

    @Test void importGateRejectsPartialFilesDirectoriesAndDanglingLinksWithoutCredentialGate() throws Exception {
        Path marker = directory.resolve("volume-import-incomplete");
        Files.writeString(marker, "");
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
        Files.delete(marker); Files.createDirectory(marker);
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
        Files.delete(marker); Files.createSymbolicLink(marker, directory.resolve("missing"));
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
    }

    @Test void importGateStopsSupervisorBeforeAnyInitialization() throws Exception {
        Files.writeString(directory.resolve("volume-import-incomplete"), "partial");
        IOException failure = assertThrows(IOException.class, () -> Supervisor.main(new String[]{
                directory.resolve("no-application").toString(), directory.toString(), directory.resolve("run").toString()}));
        assertEquals("OFFLINE_RECOVERY_INCOMPLETE", failure.getMessage());
        assertFalse(Files.exists(directory.resolve("admin-token")));
        assertFalse(Files.exists(directory.resolve("proxy.properties")));
        assertFalse(Files.exists(directory.resolve("run")));
    }

    @Test void preparingFileAlsoGatesInitializationIncludingDanglingLinks() throws Exception {
        Path preparing = directory.resolve("identity-recovery-preparing");
        Files.writeString(preparing, "partial");
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
        Files.delete(preparing);Files.createSymbolicLink(preparing, directory.resolve("missing"));
        assertThrows(IOException.class, () -> Supervisor.requireRecoveryComplete(directory));
    }

    @Test void supervisorFailsBeforeInitializationOrListenersWhenRecoveryIsIncomplete() throws Exception {
        Path data = directory.resolve("data");Files.createDirectory(data);
        Path marker = data.resolve("recovery-incomplete");Files.writeString(marker, "incomplete\n");
        Path run = directory.resolve("run");
        // Invalid application path would fail later in initialization. The marker must fail first.
        IOException failure = assertThrows(IOException.class, () -> Supervisor.main(new String[]{
                directory.resolve("no-application").toString(), data.toString(), run.toString()}));
        assertEquals("OFFLINE_RECOVERY_INCOMPLETE", failure.getMessage());
        assertFalse(Files.exists(data.resolve("admin-token")));
        assertFalse(Files.exists(data.resolve("proxy.properties")));
        assertFalse(Files.exists(run));
    }
}
