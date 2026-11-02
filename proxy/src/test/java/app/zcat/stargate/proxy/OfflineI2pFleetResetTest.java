// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OfflineI2pFleetResetTest {
    @TempDir Path root;
    Path app, control, fleet, gate;
    void setup() throws Exception {
        app = Files.createDirectory(root.resolve("app")); control = Files.createDirectory(root.resolve("control"));
        Files.setPosixFilePermissions(app, PosixFilePermissions.fromString("rwx------"));
        Files.setPosixFilePermissions(control, PosixFilePermissions.fromString("rwx------"));
        file(app.resolve("proxy-desired"), "stopped\n"); file(app.resolve("proxy.properties"), "port=14447\n");
        fleet = control.resolve("tunnels.conf"); file(fleet, "[device-old]\nport=14447\nkeys=device-old.dat\n");
        gate = app.resolve(OfflineI2pFleetReset.GATE);
    }
    void file(Path p, String text) throws Exception { Files.writeString(p, text); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); }
    void reset() throws Exception { OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO()); }

    @Test void resetsOnlyFleet() throws Exception {
        setup(); file(control.resolve("password"), "keep"); reset();
        assertEquals("", Files.readString(fleet)); assertEquals("keep", Files.readString(control.resolve("password")));
        assertEquals("port=14447\n", Files.readString(app.resolve("proxy.properties"))); assertFalse(Files.exists(gate));
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(fleet));
    }
    @Test void failedGateCreationNeverMutatesFleetAndPartialGateIsNotAdopted() throws Exception {
        setup(); assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            @Override void createGate(Path p) throws IOException { Files.writeString(p, "I2P-"); Files.setPosixFilePermissions(p, PosixFilePermissions.fromString("rw-------")); throw new IOException("injected"); }
        }));
        assertTrue(Files.readString(fleet).contains("device-old")); assertThrows(IOException.class, this::reset);
        assertEquals("I2P-", Files.readString(gate));
    }
    @Test void failedReplaceAndDirectorySyncRetainGateAndRetry() throws Exception {
        setup(); assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            @Override void replace(Path t, Path f) throws IOException { throw new IOException("injected"); }
        }));
        assertTrue(Files.readString(fleet).contains("device-old")); assertTrue(Files.exists(gate));
        assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            @Override void forceDirectory(Path p) throws IOException { if (p.equals(control)) throw new IOException("injected"); super.forceDirectory(p); }
        }));
        assertEquals("", Files.readString(fleet)); assertTrue(Files.exists(gate)); reset(); assertFalse(Files.exists(gate));
    }
    @Test void gateDirectorySyncFailurePrecedesFleetMutationAndCanBeRetried() throws Exception {
        setup(); assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            @Override void forceDirectory(Path p) throws IOException { if (p.equals(app)) throw new IOException("injected"); super.forceDirectory(p); }
            @Override void replace(Path t, Path f) { fail("fleet must not be replaced before gate sync"); }
        }));
        assertTrue(Files.readString(fleet).contains("device-old"));
        assertArrayEquals(OfflineI2pFleetReset.PLAN, Files.readAllBytes(gate)); reset();
    }
    @Test void failedFinalSyncRestoresGateAndPersistentFailureRequiresOfflineInspection() throws Exception {
        setup(); assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            int calls;
            @Override void forceDirectory(Path p) throws IOException { if (p.equals(app) && ++calls == 2) throw new IOException("injected"); super.forceDirectory(p); }
        }));
        assertArrayEquals(OfflineI2pFleetReset.PLAN, Files.readAllBytes(gate)); reset();
        assertThrows(IOException.class, () -> OfflineI2pFleetReset.reset(app, control, new OfflineI2pFleetReset.IO() {
            int calls;
            @Override void forceDirectory(Path p) throws IOException { if (p.equals(app) && ++calls >= 2) throw new IOException("injected"); super.forceDirectory(p); }
            @Override void createGate(Path p) throws IOException { if (Files.size(fleet) == 0 && Files.exists(p) == false && calls >= 2) throw new IOException("repair failed"); super.createGate(p); }
        }));
        assertFalse(Files.exists(gate)); // Nonzero exit remains a failure even when repair was impossible.
    }
    @Test void rejectsUnsafeFilesAndOtherMarkers() throws Exception {
        setup(); file(gate, "I2P-IDENTITY-1\n"); assertThrows(IOException.class, this::reset); Files.delete(gate);
        Files.createSymbolicLink(gate, root.resolve("missing")); assertThrows(IOException.class, this::reset); Files.delete(gate);
        Path alias = control.resolve("alias"); Files.createLink(alias, fleet); assertThrows(IOException.class, this::reset); Files.delete(alias);
        Files.delete(fleet); Files.createSymbolicLink(fleet, root.resolve("missing")); assertThrows(IOException.class, this::reset); Files.delete(fleet);
        file(app.resolve("identity-recovery-preparing"), ""); assertThrows(IOException.class, this::reset);
    }

    @Test void incompleteImportCannotBeBypassedByFleetReset() throws Exception {
        setup(); Path marker = app.resolve("volume-import-incomplete");
        String original = Files.readString(fleet);
        for (String kind : new String[]{"partial-file", "dangling-link"}) {
            if (kind.equals("partial-file")) file(marker, "");
            else Files.createSymbolicLink(marker, root.resolve("missing"));
            assertThrows(IOException.class, this::reset);
            assertEquals(original, Files.readString(fleet));
            assertFalse(Files.exists(gate));
            assertTrue(Files.exists(marker, LinkOption.NOFOLLOW_LINKS));
            Files.delete(marker);
        }
    }
    @Test void supervisorRejectsFleetGateIncludingPartialRecord() throws Exception {
        setup();
        var check = Class.forName("app.zcat.stargate.runtime.Supervisor").getDeclaredMethod("requireRecoveryComplete", Path.class);
        check.setAccessible(true);
        for (String record : new String[]{"", "I2P-", new String(OfflineI2pFleetReset.PLAN)}) {
            file(gate, record);
            var error = assertThrows(java.lang.reflect.InvocationTargetException.class, () -> check.invoke(null, app));
            assertInstanceOf(IOException.class, error.getCause());
        }
    }
    @Test void otherRecoveryCommandsCannotClearCompleteFleetGate() throws Exception {
        setup(); file(gate, new String(OfflineI2pFleetReset.PLAN));
        assertThrows(IOException.class, () -> OfflineRecovery.prepare(app.resolve("proxy.properties"), new OfflineRecovery.AtomicFiles()));
        var identity = new OfflineI2pIdentityRecoveryTest(); identity.root = Files.createDirectory(root.resolve("identity")); identity.fixture();
        file(identity.app.resolve(OfflineI2pFleetReset.GATE), new String(OfflineI2pFleetReset.PLAN));
        assertThrows(Exception.class, identity::run);
        assertArrayEquals(OfflineI2pFleetReset.PLAN, Files.readAllBytes(identity.app.resolve(OfflineI2pFleetReset.GATE)));
    }
}
