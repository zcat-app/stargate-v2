// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;
import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
class I2pDevicesTest {
    @TempDir Path directory;
    DeviceCredentials store() throws Exception {
        Path p=directory.resolve("proxy.properties");
        if(!Files.exists(p)) { Files.writeString(p,"i2p.deviceIsolation=true\ni2p.nextPort=14447\n");Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rw-------")); }
        return new DeviceCredentials(p,directory.resolve("tunnels.conf"));
    }
    @Test void mappingsSurviveRestartAndRevokedPortsAreNeverReused() throws Exception {
        var s=store();var a=s.create("same");var b=s.create("same");assertEquals(14447,s.i2pPort(a.id()));assertEquals(14448,s.i2pPort(b.id()));
        s.reconcileI2p();int ap=s.i2pPort(a.id()),bp=s.i2pPort(b.id());assertNotEquals(ap,bp);
        store().reconcileI2p();assertEquals(ap,store().i2pPort(a.id()));
        s.revoke(a.id());var c=s.create("same");s.reconcileI2p();assertTrue(s.i2pPort(c.id())>Math.max(ap,bp));assertEquals(bp,s.i2pPort(b.id()));
        assertFalse(Files.exists(directory.resolve("tunnels.conf")));
    }
    @Test void managerNeverPublishesFleetAndEnablePreservesMapping() throws Exception {
        var s=store();var a=s.create("A");var b=s.create("B");s.reconcileI2p();int ap=s.i2pPort(a.id()),bp=s.i2pPort(b.id());
        Path fleet=directory.resolve("tunnels.conf");Files.writeString(fleet,"proxy-owned live fleet");
        s.setI2pEnabled(a.id(),false);s.reconcileI2p();assertEquals(0,s.i2pPort(a.id()));assertEquals(bp,s.i2pPort(b.id()));
        s.setI2pEnabled(a.id(),true);store().reconcileI2p();assertEquals(ap,s.i2pPort(a.id()));assertEquals("proxy-owned live fleet",Files.readString(fleet));
    }
    @Test void moreThan128PairWithoutAllocatingTunnels() throws Exception {
        var s=store();for(int n=0;n<12;n++)s.create("device");s.requireCapacity();s.reconcileI2p();assertEquals(12,s.tokens().size());assertFalse(Files.exists(directory.resolve("tunnels.conf")));
        for(int n=12;n<129;n++)s.create("device");s.requireCapacity();s.reconcileI2p();assertEquals(129,store().tokens().size());assertFalse(Files.exists(directory.resolve("tunnels.conf")));
    }
    @Test void oversizedI2pMutationsLeaveOriginalConfigurationIntact() throws Exception {
        var s = store();Path path = directory.resolve("proxy.properties");
        var properties = new java.util.Properties();
        properties.setProperty("i2p.deviceIsolation", "true");properties.setProperty("i2p.nextPort", "14447");
        properties.setProperty("profile.existing.token", "a".repeat(43));
        properties.setProperty("nym.host", "x".repeat(261900));
        try (var writer = Files.newBufferedWriter(path)) { properties.store(writer, "Stargate private configuration"); }
        int padding = 262140 - (int) Files.size(path);
        assertTrue(padding > 0);properties.setProperty("nym.host", properties.getProperty("nym.host") + "x".repeat(padding));
        try (var writer = Files.newBufferedWriter(path)) { properties.store(writer, "Stargate private configuration"); }
        byte[] before = Files.readAllBytes(path);assertEquals(262140, before.length);
        assertThrows(IllegalStateException.class, () -> s.setI2pEnabled("existing", false));
        assertArrayEquals(before, Files.readAllBytes(path));
        assertThrows(IllegalStateException.class, s::reconcileI2p);
        assertArrayEquals(before, Files.readAllBytes(path));
        assertEquals(1, s.tokens().size());
    }
    @Test void exhaustedMixedFleetCanResumeSavedMappingWithoutAllocatingOrWritingDuringValidation() throws Exception {
        var s=store();Path p=directory.resolve("proxy.properties");
        Files.writeString(p,"i2p.deviceIsolation=true\ni2p.nextPort=65536\nprofile.assigned.token="+"a".repeat(43)
                +"\nprofile.assigned.i2pPort=14447\nprofile.assigned.i2pEnabled=false\nprofile.unallocated.token="+"b".repeat(43)+"\n");
        String before=Files.readString(p);
        assertThrows(IllegalStateException.class,s::reconcileI2p);
        assertTrue(s.canEnableI2p("assigned", false));
        assertFalse(s.canEnableI2p("unallocated", false));
        assertFalse(s.canEnableI2p("unallocated", true));
        assertFalse(s.canEnableI2p("missing", false));
        assertEquals(before,Files.readString(p));
        s.setI2pEnabled("assigned",true);assertEquals(14447,s.i2pPort("assigned"));
        assertThrows(IllegalStateException.class,s::reconcileI2p);
        assertEquals(0,s.i2pPort("unallocated"));
        assertTrue(Files.readString(p).contains("i2p.nextPort=65536"));
        assertFalse(Files.readString(p).contains("profile.unallocated.i2pPort="));
        assertFalse(Files.exists(directory.resolve("tunnels.conf")));
    }
    @Test void corruptExhaustedFleetCannotEnableSavedMapping() throws Exception {
        var s=store();Path p=directory.resolve("proxy.properties");
        String valid="i2p.deviceIsolation=true\ni2p.nextPort=65536\nprofile.assigned.token="+"a".repeat(43)
                +"\nprofile.assigned.i2pPort=14447\nprofile.assigned.i2pEnabled=false\nprofile.other.token="+"b".repeat(43)+"\n";
        for(String corrupt:new String[]{valid+"profile.other.i2pPort=14447\n", valid+"profile.other.i2pPort=not-a-port\n",
                valid+"profile.other.i2pEnabled=invalid\n",valid.replace("65536","65537"),
                valid.replace("14447","14446"),valid.replace("profile.assigned.token="+"a".repeat(43),"profile.assigned.token=bad")}) {
            Files.writeString(p,corrupt);
            assertFalse(s.canEnableI2p("assigned", false));
            assertFalse(s.canEnableI2p("assigned", true));
            assertThrows(IllegalStateException.class,s::reconcileI2p);
            assertEquals("DEVICE_STORE_UNAVAILABLE", assertThrows(IllegalStateException.class, () -> s.create("fresh")).getMessage());
            assertEquals(corrupt,Files.readString(p));
        }
    }
    @Test void lastPortIsAllocatedOnceAndInsufficientHistoricalCapacityNeverPublishesPartialChanges() throws Exception {
        var s=store();Path p=directory.resolve("proxy.properties");
        Files.writeString(p,"i2p.deviceIsolation=true\ni2p.nextPort=65535\nprofile.saved.token="+"a".repeat(43)
                +"\nprofile.saved.i2pPort=14447\nprofile.saved.i2pEnabled=false\n");
        String before=Files.readString(p);
        // Both the legacy unallocated credential and the new credential need the one remaining port.
        Files.writeString(p,before+"profile.legacy.token="+"b".repeat(43)+"\n");
        String insufficient=Files.readString(p);
        assertThrows(IllegalStateException.class,()->s.create("fresh"));
        assertEquals(insufficient,Files.readString(p));
        Files.writeString(p,before);
        var last=s.create("last");assertEquals(65535,s.i2pPort(last.id()));
        assertTrue(Files.readString(p).contains("i2p.nextPort=65536"));
        assertEquals(0,s.i2pPort("saved"));
        s.setI2pEnabled("saved",true);assertEquals(14447,s.i2pPort("saved"));
        String exhausted=Files.readString(p);
        assertThrows(IllegalStateException.class,()->s.create("fresh"));
        assertEquals(exhausted,Files.readString(p));
        assertTrue(s.revoke(last.id()));
        String revoked=Files.readString(p);
        assertThrows(IllegalStateException.class,()->s.create("fresh"));
        assertEquals(revoked,Files.readString(p));
        assertFalse(Files.exists(directory.resolve("tunnels.conf")));
    }
    @Test void malformedSequenceDoesNotOverwriteLiveFleet() throws Exception {
        var s=store();s.create("A");s.reconcileI2p();Path p=directory.resolve("proxy.properties");Files.writeString(p,Files.readString(p).replaceAll("i2p.nextPort=[0-9]+","i2p.nextPort=14447"));
        Files.writeString(directory.resolve("tunnels.conf"),"proxy-owned");assertThrows(IllegalStateException.class,s::reconcileI2p);assertEquals("proxy-owned",Files.readString(directory.resolve("tunnels.conf")));
    }
}
