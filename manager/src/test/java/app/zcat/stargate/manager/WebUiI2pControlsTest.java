// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WebUiI2pControlsTest {
    @TempDir Path directory;

    @Test void unavailableAllocationHidesEnableButPreservesPairingRevocationAndExistingStop() throws Exception {
        String unallocated = render("i2p.deviceIsolation=true\ni2p.nextPort=65536\n");
        assertTrue(unallocated.contains("unavailable; inspect configuration"));
        assertFalse(unallocated.contains("Enable I2P for device"));
        assertFalse(unallocated.contains("Stop I2P for device"));
        assertTrue(unallocated.contains("Create one-time code"));
        assertTrue(unallocated.contains("Revoke device"));
        assertTrue(unallocated.contains("Local lifecycle observation unavailable"));

        String existingRoute = render("i2p.deviceIsolation=true\ni2p.nextPort=invalid\nprofile.browser.i2pPort=14447\n");
        assertTrue(existingRoute.contains("unavailable; inspect configuration"));
        assertTrue(existingRoute.contains("Stop I2P for device"));
        assertFalse(existingRoute.contains("Enable I2P for device"));
    }

    @Test void healthyIsolatedControlsAndSharedModeRemainUnchanged() throws Exception {
        String stopped = render("i2p.deviceIsolation=true\ni2p.nextPort=14448\nprofile.browser.i2pPort=14447\nprofile.browser.i2pEnabled=false\n");
        assertTrue(stopped.contains("Enable I2P for device"));
        assertFalse(stopped.contains("Stop I2P for device"));
        String enabled = render("i2p.deviceIsolation=true\ni2p.nextPort=14448\nprofile.browser.i2pPort=14447\n");
        assertTrue(enabled.contains("Stop I2P for device"));
        assertFalse(enabled.contains("Enable I2P for device"));
        String shared = render("i2p.deviceIsolation=false\ni2p.nextPort=65536\n");
        assertFalse(shared.contains("Enable I2P for device"));
        assertFalse(shared.contains("Stop I2P for device"));
        assertTrue(shared.contains("Create one-time code"));
        assertTrue(shared.contains("Revoke device"));
    }

    @Test void exhaustedMixedFleetCanResumeOnlyValidatedAssignedDevice() throws Exception {
        String mixed = "i2p.deviceIsolation=true\ni2p.nextPort=65536\nprofile.browser.i2pPort=14447\nprofile.browser.i2pEnabled=false\n"
                + "profile.unallocated.token=" + "c".repeat(43) + "\n"
                + "profile.running.token=" + "d".repeat(43) + "\nprofile.running.i2pPort=14448\n";
        String html = render(mixed);
        assertTrue(html.contains("unavailable; inspect configuration"));
        assertTrue(i2pForm(html, "browser").contains("Enable I2P for device"));
        assertEquals("", i2pForm(html, "unallocated"));
        assertTrue(i2pForm(html, "running").contains("Stop I2P for device"));

        for (String corrupt : new String[]{
                mixed.replace("i2p.nextPort=65536", "i2p.nextPort=invalid"),
                mixed.replace("i2p.nextPort=65536", "i2p.nextPort=65537"),
                mixed.replace("profile.running.i2pPort=14448", "profile.running.i2pPort=14447"),
                mixed.replace("profile.running.i2pPort=14448", "profile.running.i2pPort=65536"),
                mixed.replace("profile.running.i2pPort=14448", "profile.running.i2pPort=invalid"),
                mixed + "profile.unallocated.i2pEnabled=invalid\n"}) {
            String invalid = render(corrupt);
            assertTrue(invalid.contains("unavailable; inspect configuration"));
            assertEquals("", i2pForm(invalid, "browser"));
            assertEquals("", i2pForm(invalid, "unallocated"));
        }
    }

    private static String i2pForm(String html, String id) {
        return java.util.regex.Pattern.compile("<form[^>]*action=\"/devices/i2p\"[^>]*>.*?</form>")
                .matcher(html).results().map(java.util.regex.MatchResult::group)
                .filter(form -> form.contains("name=\"deviceId\" value=\"" + id + "\""))
                .findFirst().orElse("");
    }

    private String render(String configuration) throws Exception {
        Path proxy = directory.resolve("proxy.properties");
        privateFile(proxy, "network.mode=container\n" + configuration + "profile.browser.token=" + "a".repeat(43)
                + "\ni2p.lifecycleDirectory=" + directory.resolve("lifecycle") + "\n");
        Path managerFile = directory.resolve("manager.properties");
        privateFile(managerFile, "manager.token=" + "b".repeat(43) + "\nproxy.config=" + proxy
                + "\nproxy.control.socket=" + directory.resolve("unused.sock")
                + "\ntor.cookie=" + directory.resolve("cookie") + "\ntor.control.port=9051\n");
        // Render the real UI with real allocation state; substitute observations so no
        // socket, process-control request or native service participates in this test.
        var manager = new ManagerService(managerFile.toString(), "0.0.0.0", 9080) {
            @Override public Status status() {
                return new Status("synthetic", "SUPERVISOR", null,
                        new ProxyControl.Unit("synthetic", "loaded", "inactive", "dead", 0L, null, null, null, null),
                        new ProxyObservation("REFUSED", "synthetic", false),
                        new TorProbe.Observation(TorProbe.Health.UNAVAILABLE, "synthetic", null, null, null, null, null, null, null, null),
                        new I2pProbe.Observation("UNAVAILABLE", "synthetic", null, null, null, null, null, null, null, "UNKNOWN"),
                        new NymProbe.Observation("DISABLED", null, "UNKNOWN"), null);
            }
            @Override public String i2pLifecycleObservation() { return "synthetic"; }
        };
        try { return WebUi.page(manager, manager.sessions().create(), null, null); }
        finally { manager.closeI2pConfiguration(); }
    }

    private static void privateFile(Path path, String content) throws Exception {
        Files.writeString(path, content);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
}
