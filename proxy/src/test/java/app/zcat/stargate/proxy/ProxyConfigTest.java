// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import static org.junit.jupiter.api.Assertions.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProxyConfigTest {
    @TempDir Path directory;
    private static final String TOKEN = "a".repeat(43);

    @Test void devicePortsAreUniqueAndMissingAssignmentsStayUnavailable() throws Exception {
        var missing = ProxyConfig.loadProfiles(write("i2p.deviceIsolation=true\n"));
        assertEquals(0, missing.get("browser").i2pPort());
        var assigned = ProxyConfig.loadProfiles(write("i2p.deviceIsolation=true\nprofile.browser.i2pPort=14447\n"));
        assertEquals(14447, assigned.get("browser").i2pPort());
        var disabled = ProxyConfig.loadProfiles(write("i2p.deviceIsolation=true\nprofile.browser.i2pPort=14447\nprofile.browser.i2pEnabled=false\n"));
        assertEquals(0, disabled.get("browser").i2pPort());
        assertTrue(missing.get("browser").sameCredential(assigned.get("browser")));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.loadProfiles(write("i2p.deviceIsolation=true\nprofile.browser.i2pPort=14447\nprofile.other.token=" + TOKEN + "\nprofile.other.i2pPort=14447\n")));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.loadProfiles(write("i2p.deviceIsolation=true\nprofile.browser.i2pPort=4447\n")));
    }

    @Test void exhaustedCounterIsAcceptedAndOnlyIsolatedUnallocatedProfilesAreUnavailable() throws Exception {
        for (boolean isolated : new boolean[]{true, false}) {
            Path path = write("i2p.nextPort=65536\ni2p.deviceIsolation=" + isolated
                    + "\ni2p.host=127.0.0.1\nnym.enabled=true\n");
            var config = ProxyConfig.load(path);
            String basic = "Basic " + Base64.getEncoder().encodeToString(("browser:" + TOKEN).getBytes(StandardCharsets.US_ASCII));
            var profile = config.authenticate(basic);
            assertNotNull(profile);
            assertEquals(isolated ? 0 : -1, profile.i2pPort());
            assertEquals(9050, config.tor().getPort());
            assertEquals(4447, config.i2p().getPort());
            assertEquals(1080, config.nym().getPort());
        }
    }

    @Test void independentHmacVectorAndProfileSeparation() {
        // Computed independently with Python hmac/hashlib, not with the Java helper.
        HmacPartition hmac = new HmacPartition(new byte[32]);
        assertEquals("sg2:4760dd732e9566711a83c647963cd83ca65ca357604ee448a95fa2fdfc12a15c", hmac.forProfile("browser"));
        assertNotEquals(hmac.forProfile("browser"), hmac.forProfile("other"));
        assertEquals(68, hmac.forProfile("browser").length());
    }

    @Test void privateConfigurationLoadsAndAuthenticates() throws Exception {
        Path path = write("");ProxyConfig config = ProxyConfig.load(path);
        String correct = "Basic " + Base64.getEncoder().encodeToString(("browser:" + TOKEN).getBytes(StandardCharsets.US_ASCII));
        assertNotNull(config.authenticate(correct));assertNull(config.authenticate(correct + "!"));
        assertNull(config.authenticate("Bearer " + TOKEN));
        assertNull(config.i2p());
        assertEquals(8881, config.listen().getPort());
    }

    @Test void exposedSecretsUnknownSettingsAndNonLoopbackAreRejected() throws Exception {
        Path insecure = write("");Files.setPosixFilePermissions(insecure, PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(insecure));
        Path unknown = write("unrecognized.option=true\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(unknown));
        Path remote = write("tor.host=example.com\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(remote));
    }

    @Test void containerNetworkIsExplicitAndCannotTargetAPublicUpstream() throws Exception {
        Path ordinary = write("listen.host=0.0.0.0\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(ordinary));
        Path allowed = write("network.mode=container\nlisten.host=0.0.0.0\ntor.host=172.20.0.2\nmetrics.path=" + directory.resolve("traffic.json") + "\n");
        assertTrue(ProxyConfig.load(allowed).containerNetwork());
        Path publicTor = write("network.mode=container\ntor.host=8.8.8.8\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(publicTor));
        Path relativeMetrics = write("metrics.path=traffic.json\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(relativeMetrics));
        Path i2p = write("i2p.host=127.0.0.1\ni2p.port=4447\ni2pSetupTimeoutMillis=90000\n");
        assertEquals(4447, ProxyConfig.load(i2p).i2p().getPort());
        assertEquals(90000, ProxyConfig.load(i2p).i2pSetupTimeoutMillis());
        Path publicI2p = write("network.mode=container\ni2p.host=8.8.8.8\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(publicI2p));
        Path zeroTimeout = write("i2pSetupTimeoutMillis=0\n");
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(zeroTimeout));
    }

    @Test void nymRequiresExplicitOptInAndPrivateEndpoint() throws Exception {
        assertNull(ProxyConfig.load(write("nym.host=127.0.0.1\nnym.port=1080\n")).nym());
        assertEquals(1080, ProxyConfig.load(write("nym.enabled=true\n")).nym().getPort());
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(write("nym.enabled=yes\n")));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(write("nym.enabled=true\nnetwork.mode=container\nnym.host=8.8.8.8\n")));
        assertThrows(IllegalArgumentException.class, () -> ProxyConfig.load(write("nymSetupTimeoutMillis=0\n")));
    }

    @Test void credentialRefreshDoesNotResolveOrDependOnNetworkEndpoints() throws Exception {
        Path path = write("network.mode=container\ntor.host=must-not-resolve.invalid\ni2p.host=must-not-resolve.invalid\nnym.enabled=true\nnym.host=must-not-resolve.invalid\n");
        assertEquals(java.util.Set.of("browser"), ProxyConfig.loadProfiles(path).keySet());
        Files.writeString(path, "isolation.key=" + "00".repeat(32) + "\nnetwork.mode=container\ntor.host=must-not-resolve.invalid\n");
        assertTrue(ProxyConfig.loadProfiles(path).isEmpty());
    }

    @Test void reloadAcceptsAndAuthenticatesMoreThan128Profiles() throws Exception {
        Path path = write("");
        ProxyConfig initial = ProxyConfig.load(path);
        var text = new StringBuilder(Files.readString(path));
        for (int i = 0; i < 128; i++) text.append("profile.device").append(i).append(".token=").append(TOKEN).append('\n');
        Files.writeString(path, text);
        var reloaded = ProxyConfig.loadProfiles(path);
        assertEquals(129, reloaded.size());
        String basic = "Basic " + Base64.getEncoder().encodeToString(("device127:" + TOKEN).getBytes(StandardCharsets.US_ASCII));
        assertNotNull(ProxyConfig.authenticate(basic, reloaded));
        assertEquals(129, ProxyConfig.load(path).profiles().size());
        assertEquals(1, initial.profiles().size());
        try (var proxy = new ProxyServer(initial, path)) {
            var refresh = ProxyServer.class.getDeclaredMethod("refreshCredentials");refresh.setAccessible(true);refresh.invoke(proxy);
            var field = ProxyServer.class.getDeclaredField("credentials");field.setAccessible(true);
            Object credentials = field.get(proxy);
            var byId = credentials.getClass().getDeclaredMethod("byId");byId.setAccessible(true);
            @SuppressWarnings("unchecked") var live = (java.util.Map<String, ProxyConfig.Profile>) byId.invoke(credentials);
            assertEquals(129, live.size());assertNotNull(ProxyConfig.authenticate(basic, live));
        }
    }

    private Path write(String extra) throws Exception {
        Path path = directory.resolve("proxy.properties");
        Files.writeString(path, "isolation.key=" + "00".repeat(32) + "\nprofile.browser.token=" + TOKEN + "\n" + extra);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));return path;
    }
}
