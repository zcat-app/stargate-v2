// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ManagerSettingsTest {
    @TempDir Path directory;
    @Test void privateConfigurationRestrictsCommandsAndEndpoints() throws Exception {
        Path proxy = directory.resolve("proxy");write(proxy, "listen.port=8881\ntor.port=9050\n");
        Path manager = directory.resolve("manager");String config = "manager.token=" + "a".repeat(43) + "\nproxy.config=" + proxy + "\ntor.control.port=9051\ntor.cookie=" + directory.resolve("cookie") + "\n";
        write(manager, config);assertEquals("stargate-v2-proxy.service", ManagerSettings.load(manager).unit());
        assertNull(ManagerSettings.load(manager).upgradeDirectory());
        write(manager,config+"upgrade.directory=relative\n");assertThrows(IllegalArgumentException.class,()->ManagerSettings.load(manager));
        write(manager,config+"upgrade.directory=/run/stargate-upgrade\n");assertEquals(Path.of("/run/stargate-upgrade"),ManagerSettings.load(manager).upgradeDirectory());
        write(manager, config + "proxy.unit=ssh.service\n");assertThrows(IllegalArgumentException.class, () -> ManagerSettings.load(manager));
        write(manager, config + "tor.control.host=example.com\n");assertThrows(IllegalArgumentException.class, () -> ManagerSettings.load(manager));
        write(manager, config);Files.setPosixFilePermissions(manager, PosixFilePermissions.fromString("rw-r--r--"));
        assertThrows(IllegalArgumentException.class, () -> ManagerSettings.load(manager));
    }
    @Test void privateConfigurationReadIsByteBoundedBeforeParsing() throws Exception {
        Path config = directory.resolve("config");
        String prefix = "name=café\n#";
        int prefixBytes = prefix.getBytes(StandardCharsets.UTF_8).length;
        write(config, prefix + "x".repeat(262144 - prefixBytes));
        assertEquals(262144, Files.size(config));
        assertEquals("café", ManagerSettings.privateProperties(config).getProperty("name"));

        // An invalid escape would fail parsing if the oversized contents were parsed first.
        write(config, "bad=\\uXXXX\n#" + "x".repeat(262144));
        IOException error = assertThrows(IOException.class, () -> ManagerSettings.privateProperties(config));
        assertEquals("CONFIGURATION_TOO_LARGE", error.getMessage());

        write(config, prefix + "x".repeat(262145 - prefixBytes));
        assertEquals(262145, Files.size(config));
        assertEquals("CONFIGURATION_TOO_LARGE", assertThrows(IOException.class,
                () -> ManagerSettings.privateProperties(config)).getMessage());
    }

    @Test void oversizedProxyConfigurationIsRejectedByManagerLoad() throws Exception {
        Path proxy = directory.resolve("proxy");
        write(proxy, "#" + "x".repeat(262144));
        Path manager = directory.resolve("manager");
        write(manager, "manager.token=" + "a".repeat(43) + "\nproxy.config=" + proxy
                + "\ntor.control.port=9051\ntor.cookie=" + directory.resolve("cookie") + "\n");
        assertEquals("CONFIGURATION_TOO_LARGE", assertThrows(IOException.class,
                () -> ManagerSettings.load(manager)).getMessage());
    }

    @Test void privateConfigurationDoesNotFollowSymlinks() throws Exception {
        Path config = directory.resolve("config");
        write(config, "name=value\n");
        Path link = directory.resolve("link");
        Files.createSymbolicLink(link, config);
        assertEquals("CONFIGURATION_MUST_BE_REGULAR_FILE", assertThrows(IOException.class,
                () -> ManagerSettings.privateProperties(link)).getMessage());
    }

    @Test void privateConfigurationRejectsFifoWithoutBlocking() throws Exception {
        Path fifo = directory.resolve("fifo");
        Process mkfifo = new ProcessBuilder("mkfifo", "-m", "600", fifo.toString()).start();
        assertEquals(0, mkfifo.waitFor());
        var executor = Executors.newSingleThreadExecutor(task -> {
            Thread thread = new Thread(task);
            thread.setDaemon(true);
            return thread;
        });
        try {
            var result = executor.submit(() -> assertThrows(IOException.class,
                    () -> ManagerSettings.privateProperties(fifo)).getMessage());
            assertEquals("CONFIGURATION_MUST_BE_REGULAR_FILE", result.get(2, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }
    @Test void releaseMonitorRequiresAnExplicitAbsolutePathAndBound() throws Exception {
        Path proxy = directory.resolve("proxy"); write(proxy, "listen.port=8881\ntor.port=9050\n");
        Path manager = directory.resolve("manager");
        String base = "manager.token=" + "a".repeat(43) + "\nproxy.config=" + proxy + "\ntor.control.port=9051\ntor.cookie=" + directory.resolve("cookie") + "\n";
        write(manager, base); assertNull(ManagerSettings.load(manager).releaseSnapshot());
        for (String option : new String[]{"release.snapshot=/tmp/x\n", "release.max-age-seconds=5\n", "release.snapshot=relative\nrelease.max-age-seconds=5\n", "release.snapshot=/tmp/x\nrelease.max-age-seconds=0\n", "release.snapshot=/tmp/x\nrelease.max-age-seconds=31536001\n"}) {
            write(manager, base + option); assertThrows(IllegalArgumentException.class, () -> ManagerSettings.load(manager));
        }
        write(manager, base + "release.snapshot=/tmp/x\nrelease.max-age-seconds=60\n");
        assertEquals(60, ManagerSettings.load(manager).releaseMaxAge());
    }
    @Test void consumerMonitorRequiresAnExplicitAbsolutePathAndBound() throws Exception {
        Path proxy = directory.resolve("proxy"); write(proxy, "listen.port=8881\ntor.port=9050\n");
        Path manager = directory.resolve("manager");
        String base = "manager.token=" + "a".repeat(43) + "\nproxy.config=" + proxy + "\ntor.control.port=9051\ntor.cookie=" + directory.resolve("cookie") + "\n";
        write(manager, base); assertNull(ManagerSettings.load(manager).consumerSnapshot());
        for (String option : new String[]{"consumer.snapshot=/tmp/x\n", "consumer.max-age-seconds=5\n", "consumer.snapshot=relative\nconsumer.max-age-seconds=5\n", "consumer.snapshot=/tmp/x\nconsumer.max-age-seconds=0\n", "consumer.snapshot=/tmp/x\nconsumer.max-age-seconds=31536001\n"}) {
            write(manager, base + option); assertThrows(IllegalArgumentException.class, () -> ManagerSettings.load(manager));
        }
        write(manager, base + "consumer.snapshot=/tmp/x\nconsumer.max-age-seconds=60\n");
        assertEquals(60, ManagerSettings.load(manager).consumerMaxAge());
    }
    private static void write(Path path, String value) throws Exception { Files.writeString(path, value);Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")); }
}
