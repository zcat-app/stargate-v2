// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import static org.junit.jupiter.api.Assertions.*;

class DockerTransportTest {
    @TempDir Path temp;
    @Test void forcesLocalSocketAndRejectsUnsuccessfulOrTimedOutCalls() throws Exception {
        Path fake = temp.resolve("fake-docker");
        Files.writeString(fake, "#!/bin/sh\n[ \"$1\" = --host ] && [ \"$2\" = unix:///var/run/docker.sock ] || exit 8\nshift 2\ncase \"$1\" in ok) printf '[{\"Id\":\"synthetic\"}]';; slow) exec /bin/sleep 3;; flood) exec /usr/bin/head -c 1048577 /dev/zero;; *) exit 9;; esac\n");
        Files.setPosixFilePermissions(fake, PosixFilePermissions.fromString("rwx------"));
        DockerTransport client = new DockerTransport.ProcessClient(fake.toString());
        assertEquals("[{\"Id\":\"synthetic\"}]", client.call(2, "ok"));
        assertThrows(Exception.class, () -> client.call(2, "bad"));
        assertThrows(Exception.class, () -> client.call(1, "slow"));
        assertThrows(Exception.class, () -> client.call(2, "flood"));
    }
}
