// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HandoffSerializationTest {
    @Test void overrideBytesAreStableAcrossJvmProcesses() throws Exception {
        String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        String expected = "{\"name\":\"synthetic-project\",\"volumes\":{\"app-data\":{\"external\":true,\"name\":\"synthetic-app\"},\"nym-data\":{\"external\":true,\"name\":\"synthetic-nym\"}}}\n";
        for (int attempt = 0; attempt < 8; attempt++) {
            Process process = new ProcessBuilder(java, "-cp", classpath, HandoffSerializationProbe.class.getName())
                    .redirectError(ProcessBuilder.Redirect.INHERIT).start();
            assertTrue(process.waitFor(10, TimeUnit.SECONDS));
            assertEquals(0, process.exitValue());
            assertEquals(expected, new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8));
        }
    }
}
