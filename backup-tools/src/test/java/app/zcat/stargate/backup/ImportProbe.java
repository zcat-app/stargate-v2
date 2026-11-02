// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.file.Files;
import java.nio.file.Path;

/** Synthetic failure injection in a separate JVM. */
public final class ImportProbe {
    public static void main(String[] args) {
        try {
            Path src = Path.of(args[0]), dst = Path.of(args[1]); String requested = args[2];
            if (requested.equals("signal")) {
                VolumeImport.faults = phase -> {
                    if (phase.equals("before-copy")) {
                        Files.writeString(dst.resolveSibling("signal-ready"), "ready");
                        Thread.sleep(30_000);
                    }
                };
                VolumeImport.main(new String[]{"--source", src.toString(), "--destination", dst.toString()});
                return;
            }
            VolumeImport.faults = phase -> {
                boolean interrupt = requested.equals("interrupt-" + phase);
                if (!phase.equals(requested) && !interrupt) return;
                if (interrupt) { Thread.currentThread().interrupt(); return; }
                Path incomplete = dst.resolve("app-data/volume-import-incomplete");
                if (phase.equals("import-gate-synced")) {
                    if (!Files.isRegularFile(incomplete) || Files.exists(dst.resolve("app-data/recovery-incomplete"))) throw new AssertionError();
                }
                if (phase.equals("before-rescan")) { Files.writeString(src.resolve("app-data/file"), "changed"); return; }
                throw new java.io.IOException("Synthetic injected failure");
            };
            VolumeImport.importSet(src.toString(), dst.toString(), false);
            System.exit(2);
        } catch (Exception expected) { System.exit(0); }
    }
}
