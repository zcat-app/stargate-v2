// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/** Injects scoped synthetic failures while exercising the real CLI transaction. */
public final class OfflineFailureProbe {
    public static void main(String[] args) {
        String mode = args[0]; Path sentinel = Path.of(args[1]);
        if (mode.equals("age-timeout")) OfflineVerify.timeoutNanos = 0;
        OfflineVerify.faults = phase -> {
            if ((mode.equals("observe-inspection") || mode.equals("age-timeout")) && phase.equals("before-inspect")) Files.writeString(sentinel, "inspected");
            if (mode.equals("signal") && phase.equals("after-age-spawn")) {
                Files.writeString(sentinel, "ready");
                try { Thread.sleep(30_000); } catch (InterruptedException e) { Thread.currentThread().interrupt(); throw new java.io.IOException("Interrupted", e); }
            }
            if ((mode.equals("cleanup-file") && phase.equals("cleanup-file"))
                    || (mode.equals("cleanup-dir") && phase.equals("after-work-rmdir"))
                    || (mode.equals("pack-publish") && phase.equals("after-pack-link"))) throw new java.io.IOException("Synthetic injected failure");
        };
        if (mode.equals("stage-publish")) StagedArchive.faults = phase -> {
            if (phase.equals("after-publish")) throw new java.io.IOException("Synthetic injected failure");
        };
        OfflineVerify.main(Arrays.copyOfRange(args, 2, args.length));
    }
}
