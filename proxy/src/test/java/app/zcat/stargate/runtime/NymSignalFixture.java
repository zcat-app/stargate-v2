// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;

import java.util.concurrent.CountDownLatch;
import sun.misc.Signal;
import sun.misc.SignalHandler;

/** Child JVM used to exercise the launcher's handling of SIGTERM. */
public final class NymSignalFixture {
    public static void main(String[] args) throws InterruptedException {
        Signal term = new Signal("TERM");
        if (args.length != 1) throw new IllegalArgumentException("Expected one signal behavior");
        switch (args[0]) {
            case "cooperative" -> Signal.handle(term, signal -> {
                try { Thread.sleep(150); }
                catch (InterruptedException e) { Thread.currentThread().interrupt(); }
                System.exit(0);
            });
            case "ignore" -> Signal.handle(term, SignalHandler.SIG_IGN);
            default -> throw new IllegalArgumentException("Unknown signal behavior");
        }
        System.out.println("ready");
        System.out.flush();
        new CountDownLatch(1).await();
    }
}
