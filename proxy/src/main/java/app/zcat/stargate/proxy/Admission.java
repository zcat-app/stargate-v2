// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/** Global accepted sockets, including those not yet authenticated. */
final class Admission {
    final int limit;
    final AtomicInteger occupancy = new AtomicInteger();
    final AtomicLong refusals = new AtomicLong();

    Admission(int limit) { this.limit = limit; }

    // Called exactly once per accepted socket, before choosing the TLS or plaintext path.
    boolean accept() {
        boolean overloaded = occupancy.incrementAndGet() > limit;
        if (overloaded) refusals.incrementAndGet();
        return overloaded;
    }

    void release() { occupancy.decrementAndGet(); }
}
