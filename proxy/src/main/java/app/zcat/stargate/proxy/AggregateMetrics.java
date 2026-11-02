// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.proxy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/** Process-wide counters only. No destination, profile, stream or request record is collected. */
final class AggregateMetrics implements AutoCloseable {
    final AtomicLong connections = new AtomicLong(), connected = new AtomicLong(), failures = new AtomicLong();
    final AtomicLong uploaded = new AtomicLong(), downloaded = new AtomicLong(), active = new AtomicLong();
    final AtomicLong i2pConnections = new AtomicLong(), i2pConnected = new AtomicLong(), i2pResponses = new AtomicLong();
    final AtomicLong nymConnections = new AtomicLong(), nymConnected = new AtomicLong(), nymResponses = new AtomicLong();
    private final Path file;
    private final Admission admission;
    private final String started = Instant.now().toString();
    private final java.util.concurrent.ScheduledExecutorService writer;

    AggregateMetrics(Path file, Admission admission) {
        this.file = file;
        this.admission = admission;
        writer = file == null ? null : Executors.newSingleThreadScheduledExecutor(task -> Thread.ofPlatform().daemon().name("aggregate-counters").unstarted(task));
        if (writer != null) writer.scheduleWithFixedDelay(this::write, 0, 1, TimeUnit.SECONDS);
    }
    private void write() {
        if (file == null) return;
        Path temporary = null;
        try {
            temporary = Files.createTempFile(file.getParent(), ".aggregate-", ".json", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
            String json = "{\"pid\":" + ProcessHandle.current().pid() + ",\"startedAt\":\"" + started + "\",\"observedAt\":\"" + Instant.now()
                    + "\",\"connections\":" + connections.get() + ",\"connected\":" + connected.get() + ",\"failures\":" + failures.get()
                    + ",\"uploaded\":" + uploaded.get() + ",\"downloaded\":" + downloaded.get() + ",\"active\":" + active.get()
                    + ",\"i2pConnections\":" + i2pConnections.get() + ",\"i2pConnected\":" + i2pConnected.get() + ",\"i2pResponses\":" + i2pResponses.get()
                    + ",\"globalConnectionLimit\":" + admission.limit + ",\"acceptedConnections\":" + admission.occupancy.get()
                    + ",\"connectionLimitRefusals\":" + admission.refusals.get()
                    + ",\"nymConnections\":" + nymConnections.get() + ",\"nymConnected\":" + nymConnected.get() + ",\"nymResponses\":" + nymResponses.get() + "}\n";
            Files.writeString(temporary, json);Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (Exception ignored) { /* Counter export cannot interrupt forwarding. Missing/stale data stays unknown in the manager. */ }
        finally { if (temporary != null) try { Files.deleteIfExists(temporary); } catch (Exception ignored) {} }
    }
    @Override public void close() { if (writer != null) writer.shutdownNow();write(); }
}
