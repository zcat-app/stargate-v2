// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** A private, owner-only Unix socket accepts fixed verbs, never commands or paths. */
final class SupervisedProxy implements ProxyControl {
    private static final java.util.concurrent.ScheduledExecutorService DEADLINES = Executors.newSingleThreadScheduledExecutor(
            task -> Thread.ofPlatform().daemon().name("supervisor-deadline").unstarted(task));
    private final Path socket;
    SupervisedProxy(Path socket) { this.socket = socket; }

    private String request(String action) throws Exception {
        try (var channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            var deadline = DEADLINES.schedule(() -> { try { channel.close(); } catch (Exception ignored) {} }, 18, TimeUnit.SECONDS);
            try {
                channel.connect(UnixDomainSocketAddress.of(socket));
                new DataOutputStream(Channels.newOutputStream(channel)).writeUTF(action);
                return new DataInputStream(Channels.newInputStream(channel)).readUTF();
            } finally { deadline.cancel(false); }
        }
    }

    public Unit sample() {
        try {
            String[] fields = request("status").split("\\|", -1);
            if (fields.length != 5 || !List.of("active", "inactive", "failed").contains(fields[0])) throw new IllegalArgumentException();
            return new Unit("OBSERVED", "loaded", fields[0], fields[0].equals("active") ? "running" : "dead",
                    Long.valueOf(fields[1]), fields[2], fields[3], Integer.valueOf(fields[4]), "SUPERVISOR_OBSERVED");
        } catch (Exception e) {
            return new Unit("UNAVAILABLE", null, null, null, null, null, null, null, "SUPERVISOR_UNAVAILABLE");
        }
    }

    public Command action(String action) {
        if (!List.of("start", "stop", "restart").contains(action)) throw new IllegalArgumentException("INVALID_ACTION");
        try {
            boolean success = request(action).equals("OK");
            return new Command(success, success ? "SUPERVISOR_COMMAND_COMPLETED" : "SUPERVISOR_COMMAND_REJECTED");
        }
        catch (Exception e) { return new Command(false, "SUPERVISOR_COMMAND_FAILED"); }
    }
}
