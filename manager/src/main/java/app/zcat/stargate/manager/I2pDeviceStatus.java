// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/** Only the authenticated device's row leaves the private process snapshot. */
final class I2pDeviceStatus {
    record Observation(String state, String observedAt) {}
    record Snapshot(long pid, String startedAt, String observedAt, boolean available, Map<String,String> devices) {}
    private static final Set<String> STATES=Set.of("WAITING","STARTING","CONNECTIONS_OPEN","COOLDOWN","STOPPING","UNAVAILABLE");
    static Observation unavailable() { return new Observation("UNAVAILABLE",null); }
    static Observation read(Path file, int port, ProxyControl.Unit process) {
        try {
            if(!"OBSERVED".equals(process.observation())||!"active".equals(process.activeState())||process.pid()==null)return unavailable();
            byte[] bytes;
            try(var input=Files.newInputStream(file,LinkOption.NOFOLLOW_LINKS)){bytes=input.readNBytes(2097153);}
            if(bytes.length>2097152)return unavailable();
            Snapshot s=new ObjectMapper().readValue(bytes,Snapshot.class);
            Instant observed=Instant.parse(s.observedAt());
            long age=Duration.between(observed,Instant.now()).toMillis();
            if(!s.available()||s.pid()!=process.pid()||age<0||age>5000||s.devices()==null)return unavailable();
            // A reused PID or a previous proxy's final snapshot is not a current observation.
            var started=ProcessHandle.of(s.pid()).flatMap(p->p.info().startInstant()).orElseThrow();
            if(!started.equals(Instant.parse(s.startedAt()))||observed.isBefore(started))return unavailable();
            for(var e:s.devices().entrySet()) {
                if(!e.getKey().matches("[0-9]{5}")||Integer.parseInt(e.getKey())<14447||Integer.parseInt(e.getKey())>65535||!STATES.contains(e.getValue()))return unavailable();
            }
            return new Observation(s.devices().getOrDefault(Integer.toString(port),"NOT_STARTED"),s.observedAt());
        } catch(Exception e){return unavailable();}
    }
    static String describe(Observation o) {
        return switch(o.state()) {
            case "NOT_STARTED" -> "Not started. Opens on the next I2P request; the saved identity is retained.";
            case "WAITING" -> "Waiting for local activation. Leave the request open; other routes may be starting.";
            case "STARTING" -> "Starting or connecting. Leave the request open; a cold route can take minutes. If it fails, retry only when safe; a submitted action may already have reached its destination.";
            case "CONNECTIONS_OPEN" -> "Connections open. Silent connections keep this device route running; this does not prove the next destination is reachable.";
            case "COOLDOWN" -> "Cooling down. No connections are held; the route will unload and retain its identity.";
            case "STOPPING" -> "Unloading the previous route. Any new request waits for removal before starting again.";
            case "DISABLED" -> "Disabled for this device. Ask the administrator to enable I2P; pairing again is unnecessary.";
            case "NOT_CONFIGURED" -> "Per-device lifecycle is not configured for this deployment.";
            default -> "Local lifecycle observation unavailable. Refresh observations; ask the administrator to inspect I2P if this persists. Do not restart or pair again just because status is unknown.";
        };
    }
}
