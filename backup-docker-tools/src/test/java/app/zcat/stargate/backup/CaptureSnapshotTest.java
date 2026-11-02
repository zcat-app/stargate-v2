// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class CaptureSnapshotTest {
    static final String ID = "b".repeat(64);
    static final class Fake implements DockerTransport {
        final Map<String,JsonNode> volumes = new HashMap<>(); JsonNode writer; String attached = ID, daemon = "daemon";
        public String call(long timeout, String... args) throws Exception {
            if (args[0].equals("info")) return DockerPolicy.json(daemon);
            if (args[0].equals("ps")) return attached;
            throw new AssertionError();
        }
        public JsonNode inspect(String kind, String name) { return kind.equals("volume") ? volumes.get(name) : writer; }
    }
    private static Fake fake() throws Exception {
        Fake d = new Fake();
        for (String name : DockerPolicy.BASE) d.volumes.put(name, DockerPolicy.parse("{\"Name\":\"" + name + "\",\"Driver\":\"local\",\"Scope\":\"local\",\"Options\":null,\"Mountpoint\":\"/var/lib/volumes/" + name + "\",\"CreatedAt\":\"time\",\"Labels\":{}}"));
        d.writer = DockerPolicy.parse("{\"Id\":\"" + ID + "\",\"Name\":\"/writer\",\"Image\":\"image\",\"Mounts\":[{\"Name\":\"b\"},{\"Name\":\"a\"}],\"State\":{\"Running\":false,\"Status\":\"exited\",\"Paused\":false,\"Restarting\":false,\"Dead\":false}}");
        return d;
    }
    private static DockerPolicy.Selection selection() { Map<String,String> names = new HashMap<>(); for (String role : DockerPolicy.BASE) names.put(role, role); return new DockerPolicy.Selection(names, Set.of(ID)); }
    @Test void requiresStoppedWritersAndStableVolumeIdentities() throws Exception {
        Fake d = fake(); var selected = selection(); var baseline = CaptureSnapshot.inspect(d, selected, Set.of(), null);
        assertEquals(baseline, CaptureSnapshot.inspect(d, selected, Set.of(), baseline));
        ((ObjectNode) d.volumes.get("app-data")).put("CreatedAt", "changed");
        assertThrows(Exception.class, () -> CaptureSnapshot.inspect(d, selected, Set.of(), baseline));
        Fake running = fake(); ((ObjectNode) running.writer.path("State")).put("Running", true);
        assertThrows(Exception.class, () -> CaptureSnapshot.inspect(running, selected, Set.of(), null));
    }
    @Test void ignoresMountOrderButNotMultiplicityOrUnexpectedAttachments() throws Exception {
        Fake d = fake(); var selected = selection(); var baseline = CaptureSnapshot.inspect(d, selected, Set.of(), null);
        ArrayNode mounts = (ArrayNode) d.writer.path("Mounts"); JsonNode first = mounts.remove(0); mounts.add(first);
        assertEquals(baseline, CaptureSnapshot.inspect(d, selected, Set.of(), baseline));
        mounts.add(first.deepCopy()); assertThrows(Exception.class, () -> CaptureSnapshot.inspect(d, selected, Set.of(), baseline));
        Fake other = fake(); other.attached = "f".repeat(64); assertThrows(Exception.class, () -> CaptureSnapshot.inspect(other, selected, Set.of(), null));
        assertThrows(Exception.class, () -> CaptureSnapshot.rootful(DockerPolicy.parse("[\"name=rootless\"]")));
        Fake replacedDaemon=fake(); var original=CaptureSnapshot.inspect(replacedDaemon,selected,Set.of(),null);replacedDaemon.daemon="different";
        assertThrows(Exception.class,()->CaptureSnapshot.inspect(replacedDaemon,selected,Set.of(),original));
    }
}
