// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

/** Synthetic Docker inspection records only; no daemon is contacted. */
class DockerPolicyTest {
    private static final String TOKEN = "a".repeat(32), ID = "b".repeat(64), IMAGE = "sha256:" + "c".repeat(64);
    private static ObjectNode volume() throws Exception {
        return (ObjectNode) DockerPolicy.parse("{\"Name\":\"v\",\"Driver\":\"local\",\"Scope\":\"local\",\"Options\":null,\"Labels\":{\"org.stargate.offline-import\":\"" + TOKEN + "\",\"org.stargate.offline-import-role\":\"app-data\"},\"CreatedAt\":\"2026-01-01\",\"Mountpoint\":\"/var/lib/docker/volumes/v/_data\"}");
    }
    @Test void requiresExactVolumeIdentityAndRejectsReplacement() throws Exception {
        ObjectNode record = volume(); JsonNode baseline = DockerPolicy.importVolume(record, "v", TOKEN, "app-data");
        assertEquals(baseline, DockerPolicy.importVolume(record.deepCopy(), "v", TOKEN, "app-data"));
        ObjectNode replacement = record.deepCopy(); replacement.put("CreatedAt", "later");
        assertNotEquals(baseline, DockerPolicy.importVolume(replacement, "v", TOKEN, "app-data"));
        replacement = record.deepCopy(); replacement.put("Driver", "remote"); ObjectNode bad = replacement;
        assertThrows(Exception.class, () -> DockerPolicy.importVolume(bad, "v", TOKEN, "app-data"));
        replacement = record.deepCopy(); ((ObjectNode) replacement.get("Labels")).put("unexpected", "x"); ObjectNode badLabels = replacement;
        assertThrows(Exception.class, () -> DockerPolicy.importVolume(badLabels, "v", TOKEN, "app-data"));
    }
    @Test void rejectsAmbiguousJsonAndSelection() throws Exception {
        assertThrows(Exception.class, () -> DockerPolicy.parse("{\"a\":1,\"a\":2}"));
        assertThrows(Exception.class, () -> DockerPolicy.parse("{} {}"));
        String valid = "{\"version\":1,\"volumes\":{\"app-data\":\"a\",\"tor-data\":\"b\",\"tor-control\":\"c\",\"i2p-data\":\"d\",\"i2p-control\":\"e\"},\"containers\":[\"" + ID + "\"]}";
        assertEquals(5, DockerPolicy.selection(DockerPolicy.parse(valid), false).volumes().size());
        assertThrows(Exception.class, () -> DockerPolicy.selection(DockerPolicy.parse(valid), true));
        assertThrows(Exception.class, () -> DockerPolicy.selection(DockerPolicy.parse(valid.replace("\"tor-data\":\"b\"", "\"tor-data\":\"a\"")), false));
    }
    @Test void requiresExplicitImmutableImageAndKnownAttachments() throws Exception {
        DockerPolicy.imageId(IMAGE);
        assertThrows(Exception.class, () -> DockerPolicy.imageId("latest"));
        DockerPolicy.attachments(Set.of(ID), Set.of(ID));
        assertThrows(Exception.class, () -> DockerPolicy.attachments(Set.of(ID), Set.of()));
        assertThrows(Exception.class, () -> DockerPolicy.attachments(Set.of("short"), Set.of("short")));
    }
}
