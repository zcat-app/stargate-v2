// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Map;
import java.util.Set;
import static org.junit.jupiter.api.Assertions.*;

class HelperPolicyTest {
    private static final String ID = "a".repeat(64), IMAGE = "sha256:" + "b".repeat(64), TOKEN = "c".repeat(32);
    private static HelperPolicy.Spec spec() {
        return new HelperPolicy.Spec(ID, "created", "helper", IMAGE, Map.of(DockerPolicy.LABEL, TOKEN), "10001:10001", List.of("/opt/java/bin/java"),
                List.of("-cp", "/tool/backup.jar", "example.Main"), Set.of(), Map.of("/dest", "uid=10001,gid=10001,mode=0700"),
                Set.of(new HelperPolicy.Mount("volume", "v", "/dest/app-data", true)), Set.of("v"));
    }
    private static ObjectNode fixture() throws Exception {
        return (ObjectNode) DockerPolicy.parse("""
                {"Id":"%s","Created":"created","Name":"/helper","Image":"%s",
                 "Config":{"Labels":{"org.stargate.offline-import":"%s"},"User":"10001:10001","Entrypoint":["/opt/java/bin/java"],"Cmd":["-cp","/tool/backup.jar","example.Main"],"Healthcheck":{"Test":["NONE"]}},
                 "HostConfig":{"NetworkMode":"none","ReadonlyRootfs":true,"Privileged":false,"CapDrop":["ALL"],"CapAdd":[],"SecurityOpt":["no-new-privileges"],"UsernsMode":"host",
                  "Memory":536870912,"MemorySwap":536870912,"NanoCpus":2000000000,"PidsLimit":128,"PortBindings":null,"PublishAllPorts":false,"PidMode":"","IpcMode":"private","UTSMode":"","Devices":[],"VolumesFrom":[],
                  "Tmpfs":{"/dest":"uid=10001,gid=10001,mode=0700"},"Mounts":[{"Type":"volume","Source":"v","ReadOnly":false,"VolumeOptions":{"NoCopy":true}}],
                  "Ulimits":[{"Name":"core","Soft":0,"Hard":0},{"Name":"fsize","Soft":8589934592,"Hard":8589934592}],"LogConfig":{"Type":"local","Config":{"max-size":"1m","max-file":"1","compress":"false"}}},
                 "Mounts":[{"Type":"volume","Name":"v","Destination":"/dest/app-data","RW":true}],"State":{"Running":false,"Status":"exited","OOMKilled":false,"Dead":false,"ExitCode":0}}
                """.formatted(ID, IMAGE, TOKEN));
    }
    @Test void acceptsExactIsolatedHelperAndRejectsChangedMountsOrPrivileges() throws Exception {
        ObjectNode valid = fixture(); HelperPolicy.validate(valid, spec()); HelperPolicy.finished(valid);
        ObjectNode mount = fixture(); ((ArrayNode) mount.path("Mounts")).add(mount.path("Mounts").get(0).deepCopy());
        assertThrows(Exception.class, () -> HelperPolicy.validate(mount, spec()));
        ObjectNode cap = fixture(); ((ArrayNode) cap.path("HostConfig").path("CapAdd")).add("CAP_CHOWN");
        assertThrows(Exception.class, () -> HelperPolicy.validate(cap, spec()));
        ObjectNode wrongLimit = fixture(); ((ObjectNode) wrongLimit.path("HostConfig")).put("Memory", 1);
        assertThrows(Exception.class, () -> HelperPolicy.validate(wrongLimit, spec()));
        ObjectNode running = fixture(); ((ObjectNode) running.path("State")).put("Running", true);
        assertThrows(Exception.class, () -> HelperPolicy.finished(running));
    }
}
