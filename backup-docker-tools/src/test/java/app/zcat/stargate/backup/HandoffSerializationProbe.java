// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.backup;

import java.util.LinkedHashMap;

/** Cross-process probe for stable Compose override bytes. */
public final class HandoffSerializationProbe {
    private HandoffSerializationProbe() {}
    public static void main(String[] args) throws Exception {
        var volumes = new LinkedHashMap<String,String>();
        volumes.put("app-data", "synthetic-app");
        volumes.put("nym-data", "synthetic-nym");
        System.out.println(DockerPolicy.json(ComposeHandoff.override("synthetic-project", volumes)));
    }
}
