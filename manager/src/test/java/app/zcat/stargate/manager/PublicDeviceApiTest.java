// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
class PublicDeviceApiTest {
    @Test void exactMethodsAndRawUrisOnly() {
        assertTrue(PublicDeviceApi.permitted("POST","/api/pairing/redeem"));
        assertTrue(PublicDeviceApi.permitted("GET","/api/extension/status"));
        for(String path:new String[]{"/","/login","/api/status","/api/proxy/stop","/api/devices/revoke","/pairing","/pairing/cancel","/api/pairing/code","/api/pairing/invitations","/api/pairing/cancel","/style.css","/q/health","//api/extension/status","/api/extension/status?x=1","/api/%65xtension/status","/api/extension/status/","/api/extension/../status"})
            for(String method:new String[]{"GET","POST","HEAD","OPTIONS","CONNECT"})assertFalse(PublicDeviceApi.permitted(method,path),method+" "+path);
        assertFalse(PublicDeviceApi.permitted("GET","/api/pairing/redeem"));
        assertFalse(PublicDeviceApi.permitted("POST","/api/extension/status"));
    }
}
