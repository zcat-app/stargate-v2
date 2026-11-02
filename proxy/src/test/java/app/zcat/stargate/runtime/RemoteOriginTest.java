// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.runtime;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;
class RemoteOriginTest {
    @Test void invalidRemoteOriginFailsBeforeManagerRestartLoop() {
        for(String valid:new String[]{"https://gate.example", "https://gate.example:9443", "https://127.0.0.1:9443"})assertDoesNotThrow(()->Supervisor.validatePublicOrigin(valid));
        for(String invalid:new String[]{"http://gate.example","https://Gate.example","https://gate.example:443","https://gate.example:65536","https://gate.example:0","https://gate.example/","https://gate.onion","https://gate.i2p","https://user@gate.example","https://gate.example?x=1","https://gate.example#x"})assertThrows(IllegalArgumentException.class,()->Supervisor.validatePublicOrigin(invalid),invalid);
    }
}
