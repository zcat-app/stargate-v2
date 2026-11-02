// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WebUiInvitationsTest {
    @TempDir Path directory;

    @Test void issuanceJsonAndAuthenticatedPagesShareTheExactCancellationReference() throws Exception {
        var manager = manager();
        try {
            var resource = new ManagerResource();resource.manager = manager;
            var response = resource.pairingCode(new ManagerResource.Issue("browser"));
            assertEquals(200, response.getStatus());
            var first = (Pairing.Ticket) response.getEntity();
            var json = new ObjectMapper().valueToTree(first);
            assertEquals(4, json.size());
            assertEquals(first.code(), json.get("code").asText());
            assertEquals(first.label(), json.get("label").asText());
            assertEquals(first.expiresAt(), json.get("expiresAt").asText());
            assertEquals(first.id(), json.get("id").asText());
            var second = manager.issuePairing("browser");
            var session = manager.sessions().create();
            String issued = WebUi.page(manager, session, null, first);
            String refreshed = WebUi.page(manager, session, null, null);
            String locked = WebUi.page(manager, null, null, first);
            assertTrue(issued.contains("value=\"" + first.code() + "\""));
            assertEquals(issued.indexOf(first.code()), issued.lastIndexOf(first.code()));
            assertTrue(issued.substring(0, issued.indexOf("<h3>Pending invitations</h3>"))
                    .contains("Invitation reference <code>" + first.id() + "</code>"));
            for (var ticket : java.util.List.of(first, second)) {
                String reference = "Invitation reference <code>" + ticket.id() + "</code>";
                assertFalse(refreshed.contains(ticket.code()));assertFalse(locked.contains(ticket.code()));
                assertFalse(locked.contains(ticket.id()));
                for (String page : java.util.List.of(issued, refreshed)) {
                    var rows = Pattern.compile("<div>browser · expires .*?</div>").matcher(page).results()
                            .map(java.util.regex.MatchResult::group).toList();
                    assertEquals(2, rows.size());
                    String row = rows.stream().filter(value -> value.contains(reference)).findFirst().orElseThrow();
                    assertTrue(row.contains("action=\"/pairing/cancel\""));
                    assertTrue(row.contains("name=\"id\" value=\"" + ticket.id() + "\""));
                    assertTrue(row.contains("name=\"csrf\" value=\"" + session.csrf() + "\""));
                    assertFalse(row.contains(first.code()));assertFalse(row.contains(second.code()));
                }
            }
            assertFalse(issued.contains(second.code()));assertFalse(issued.contains("<script"));
            assertEquals(403, resource.cancelInvitation(session.id(), "wrong", first.id()).getStatus());
            var cancelled = resource.cancelInvitation(session.id(), session.csrf(), first.id());
            assertEquals(200, cancelled.getStatus());
            assertFalse(cancelled.getEntity().toString().contains(first.id()));
            assertTrue(cancelled.getEntity().toString().contains("Invitation reference <code>" + second.id() + "</code>"));
            String origin = "chrome-extension://" + "a".repeat(32);
            assertNull(manager.redeemPairing(first.code(), origin));
            assertNotNull(manager.redeemPairing(second.code(), origin));
            assertNull(manager.redeemPairing(second.code(), origin));
        } finally { manager.closeI2pConfiguration(); }
    }

    private ManagerService manager() throws Exception {
        Path proxy = directory.resolve("proxy.properties");
        privateFile(proxy, "network.mode=container\nisolation.key=" + "00".repeat(32) + "\n");
        Path config = directory.resolve("manager.properties");
        privateFile(config, "manager.token=" + "b".repeat(43) + "\nproxy.config=" + proxy
                + "\nproxy.control.socket=" + directory.resolve("unused.sock")
                + "\ntor.cookie=" + directory.resolve("cookie") + "\ntor.control.port=9051\n");
        // Render real invitations with synthetic observations; no sockets or process controls.
        return new ManagerService(config.toString(), "0.0.0.0", 9080) {
            @Override public Status status() {
                return new Status("synthetic", "SUPERVISOR", null,
                        new ProxyControl.Unit("synthetic", "loaded", "inactive", "dead", 0L, null, null, null, null),
                        new ProxyObservation("REFUSED", "synthetic", false),
                        new TorProbe.Observation(TorProbe.Health.UNAVAILABLE, "synthetic", null, null, null, null, null, null, null, null),
                        new I2pProbe.Observation("UNAVAILABLE", "synthetic", null, null, null, null, null, null, null, "UNKNOWN"),
                        new NymProbe.Observation("DISABLED", null, "UNKNOWN"), null);
            }
            @Override public String i2pLifecycleObservation() { return "synthetic"; }
        };
    }

    private static void privateFile(Path path, String content) throws Exception {
        Files.writeString(path, content);
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
    }
}
