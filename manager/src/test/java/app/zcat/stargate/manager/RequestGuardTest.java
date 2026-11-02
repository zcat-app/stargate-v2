// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import static org.junit.jupiter.api.Assertions.*;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class RequestGuardTest {
    @TempDir Path directory;
    private static final String TOKEN = "synthetic-manager-token-for-guard-tests-000000";

    @Test void leadingSlashAndUnknownRoutesCannotBypassAuthentication() throws Exception {
        RequestGuard guard = guard();
        for (String path : new String[]{"api/status", "/api/status", "//api/status", "api/proxy/start", "api/devices/revoke", "api/devices/i2p", "api/pairing/invitations", "api/pairing/cancel", "another-api"}) {
            assertEquals(401, filter(guard, path, "GET", Map.of()).getStatus(), path);
        }
        assertNull(filter(guard, "/", "GET", Map.of()));
        assertEquals(401, filter(guard, "/app.js", "GET", Map.of()).getStatus());
        assertNull(filter(guard, "/api/status", "GET", Map.of("Authorization", "Bearer " + TOKEN)));
    }

    @Test void originAndHostGuardsApplyEvenWithValidManagementToken() throws Exception {
        RequestGuard guard = guard();
        assertEquals(403, filter(guard, "/api/proxy/start", "POST", Map.of("Authorization", "Bearer " + TOKEN)).getStatus());
        assertEquals(403, filter(guard, "/api/proxy/start", "POST", Map.of("Authorization", "Bearer " + TOKEN, "Origin", "https://attacker.invalid")).getStatus());
        assertEquals(403, filter(guard, "/api/status", "GET", Map.of("Authorization", "Bearer " + TOKEN, "Host", "attacker.invalid")).getStatus());
        assertNull(filter(guard, "/api/proxy/start", "POST", Map.of("Authorization", "Bearer " + TOKEN, "Origin", "http://127.0.0.1:9080")));
        assertEquals(415, filter(guard, "/api/proxy/start", "POST", Map.of("Authorization", "Bearer " + TOKEN, "Origin", "http://127.0.0.1:9080", "Content-Encoding", "br")).getStatus());
    }

    @Test void extensionCredentialsOnlyAuthorizeTheReadOnlyExtensionEndpoint() throws Exception {
        RequestGuard guard = guard();String origin = "chrome-extension://" + "a".repeat(32);
        var ticket = guard.manager.issuePairing("browser");var grant = guard.manager.redeemPairing(ticket.code(), origin);
        String authorization = grant.credentials().authorization();
        var headers = Map.of("Authorization", authorization, "X-Stargate-Extension", origin);
        assertNull(filter(guard, "/api/extension/status", "GET", headers));
        assertEquals(401, filter(guard, "/api/status", "GET", headers).getStatus());
        assertEquals(401, filter(guard, "/api/pairing/invitations", "GET", headers).getStatus());
        assertEquals(401, filter(guard, "/api/pairing/cancel", "POST", Map.of("Authorization", authorization, "Origin", "http://127.0.0.1:9080")).getStatus());
        assertEquals(401, filter(guard, "/api/proxy/start", "POST", Map.of("Authorization", authorization, "Origin", "http://127.0.0.1:9080")).getStatus());
        assertEquals(401, filter(guard, "/api/devices/revoke", "POST", Map.of("Authorization", authorization, "Origin", "http://127.0.0.1:9080")).getStatus());
        assertEquals(401, filter(guard, "/api/devices/i2p", "POST", Map.of("Authorization", authorization, "Origin", "http://127.0.0.1:9080")).getStatus());
        assertEquals(403, filter(guard, "/api/extension/status", "GET", Map.of("Authorization", authorization, "X-Stargate-Extension", origin, "Origin", "https://attacker.invalid")).getStatus());
        assertEquals(403, filter(guard, "/api/pairing/redeem", "POST", Map.of("X-Stargate-Extension", origin)).getStatus());
    }

    @Test void nativeRevocationRequiresTheSessionsCsrfSecret() throws Exception {
        RequestGuard guard = guard();ManagerResource resource = new ManagerResource();resource.manager = guard.manager;
        var session = guard.manager.sessions().create();
        assertEquals(403, resource.cancelInvitation(session.id(), "wrong", "a".repeat(43)).getStatus());
        assertEquals(403, resource.revoke(session.id(), "wrong", "browser").getStatus());
        assertEquals(403, resource.i2pDeviceForm(session.id(), "wrong", "browser", "false").getStatus());
        assertEquals(403, resource.i2pDeviceForm(null, session.csrf(), "browser", "false").getStatus());
        assertTrue(guard.manager.profiles().contains("browser"));
        assertEquals(403, resource.revoke(null, session.csrf(), "browser").getStatus());
        assertEquals(403, resource.upgrade("install",session.id(),"wrong","a".repeat(64)).getStatus());
        assertEquals(403, resource.upgrade("rollback",null,session.csrf(),"a".repeat(64)).getStatus());
        assertEquals(415, filter(guard,"/upgrades/install","POST",Map.of("Origin","http://127.0.0.1:9080")).getStatus());
        assertEquals(403, filter(guard,"/upgrades/install","POST",Map.of("Origin","https://attacker.invalid")).getStatus());
        assertTrue(guard.manager.profiles().contains("browser"));
    }

    @Test void invitationPagesNeverRedisplayCodesAndResponsesAreNotCached() throws Exception {
        RequestGuard guard = guard();var session = guard.manager.sessions().create();
        var ticket = guard.manager.issuePairing("browser", "24h");
        String issued = WebUi.page(guard.manager, session, null, ticket);
        String refreshed = WebUi.page(guard.manager, session, null, null);
        assertTrue(issued.contains(ticket.code()));assertFalse(refreshed.contains(ticket.code()));
        assertTrue(refreshed.contains("Pending invitations"));assertTrue(refreshed.contains("manager restarts"));
        var headers = new MultivaluedHashMap<String, Object>();
        var response = (jakarta.ws.rs.container.ContainerResponseContext) Proxy.newProxyInstance(
                getClass().getClassLoader(), new Class[]{jakarta.ws.rs.container.ContainerResponseContext.class},
                (_, method, _) -> method.getName().equals("getHeaders") ? headers : null);
        guard.filter(null, response);assertEquals("no-store", headers.getFirst("Cache-Control"));
        var resource = new ManagerResource();resource.manager = guard.manager;
        String id = guard.manager.invitations().getFirst().id();
        assertEquals(403, resource.cancelInvitation(session.id(), "wrong", id).getStatus());
        assertEquals(200, resource.cancelInvitation(session.id(), session.csrf(), id).getStatus());
        assertNull(guard.manager.redeemPairing(ticket.code(), "chrome-extension://" + "a".repeat(32)));
    }

    @Test void i2pProvisioningFailureDoesNotPreventManagerStartupOrCredentialAdministration() throws Exception {
        Path proxy = directory.resolve("many-profiles");
        String text = "network.mode=container\ni2p.deviceIsolation=true\ni2p.nextPort=invalid\n";
        for (int n=0;n<9;n++) text += "profile.device"+n+".token=synthetic-proxy-token-for-request-guard-tests\n";
        privateFile(proxy,text);Path config=directory.resolve("degraded-manager");
        privateFile(config,"manager.token="+TOKEN+"\nproxy.config="+proxy+"\nproxy.control.socket="+directory.resolve("unused.sock")+"\ntor.cookie="+directory.resolve("cookie")+"\ntor.control.port=9051\n");
        var manager = new ManagerService(config.toString(),"0.0.0.0",9080);
        try { assertFalse(manager.i2pConfigurationAvailable());assertEquals(9,manager.profiles().size());
            var resource = new ManagerResource();resource.manager=manager;
            var full = resource.pairingCode(new ManagerResource.Issue("extra"));
            assertEquals(200,full.getStatus());
            var ticket = (Pairing.Ticket) full.getEntity();
            byte[] before = Files.readAllBytes(proxy);
            var failed = resource.redeem(new ManagerResource.Redeem(ticket.code()), "chrome-extension://" + "a".repeat(32));
            assertEquals(503,failed.getStatus());
            assertEquals(Map.of("code","DEVICE_STORE_UNAVAILABLE"),failed.getEntity());
            assertArrayEquals(before,Files.readAllBytes(proxy));assertEquals(9,manager.profiles().size());
            assertTrue(manager.invitations().isEmpty());
            assertEquals(403,resource.redeem(new ManagerResource.Redeem(ticket.code()), "chrome-extension://" + "a".repeat(32)).getStatus());
            assertTrue(manager.revokeDevice("device0")); }
        finally { manager.closeI2pConfiguration(); }
    }

    private RequestGuard guard() throws Exception {
        Path proxy = directory.resolve("proxy");privateFile(proxy, "listen.port=8881\ntor.port=9050\nprofile.browser.token=synthetic-proxy-token-for-request-guard-tests\n");
        Path config = directory.resolve("manager");privateFile(config, "manager.token=" + TOKEN + "\nproxy.config=" + proxy + "\ntor.control.port=9051\ntor.cookie=" + directory.resolve("cookie") + "\n");
        RequestGuard guard = new RequestGuard();guard.manager = new ManagerService(config.toString(), "127.0.0.1", 9080);return guard;
    }

    private static Response filter(RequestGuard guard, String path, String method, Map<String, String> headers) {
        var all = new MultivaluedHashMap<String, String>();all.putSingle("Host", "127.0.0.1:9080");headers.forEach(all::putSingle);
        AtomicReference<Response> rejected = new AtomicReference<>();
        UriInfo uri = (UriInfo) Proxy.newProxyInstance(UriInfo.class.getClassLoader(), new Class[]{UriInfo.class}, (_, function, _) -> function.getName().equals("getPath") ? path : null);
        ContainerRequestContext request = (ContainerRequestContext) Proxy.newProxyInstance(ContainerRequestContext.class.getClassLoader(), new Class[]{ContainerRequestContext.class}, (_, function, args) -> switch (function.getName()) {
            case "getHeaders" -> all;
            case "getHeaderString" -> all.getFirst((String) args[0]);
            case "getMethod" -> method;
            case "getUriInfo" -> uri;
            case "getMediaType" -> MediaType.APPLICATION_JSON_TYPE;
            case "abortWith" -> { rejected.set((Response) args[0]);yield null; }
            default -> throw new UnsupportedOperationException(function.getName());
        });
        guard.filter(request);return rejected.get();
    }
    private static void privateFile(Path path, String value) throws Exception { Files.writeString(path, value);Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------")); }
}
