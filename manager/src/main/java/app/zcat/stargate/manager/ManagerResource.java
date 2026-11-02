// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import io.smallrye.common.annotation.Blocking;
import jakarta.inject.Inject;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.CookieParam;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.core.Response;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

@Path("/")
@Blocking
public class ManagerResource {
    @Inject ManagerService manager;
    @Inject io.vertx.ext.web.RoutingContext routing;

    @GET @Produces("text/html")
    public String page(@CookieParam("stargate_session") String cookie) {
        return WebUi.page(manager, manager.sessions().get(cookie), null, null);
    }
    @POST @Path("login") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response login(@FormParam("token") String token, @CookieParam("stargate_session") String old) {
        if (token == null || !manager.authorized("Bearer " + token))
            return Response.status(401).entity(WebUi.page(manager, null, "Sign-in failed.", null)).build();
        manager.sessions().remove(old);
        try {
            var session = manager.sessions().create();
            return Response.seeOther(java.net.URI.create("/")).header("Set-Cookie", cookie(session.id(), 1800)).build();
        } catch (IllegalStateException e) {
            return Response.status(429).entity(WebUi.page(manager, null, "Session limit reached. Try again after existing sessions expire.", null)).build();
        }
    }
    @POST @Path("logout") @Consumes("application/x-www-form-urlencoded")
    public Response logout(@CookieParam("stargate_session") String session, @FormParam("csrf") String csrf) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        manager.sessions().remove(session);
        return Response.seeOther(java.net.URI.create("/")).header("Set-Cookie", cookie("", 0)).build();
    }
    @POST @Path("control/{action}") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response control(@PathParam("action") String action, @CookieParam("stargate_session") String session, @FormParam("csrf") String csrf) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        if (!List.of("start", "stop", "restart").contains(action)) return Response.status(400).build();
        var result = manager.operate(action);
        return result.success() ? Response.seeOther(java.net.URI.create("/")).build()
                : Response.status(503).entity(WebUi.page(manager, manager.sessions().get(session), result.code(), null)).build();
    }
    @POST @Path("pairing") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response pair(@CookieParam("stargate_session") String session, @FormParam("csrf") String csrf, @FormParam("label") String label, @FormParam("lifetime") String lifetime) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        try { return Response.ok(WebUi.page(manager, manager.sessions().get(session), null, manager.issuePairing(label, lifetime))).build(); }
        catch (IllegalArgumentException | IllegalStateException e) { return Response.status(400).entity(WebUi.page(manager, manager.sessions().get(session), "Pairing code could not be issued.", null)).build(); }
    }
    @POST @Path("pairing/cancel") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response cancelInvitation(@CookieParam("stargate_session") String session, @FormParam("csrf") String csrf, @FormParam("id") String id) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        boolean removed = manager.cancelInvitation(id);
        return Response.ok(WebUi.page(manager, manager.sessions().get(session), removed ? "Invitation cancelled." : "Invitation was already absent or expired.", null)).build();
    }
    @POST @Path("devices/revoke") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response revoke(@CookieParam("stargate_session") String session, @FormParam("csrf") String csrf, @FormParam("deviceId") String id) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        try {
            boolean removed = manager.revokeDevice(id);
            return Response.ok(WebUi.page(manager, manager.sessions().get(session), removed
                    ? "Device revoked. Its active connections close on the next credential refresh (normally within one second). Other devices stay connected."
                    : "Device was already absent.", null)).build();
        } catch (IllegalArgumentException e) { return Response.status(400).entity("INVALID_DEVICE_ID").build(); }
        catch (IllegalStateException e) { return Response.status(503).entity("DEVICE_STORE_UNAVAILABLE").build(); }
    }
    public record Revoke(String deviceId) {}
    @POST @Path("upgrades/{action}") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response upgrade(@PathParam("action") String action,@CookieParam("stargate_session") String session,@FormParam("csrf") String csrf,@FormParam("plan") String plan) {
        if(!manager.sessions().csrf(session,csrf))return csrfRejected();
        if(!List.of("refresh","install","rollback").contains(action))return Response.status(400).build();
        if(!manager.upgrades().request(action,plan))return Response.status(409).entity(WebUi.page(manager,manager.sessions().get(session),"Upgrade request not queued. Refresh observations and check the host updater.",null)).build();
        return Response.ok(WebUi.page(manager,manager.sessions().get(session),"Request queued, not completed. Refresh observations to check the host result.",null)).build();
    }
    public record I2pDevice(String deviceId, Boolean enabled) {}
    @POST @Path("api/devices/i2p") @Consumes("application/json") @Produces("application/json")
    public Response i2pDevice(I2pDevice request) {
        if (request == null || request.deviceId() == null || request.enabled() == null) return Response.status(400).build();
        try { manager.setI2pEnabled(request.deviceId(), request.enabled()); return Response.ok(Map.of("saved", true)).build(); }
        catch (IllegalArgumentException e) { return Response.status(400).build(); }
        catch (IllegalStateException e) { return Response.status(503).build(); }
    }
    @POST @Path("devices/i2p") @Consumes("application/x-www-form-urlencoded") @Produces("text/html")
    public Response i2pDeviceForm(@CookieParam("stargate_session") String session, @FormParam("csrf") String csrf,
                                 @FormParam("deviceId") String id, @FormParam("enabled") String enabled) {
        if (!manager.sessions().csrf(session, csrf)) return csrfRejected();
        if (id == null || !("true".equals(enabled) || "false".equals(enabled))) return Response.status(400).build();
        try {
            manager.setI2pEnabled(id, Boolean.parseBoolean(enabled));
            return Response.ok(WebUi.page(manager, manager.sessions().get(session), "I2P setting saved. Reload and tunnel startup are asynchronous; this does not confirm destination access.", null)).build();
        } catch (IllegalArgumentException e) { return Response.status(400).build(); }
        catch (IllegalStateException e) { return Response.status(503).build(); }
    }
    @POST @Path("api/devices/revoke") @Consumes("application/json") @Produces("application/json")
    public Response revokeApi(Revoke request) {
        try { return Response.ok(Map.of("removed", manager.revokeDevice(request == null ? null : request.deviceId()))).build(); }
        catch (IllegalArgumentException e) { return Response.status(400).entity(Map.of("code", "INVALID_DEVICE_ID")).build(); }
        catch (IllegalStateException e) { return Response.status(503).entity(Map.of("code", "DEVICE_STORE_UNAVAILABLE")).build(); }
    }
    private static String cookie(String value, int age) {
        return "stargate_session=" + value + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + age;
    }
    private static Response csrfRejected() { return Response.status(403).type("text/plain").entity("CSRF_REJECTED").build(); }
    @GET @Path("style.css") @Produces("text/css")
    public InputStream stylesheet() { return resource("style.css"); }
    @GET @Path("charts.css") @Produces("text/css")
    public InputStream charts() { return resource("vendor/charts.min.css"); }
    private InputStream resource(String name) { return getClass().getResourceAsStream("/web/" + name); }

    @GET @Path("api/status") @Produces("application/json")
    public ManagerService.Status status() { return manager.status(); }
    @GET @Path("api/traffic") @Produces("application/json")
    public TrafficStats.Observation traffic() { return TrafficStats.read(manager.metricsPath(), manager.status().process()); }

    @GET @Path("api/pairing/profiles") @Produces("application/json")
    public Map<String, Object> profiles() { return Map.of("profiles", manager.profiles()); }
    public record Issue(String label, String lifetime) { public Issue(String label) { this(label, null); } }
    public record CancelInvitation(String id) {}
    @GET @Path("api/pairing/invitations") @Produces("application/json")
    public Map<String, Object> invitations() { return Map.of("invitations", manager.invitations()); }
    @POST @Path("api/pairing/cancel") @Consumes("application/json") @Produces("application/json")
    public Response cancelInvitationApi(CancelInvitation request) {
        return Response.ok(Map.of("removed", manager.cancelInvitation(request == null ? null : request.id()))).build();
    }
    @POST @Path("api/pairing/code") @Consumes("application/json") @Produces("application/json")
    public Response pairingCode(Issue request) {
        try { return Response.ok(manager.issuePairing(request == null ? null : request.label(), request == null ? null : request.lifetime())).build(); }
        catch (IllegalArgumentException e) { return Response.status(400).entity(Map.of("code", "INVALID_INVITATION_LIFETIME".equals(e.getMessage()) ? "INVALID_INVITATION_LIFETIME" : "INVALID_DEVICE_LABEL")).build(); }
        catch (IllegalStateException e) { return "DEVICE_STORE_UNAVAILABLE".equals(e.getMessage())
                ? Response.status(503).entity(Map.of("code", "DEVICE_STORE_UNAVAILABLE")).build()
                : Response.status(409).entity(Map.of("code", "TOO_MANY_PENDING_CODES")).build(); }
    }
    public record Redeem(String code) {}
    @POST @Path("api/pairing/redeem") @Consumes("application/json") @Produces("application/json")
    public Response redeem(Redeem request, @HeaderParam("X-Stargate-Extension") String origin) {
        try {
            var paired = manager.redeemPairing(request == null ? null : request.code(), origin, routing != null && routing.request().isSSL());
            return paired == null ? Response.status(403).entity(Map.of("code", "INVALID_OR_EXPIRED_PAIRING_CODE")).build() : Response.ok(paired).build();
        } catch (IllegalStateException e) { return "DEVICE_STORE_FULL".equals(e.getMessage())
                ? Response.status(409).entity(Map.of("code", "DEVICE_STORE_FULL")).build()
                : Response.status(503).entity(Map.of("code", "DEVICE_STORE_UNAVAILABLE")).build(); }
    }
    @GET @Path("api/extension/status") @Produces("application/json")
    public ManagerService.ExtensionStatus extensionStatus(@HeaderParam("Authorization") String authorization,
                                                          @HeaderParam("X-Stargate-Extension") String origin) {
        return manager.extensionStatus(authorization, origin, routing != null && routing.request().isSSL());
    }

    @POST @Path("api/proxy/{action}") @Produces("application/json")
    public Response action(@PathParam("action") String action) {
        if (!List.of("start", "stop", "restart").contains(action)) return Response.status(400).entity(Map.of("code", "INVALID_ACTION")).build();
        var result = manager.operate(action);
        int status = result.success() ? 200 : result.code().equals("OPERATION_IN_PROGRESS") ? 409 : 503;
        return Response.status(status).entity(result).build();
    }
}
