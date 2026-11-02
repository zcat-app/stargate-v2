// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import jakarta.annotation.Priority;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.container.PreMatching;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import java.util.Map;

@Provider
@PreMatching
@Priority(Priorities.AUTHENTICATION)
public class RequestGuard implements ContainerRequestFilter, ContainerResponseFilter {
    @Inject ManagerService manager;
    @Inject io.vertx.ext.web.RoutingContext routing;

    @Override public void filter(ContainerRequestContext request) {
        boolean secure = routing != null && routing.request().isSSL();
        String publicOrigin = manager.publicOrigin();
        if (secure && publicOrigin == null) { reject(request,403,"PUBLIC_ENDPOINT_REJECTED");return; }
        String authority = secure ? java.net.URI.create(publicOrigin).getRawAuthority() : manager.authority();
        var hosts = request.getHeaders().get("Host");
        if (hosts == null || hosts.size() != 1 || !hosts.getFirst().equals(authority)) { reject(request, 403, "HOST_REJECTED");return; }
        String encoding = request.getHeaderString("Content-Encoding");
        if (encoding != null && !encoding.equalsIgnoreCase("identity")) { reject(request, 415, "COMPRESSED_BODY_REJECTED");return; }
        String path = request.getUriInfo().getPath();
        while (path.startsWith("/")) path = path.substring(1);
        if ((request.getMethod().equals("GET") || request.getMethod().equals("HEAD"))
                && java.util.Set.of("", "style.css", "charts.css").contains(path)) return;
        boolean redeem = path.equals("api/pairing/redeem") && request.getMethod().equals("POST");
        boolean extensionStatus = path.equals("api/extension/status") && request.getMethod().equals("GET");
        if (redeem || extensionStatus) {
            String client = request.getHeaderString("X-Stargate-Extension"), origin = request.getHeaderString("Origin");
            if (!Pairing.extensionOrigin(client) || (origin != null && !origin.equals(client)) || (redeem && !client.equals(origin))) {
                reject(request, 403, "EXTENSION_ORIGIN_REJECTED");return;
            }
            if (extensionStatus && !manager.extensionAuthorized(request.getHeaderString("Authorization"), client)) {
                reject(request, 401, "PAIRING_REJECTED");return;
            }
            if (redeem && !json(request)) reject(request, 415, "JSON_REQUIRED");
            return;
        }
        String site = request.getHeaderString("Sec-Fetch-Site");
        if (site != null && !site.equals("same-origin") && !site.equals("none")) { reject(request, 403, "CROSS_SITE_REJECTED");return; }
        String origin = request.getHeaderString("Origin");
        if ((origin != null || !request.getMethod().equals("GET")) && !manager.origin().equals(origin)) {
            reject(request, 403, "ORIGIN_REJECTED");return;
        }
        boolean form = path.equals("login") || path.equals("logout") || path.equals("pairing") || path.equals("pairing/cancel") || (path.equals("devices/revoke") || path.equals("devices/i2p")) || path.matches("control/(start|stop|restart)") || path.matches("upgrades/(refresh|install|rollback)");
        if (form && request.getMethod().equals("POST")) {
            if (request.getMediaType() == null || !jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED_TYPE.isCompatible(request.getMediaType())) {
                reject(request, 415, "FORM_REQUIRED");return;
            }
            if (!path.equals("login")) {
                var cookie = request.getCookies().get("stargate_session");
                if (cookie == null || manager.sessions().get(cookie.getValue()) == null) reject(request, 401, "SESSION_REQUIRED");
            }
            return;
        }
        String authorization = request.getHeaderString("Authorization");
        if (!manager.authorized(authorization)) {
            reject(request, 401, "MANAGER_AUTH_REQUIRED");return;
        }
        if (!request.getMethod().equals("GET") && !json(request))
            reject(request, 415, "JSON_REQUIRED");
    }

    private static boolean json(ContainerRequestContext request) {
        return request.getMediaType() != null && "application/json".equalsIgnoreCase(request.getMediaType().getType() + "/" + request.getMediaType().getSubtype());
    }

    private static void reject(ContainerRequestContext request, int status, String code) {
        request.abortWith(Response.status(status).type("application/json").entity(Map.of("code", code)).build());
    }

    @Override public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        var headers = response.getHeaders();headers.putSingle("Cache-Control", "no-store");
        headers.putSingle("Content-Security-Policy", "default-src 'none'; script-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
        // Native form posts need their same-origin Origin header. no-referrer makes it null in Firefox.
        headers.putSingle("X-Content-Type-Options", "nosniff");headers.putSingle("X-Frame-Options", "DENY");headers.putSingle("Referrer-Policy", "same-origin");
    }
}
