// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

import io.vertx.ext.web.Router;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

/** Guard the actual TLS listener before REST, static files or framework routes. */
@ApplicationScoped
public class PublicDeviceApi {
    @Inject ManagerService manager;
    void routes(@Observes Router router) {
        String origin = manager.publicOrigin();
        String expected = origin == null ? null : java.net.URI.create(origin).getRawAuthority();
        router.route().order(Integer.MIN_VALUE).handler(context -> {
            var request = context.request();
            if (!request.isSSL()) { context.next(); return; }
            boolean allowed = permitted(request.method().name(), request.uri()) && expected != null
                    && request.headers().getAll("Host").size() == 1 && expected.equals(request.getHeader("Host"));
            if (!allowed) {
                context.response().setStatusCode(403).putHeader("Content-Type", "application/json")
                        .putHeader("Cache-Control", "no-store").putHeader("X-Content-Type-Options", "nosniff")
                        .end("{\"code\":\"PUBLIC_ENDPOINT_REJECTED\"}");
                return;
            }
            context.next();
        });
    }
    static boolean permitted(String method, String uri) {
        return (method.equals("POST") && uri.equals("/api/pairing/redeem"))
                || (method.equals("GET") && uri.equals("/api/extension/status"));
    }
}
