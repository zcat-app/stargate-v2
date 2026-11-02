// Copyright 2026 The Stargate Authors
// SPDX-License-Identifier: Apache-2.0
package app.zcat.stargate.manager;

/** HTML is rendered on the server. All displayed values are escaped; graphs use fixed numeric CSS classes. */
final class WebUi {
    private WebUi() {}
    static String escape(Object value) {
        if (value == null) return "unknown";
        return value.toString().replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;");
    }
    static String page(ManagerService manager, WebSessions.Session session, String message, Pairing.Ticket ticket) {
        StringBuilder html = new StringBuilder("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Stargate</title><link rel=\"stylesheet\" href=\"/charts.css\"><link rel=\"stylesheet\" href=\"/style.css\"></head><body><main><header><p class=\"eyebrow\">STARGATE · LOCAL CONTROL</p><h1>Your route. Your control.</h1><p>Browse .onion through Tor and .i2p through I2P.</p></header>");
        if (message != null) html.append("<p class=\"notice\" role=\"status\" id=\"notice\">").append(escape(message)).append("</p>");
        if (session == null) {
            html.append("<section><h2>Unlock manager</h2><p>Use the administrator token from your private installation. Sessions expire after 30 minutes.</p><form method=\"post\" action=\"/login\" id=\"login-form\"><label for=\"token\">Administrator token</label><input id=\"token\" name=\"token\" type=\"password\" required maxlength=\"128\" autocomplete=\"off\"><button type=\"submit\">Unlock manager</button></form></section>");
        } else {
            var status = manager.status();
            var release = manager.releaseMonitor();
            var consumer = manager.consumerMonitor();
            html.append("<nav><a href=\"/\">Refresh observations</a>").append(form("/logout", session, "Lock manager", "")).append("</nav>");
            if (release != null) html.append(releaseMonitor(release));
            if (consumer != null) html.append(consumerMonitor(consumer));
            html.append(manager.upgrades().html(session));
            html.append("<section><h2>Proxy</h2><dl><dt>Process</dt><dd id=\"process-state\">").append(escape(status.process().activeState()))
                    .append("</dd><dt>PID</dt><dd id=\"process-pid\">").append(escape(status.process().pid()))
                    .append("</dd><dt>Endpoint</dt><dd id=\"proxy-state\">").append(escape(status.proxy().state()))
                    .append("</dd><dt>Listener belongs to proxy</dt><dd>").append(escape(status.proxy().ownedByProcess())).append("</dd></dl><div class=\"actions\">");
            for (String action : java.util.List.of("start", "stop", "restart")) html.append(form("/control/" + action, session, Character.toUpperCase(action.charAt(0)) + action.substring(1), ""));
            html.append("</div></section><section><h2>Tor</h2><dl><dt>Readiness</dt><dd id=\"tor-state\">").append(escape(status.tor().readiness()))
                    .append("</dd><dt>Bootstrap</dt><dd>").append(escape(status.tor().bootstrapPercent()))
                    .append("</dd><dt>Control observation</dt><dd>").append(escape(status.tor().control()))
                    .append("</dd><dt>Version</dt><dd>").append(escape(status.tor().version())).append("</dd></dl><p>Observed at ").append(escape(status.observedAt())).append(". Tor is managed separately.</p></section>");
            var i2p = status.i2p();
            html.append("<section><h2>I2P</h2><dl><dt>Router bootstrap readiness</dt><dd id=\"i2p-state\">").append(escape(i2p.readiness()))
                    .append("</dd><dt>SOCKS listener</dt><dd id=\"i2p-socks\">").append(escape(i2p.socks() == null ? null : i2p.socks().state()))
                    .append("</dd><dt>Control observation</dt><dd>").append(escape(i2p.control()))
                    .append("</dd><dt>Shared destination ready</dt><dd>").append(escape(i2p.sharedDestinationReady()))
                    .append("</dd><dt>Active peers</dt><dd>").append(escape(i2p.activePeers()))
                    .append("</dd><dt>Inbound / outbound tunnels</dt><dd>").append(escape(i2p.inboundTunnels())).append(" / ").append(escape(i2p.outboundTunnels()))
                    .append("</dd><dt>Destination traffic received</dt><dd id=\"i2p-access\">").append(escape(i2p.destinationAccess()))
                    .append("</dd><dt>Version</dt><dd>").append(escape(i2p.version()))
                    .append("</dd></dl><p>A listening port does not prove network readiness. Received traffic is a past observation in this proxy process, not a guarantee for the next destination. I2P is managed separately. When device isolation is enabled, container device routes use separate persistent destinations. Other configurations use the shared route. These router bootstrap observations do not prove an individual device route is ready. An unused device listener may be dormant until its next request; destination readiness remains unknown until actual traffic.</p></section>");
            var nym = status.nym();
            html.append("<section><h2>Nym</h2><dl><dt>Network readiness</dt><dd id=\"nym-state\">").append(escape(nym.readiness()))
                    .append("</dd><dt>SOCKS listener</dt><dd id=\"nym-socks\">").append(escape(nym.socks() == null ? null : nym.socks().state()))
                    .append("</dd><dt>Destination traffic received</dt><dd id=\"nym-access\">").append(escape(nym.destinationAccess()))
                    .append("</dd></dl><p>Opt-in ordinary web route. A SOCKS acknowledgement does not prove mixnet access. Received traffic is a past observation in this proxy process. Profiles share one Nym client; there is no Tor-style credential isolation. Bandwidth availability depends on the gateway; free grants are not guaranteed.</p></section>");
            html.append("<section id=\"traffic\"><h2>Aggregate traffic</h2><p>Tor, I2P and Nym · current proxy process lifetime · no destination or client labels. Counters reset when the proxy restarts.</p>");
            var traffic = TrafficStats.read(manager.metricsPath(), status.process());
            html.append("<p id=\"traffic-state\">").append(escape(traffic.state())).append("</p>");
            if (traffic.counters() != null) {
                var c = traffic.counters();
                html.append("<p>Snapshot ").append(escape(c.observedAt())).append(" · proxy PID ").append(c.pid()).append(" · active connections ").append(c.active()).append("</p>");
                html.append(chart("bytes-chart", "Forwarded bytes", new String[]{"To networks", "From networks"}, new long[]{c.uploaded(), c.downloaded()}, "bytes"));
                html.append(chart("connections-chart", "Authenticated connections", new String[]{"Authenticated", "SOCKS acknowledged", "Upstream failures"}, new long[]{c.connections(), c.connected(), c.failures()}, "connections"));
                html.append("<p class=\"muted\">HTTP body bytes and raw CONNECT/WebSocket tunnel bytes; excludes proxy headers and SOCKS negotiation. These are connection counters, not HTTPS page or request counts. LAST_PROCESS means a saved final observation, not live traffic.</p>");
            } else html.append("<p>Fresh counters are unavailable. Start the proxy or refresh after startup.</p>");
            html.append(admission(traffic.admission()));
            html.append("</section><section><h2>Pair a device</h2><p>Each redeemed code creates a separate device credential and Tor isolation identity. With I2P device isolation enabled, each device has an independent persistent I2P identity. Its destination starts on the first I2P request and is unloaded after all connections close and a short cooldown. Silent open connections keep it running. New I2P routes can take several minutes to build tunnels. No account is required. Codes are single-use; paired devices do not expire with the code. Anyone holding a code can pair a device, so send it privately. A longer lifetime increases exposure. Pending codes are invalidated when the manager restarts. New credentials normally activate in the running proxy within one second; if an immediate request fails, retry it without pairing again.</p>");
            html.append(form("/pairing", session, "Create one-time code", "<label for=\"device-label\">Device name</label><input id=\"device-label\" name=\"label\" value=\"My-browser\" required maxlength=\"32\" pattern=\"[A-Za-z0-9_-]{1,32}\"><p>Letters, numbers, hyphens and underscores. Use a name you can recognize later.</p><label for=\"lifetime\">Code lifetime</label><select id=\"lifetime\" name=\"lifetime\"><option value=\"5m\">5 minutes</option><option value=\"24h\">24 hours</option></select>"));
            if (ticket != null) html.append("<label for=\"pairing-code\">One-time pairing code</label><input id=\"pairing-code\" readonly value=\"").append(escape(ticket.code())).append("\"><p>Device name ").append(escape(ticket.label())).append(" · expires ").append(escape(ticket.expiresAt())).append(" · Invitation reference <code>").append(escape(ticket.id())).append("</code></p>");
            html.append("<h3>Pending invitations</h3><p>Codes are shown only when created. Use the invitation reference shown with the code to identify the exact invitation to cancel. Cancel an unused invitation if it is no longer needed or may have been exposed.</p>");
            for (var invitation : manager.invitations()) html.append("<div>").append(escape(invitation.label())).append(" · expires ").append(escape(invitation.expiresAt())).append(" · Invitation reference <code>").append(escape(invitation.id())).append("</code>").append(form("/pairing/cancel", session, "Cancel invitation", "<input type=\"hidden\" name=\"id\" value=\"" + escape(invitation.id()) + "\">" )).append("</div>");
            html.append("</section><section><h2>Paired devices</h2><p>Match this identifier with the extension before revoking. Revocation closes that credential's active connections after refresh, normally within one second. Other devices keep working.</p><p>Credentials retained from older installations may be shared. Pair each device again, then revoke the old credential. Nym identity remains shared. With device isolation enabled, I2P routes have separate persistent destinations per credential; devices still share one router and host. No per-website isolation. Stopping and enabling I2P preserves its identity; it does not rotate identity. Revocation retires the route, but its private key file remains in the router volume.</p>");
            for (String id : manager.profiles()) {
                html.append("<div><code>").append(escape(id)).append("</code>").append(form("/devices/revoke", session, "Revoke device", "<input type=\"hidden\" name=\"deviceId\" value=\"" + escape(id) + "\">"));
                boolean enabled = manager.i2pEnabled(id);
                if (manager.i2pDeviceIsolation() && (enabled || manager.canEnableI2p(id))) html.append(form("/devices/i2p", session, enabled ? "Stop I2P for device" : "Enable I2P for device", "<input type=\"hidden\" name=\"deviceId\" value=\"" + escape(id) + "\"><input type=\"hidden\" name=\"enabled\" value=\"" + !enabled + "\">"));
                html.append("<p class=\"i2p-device-state\">").append(escape(I2pDeviceStatus.describe(manager.i2pDeviceStatus(id,status.process())))).append("</p></div>");
            }
            html.append("<p>I2P lifecycle: ").append(escape(manager.i2pLifecycleObservation())).append(".</p>");
            html.append("<p>I2P device configuration: ").append(manager.i2pConfigurationAvailable() ? "identity mappings reconciled; the proxy activates routes on demand; network readiness requires actual traffic" : "unavailable; inspect configuration").append(".</p></section>");
        }
        return html.append("<footer>Server-rendered controls and Charts.css graphs. No JavaScript or external assets.</footer></main></body></html>").toString();
    }
    static String releaseMonitor(ReleaseMonitor.Observation release) {
        return "<section><h2>Release observation snapshot</h2><dl><dt>Latest published attempt</dt><dd id=\"release-monitor-state\">"
                + escape(release.latest()) + "</dd><dt>Attempt time</dt><dd>" + escape(release.attemptAt())
                + "</dd><dt>Published at</dt><dd>" + escape(release.publishedAt())
                + "</dd><dt>Freshness limit for attempt and publication</dt><dd>" + release.limitSeconds()
                + " seconds</dd></dl><p>This is the latest published snapshot. A later attempt is not reflected until a new snapshot is published. Observed means the recorded metadata checks were observed; security and deployment are not assessed.</p></section>";
    }
    static String consumerMonitor(ReleaseMonitor.ConsumerObservation consumer) {
        return "<section><h2>Consumer outcome snapshot</h2><dl><dt>Latest published outcome</dt><dd id=\"consumer-monitor-state\">"
                + escape(consumer.outcome()) + "</dd><dt>Local acceptance</dt><dd>" + escape(consumer.localAcceptance())
                + "</dd><dt>Future collection blocked</dt><dd>" + escape(consumer.futureCollectionBlocked())
                + "</dd><dt>Attempt time</dt><dd>" + escape(consumer.attemptAt())
                + "</dd><dt>Published at</dt><dd>" + escape(consumer.publishedAt())
                + "</dd><dt>Freshness limit for attempt and publication</dt><dd>" + consumer.limitSeconds()
                + " seconds</dd></dl><p>This is the latest published outcome, not necessarily the latest invocation or its exit status. "
                + "An error closing the consumer lock or writing stdout can follow publication. Local acceptance does not prove phone delivery. "
                + "Unknown includes an incomplete finish; it does not prove a process is running. Blocked collection can leave upstream changes unobserved. "
                + "This snapshot provides no missed-run alarm, phone-delivery monitor or automatic reconciliation.</p></section>";
    }
    static String admission(TrafficStats.Admission admission) {
        StringBuilder html = new StringBuilder("<h3>Global connection admission</h3>");
        if (!"CURRENT".equals(admission.state())) return html.append("<p id=\"admission-state\">Unavailable</p>").toString();
        return html.append("<dl id=\"admission-state\"><dt>Global connection limit</dt><dd>").append(admission.limit())
                .append("</dd><dt>Accepted sockets, including before authentication</dt><dd>").append(admission.occupancy())
                .append("</dd><dt>Connection-limit refusals since proxy start</dt><dd>").append(admission.refusals())
                .append("</dd></dl><p>Occupancy is a transient snapshot and can briefly exceed the limit while refused sockets close. Past refusals do not mean the limit is currently full. Capacity is shared across devices.</p>").toString();
    }
    private static String form(String action, WebSessions.Session session, String label, String fields) {
        return "<form method=\"post\" action=\"" + action + "\"><input type=\"hidden\" name=\"csrf\" value=\"" + session.csrf() + "\">" + fields + "<button type=\"submit\">" + label + "</button></form>";
    }
    private static String chart(String id, String title, String[] labels, long[] values, String unit) {
        long max = Math.max(1, java.util.Arrays.stream(values).max().orElse(1));
        StringBuilder html = new StringBuilder("<p class=\"chart-summary\">");
        for (int i = 0; i < values.length; i++) {
            if (i > 0) html.append(" · ");
            html.append(labels[i]).append(": <strong>").append(values[i]).append(' ').append(unit).append("</strong>");
        }
        html.append("</p><table id=\"").append(id).append("\" class=\"charts-css bar show-heading show-labels show-data-axes data-spacing-8\"><caption>").append(title).append(" · scale 0–").append(max).append(' ').append(unit).append("</caption><tbody>");
        for (int i = 0; i < values.length; i++) {
            int size = (int) Math.round(100.0 * values[i] / max);
            html.append("<tr><th scope=\"row\">").append(labels[i]).append("</th><td class=\"pct-").append(size).append("\"><span class=\"data\">").append(values[i]).append("</span></td></tr>");
        }
        return html.append("</tbody></table>").toString();
    }
}
