# Quarkus manager

Start with the [operator guide](../docs/operator-guide.md) for private login,
invitations, everyday controls and recovery. Ordinary browser users should use
the separate [user guide](../docs/user-guide.md).

The recommended [container installation](../containers/README.md) runs separate
manager and proxy JVMs under a supervisor, with a private owner-only Unix control
socket. Tor and I2P each run in their own container. The authenticated UI uses
server-rendered HTML, native forms and bundled Charts.css, with no page JavaScript.
The manager operates the proxy; it has no Docker-socket access.

Status distinguishes the proxy process, its HTTP authentication challenge and
Linux listener ownership. Tor observations require authenticated control data
and a SOCKS greeting. I2P observations separately show SOCKS availability,
authenticated router/tunnel readiness and destination data observed during the
current proxy process. Readiness does not guarantee that another destination is
reachable. Missing control observations remain unavailable.

Closing the page or restarting the manager leaves forwarding running. Container
pairing credentials and desired proxy state persist in named volumes. Aggregate
traffic counters contain no browsing destinations and reset with the proxy process.

## Development and packaging

The supported installation is the [container deployment](../containers/README.md),
with the manager and proxy as separate JVMs inside the app container. Follow the
[operator guide](../docs/operator-guide.md) for setup, token export and controls;
use the [persistent deployment guide](../docs/persistent-deployment.md) for the
reviewed service installation. The former direct-host configuration generator and
its generated user-unit setup are retired and are no longer published.

Build from the project root with the existing Java 25 JDK and Maven:

```sh
mvn --batch-mode --no-transfer-progress package
```

Keep the entire `manager/target/quarkus-app` directory together. For an already
configured development installation, the systemd backend and direct JVM entry
point remain available; this command does not generate configuration
or establish a new supported host setup:

```sh
java -Dstargate.config="/absolute/private/manager.properties" \
  -Dquarkus.http.port=9080 -jar manager/target/quarkus-app/quarkus-run.jar
```

Restart the manager after changing its existing private configuration. The
manager and its proxy service must select the same proxy configuration. Packaged
installation and two-network operation use the container procedure above.

## Authentication and controls

Login exchanges the administrator token for an HttpOnly, SameSite=Strict cookie
that expires after 30 minutes. Native mutations require that session, a separate
CSRF value and the exact management Origin. The token is not placed in a URL or
given to the extension. Pairing issues a single-use code, valid for five minutes
by default or 24 hours if explicitly selected; redemption creates a unique device ID/token and returns an origin-bound read-only manager
grant. Names may repeat without sharing credentials. The device store atomically
updates the private proxy configuration; the proxy refreshes credentials every
250 ms without resolving sidecar names or restarting. New credentials normally
activate within one second; pairing completion does not acknowledge proxy loading. Grants survive manager restart with unchanged keys. Rotating the manager
or device token invalidates existing grants; pending codes disappear on restart.
Revocation removes one credential and closes its active connections after refresh
without interrupting other devices. An unreadable/malformed proxy credential file
causes the proxy to reject all credentials and close active connections. An empty
set is valid and authorizes nobody. One manager owns writes; manual edits while it
is running and multiple manager writers are unsupported.

The code issuance response includes `code`, `label`, `expiresAt` and `id`. This
nonsecret invitation `id` matches the pending list and cancellation request. The
authenticated page shows it as the invitation reference beside the newly created
code and in its pending row. Match the full reference before cancelling when names
or expiry times repeat. Codes are still shown only when created.

Existing credentials are retained on upgrade and may be shared. Pair each device
again and explicitly revoke the older credentials. There are no user accounts.
Nym client identity remains shared; Tor partitions are per credential, not
per website. With I2P device isolation enabled, each credential has a separate
persistent destination while the router and host remain shared. See [privacy limits](../docs/user-guide.md#what-privacy-this-provides).

| Method | Path | Result |
| --- | --- | --- |
| GET | `/api/status` | Fresh process, proxy, Tor and I2P observations |
| GET | `/api/traffic` | Aggregate current-process counters, or an explicit unavailable/stale state |
| POST | `/api/pairing/code` | Create a single-use code with JSON `{"label":"My-browser"}`; optionally set `"lifetime":"24h"` (default `"5m"`) |
| GET | `/api/pairing/invitations` | List pending invitation IDs, labels and expiry times, never codes |
| POST | `/api/pairing/cancel` | Cancel a pending invitation with JSON `{"id":"…"}` |
| GET | `/api/pairing/profiles` | List credential IDs (including legacy IDs), never tokens |
| POST | `/api/devices/revoke` | Revoke JSON `{"deviceId":"…"}` without restarting other devices |
| POST | `/api/proxy/start` | Start the configured proxy and observe readiness |
| POST | `/api/proxy/stop` | Stop the proxy and observe listener closure |
| POST | `/api/proxy/restart` | Restart the proxy and observe readiness |

These administrator API requests require `Authorization: Bearer <manager.token>`.
Mutations additionally require the exact Origin and JSON content type. Start is
idempotent; operations are serialized. Start/Restart success requires the owned
process and a responding proxy listener. Failure or timeout does not imply that
the requested transition completed. HTTP clients cannot supply arbitrary unit
names, process IDs, shell commands or Tor control commands.

Direct mode binds to loopback. Container mode binds inside the app container,
while Compose publishes only loopback manager/proxy ports. Host and Origin checks
remain active. The login page and static styles are public; protected data needs
a session or API authorization. CSP forbids page scripts. HTTP/2 and HTTP
compression/decompression are disabled, and non-identity Content-Encoding is
rejected.

## Optional Nym observations

When Nym is enabled in the proxy configuration, status includes a Nym SOCKS
probe, `UNKNOWN`/`UNAVAILABLE` network readiness and historical destination
traffic from current-process counters. SOCKS acknowledgements are local and
never become a `READY` claim. Aggregate labels include all three networks.
No Nym secret, native control interface or Docker socket is exposed to the manager.
