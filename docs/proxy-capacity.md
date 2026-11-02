# Proxy capacity settings

`STARGATE_MAX_CONNECTIONS` sets the maximum simultaneous admitted proxy client
connections across the listeners and routes. It counts sockets in setup as well
as established tunnels, not users, devices, registered profiles or browser tabs.
One browser can open many connections. The limit does not reserve capacity per
device or guarantee upstream throughput. A single device can consume all available
slots, causing new connections from other devices to be refused while admitted
tunnels remain active.

`STARGATE_APP_MEMORY_LIMIT` sets the Compose app container's memory limit, covering
both its proxy and manager JVMs and their native memory. Use a Compose memory
size such as `512m`. Tor, I2P and optional Nym
run in separate containers with separate memory budgets. Account for those
services and the host when sizing the installation.

For a new installation, copy `.env.example` to `.env`; for an existing `.env`,
add or update only the overrides you intend. Leave `STARGATE_MAX_CONNECTIONS`
unset to preserve an existing stored connection limit.

For an existing deployment, retain its exact Compose project name and directory,
environment files, profiles and complete ordered Compose file list, including
`compose.nym.yaml`, remote TLS configuration and other overrides in use. Preserve
the selected images and volume mappings. Use that same Compose invocation with
`config` and review the resolved configuration before applying changes. Then use
the same reviewed arguments with `up -d --no-deps --force-recreate app` to
recreate only the app; its dependencies must already be running. Coordinate this
with active users: existing connections close. Compose `restart app` does not
reload environment values or the memory limit.

For remote TLS deployments, first follow the existing
[configuration-generation procedure](remote-access.md#generate-deployment-configuration).
`bash tools/setup-wizard.sh` writes resolved environment and memory values into
its output YAML, so editing `.env` does not update an existing generated file.
Regenerate into a new private output using the original source Compose inputs
and their order, the same project and environment files, and the existing public
origin, TLS ports and certificate directory. Review the regenerated configuration,
including TLS mounts, images and state-volume mappings, before using it in the
reviewed app-only recreation invocation above.

When no connection limit is stored or explicitly configured, the proxy retains
its historic fallback of 128. Compose retains 512m as the app memory default.
These fallback values are not sizing recommendations. Actual Tor, I2P and Nym
capacity, latency and throughput depend on the selected host, routes and workload.

On Supervisor initialization, an explicit `STARGATE_MAX_CONNECTIONS` wins over
`maxConnections` already in `/data/proxy.properties`, and the updated properties
are published through the existing atomic configuration replacement. The value
must match `[1-9][0-9]*` and be representable by Java's `int`; invalid values
fail before initialization mutates files. Compose passes this variable only
when configured in the shell or `.env`; it supplies no numeric connection default.
If the variable is unset, both Compose startup and direct Supervisor invocation
preserve the existing `maxConnections` property. If neither an environment
override nor a stored property exists, the proxy's historic fallback of 128
applies. An explicitly empty value is invalid in either startup path.

The direct Java proxy invocation already accepts `maxConnections` through
`--config /absolute/path/proxy.properties`; it does not read the Compose setting.
Restart the proxy after editing that property. The app memory variable is a
Compose container setting, not a Java heap setting.


## Choose limits for your deployment

Size the connection budget and app memory together for the intended workload.
Monitor connection refusals, memory use and request latency before raising a
limit. Local capacity measurements do not establish public-route performance or
fair sharing between devices. Keep the Tor, I2P, Nym and host memory budgets
separate from the app budget, and follow the configuration review and app-only
recreation procedure above when applying changes.
