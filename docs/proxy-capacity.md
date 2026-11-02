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
These existing values were not validated by the measurements below and are not
measured recommendations. The bounded local reference does not select new
defaults or establish actual Tor, I2P or Nym route capacity, latency or throughput.

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


## Measured local reference (2026-10-28)

One bounded run passed with **1 GiB for the app and a global limit of 1024**.
Existing Compose overrides corresponding to those measured values are:

```dotenv
STARGATE_MAX_CONNECTIONS=1024
STARGATE_APP_MEMORY_LIMIT=1g
```

The fixture set `maxConnections=1024` directly and imposed a 1073741824-byte
app container memory limit; this example selects the corresponding existing
Compose controls. Follow the configuration review and recreation procedure above
when applying overrides. This is a tested reference, not a general sizing
recommendation or a new default. The memory limit covers the proxy and manager,
not the separate Tor, I2P, Nym or test-driver processes.

The measured workload used local TLS with certificate/hostname verification and a mock SOCKS echo upstream
in an isolated network with no public-network access. The app had no CPU quota;
the separate driver had a 2-CPU quota. The ramp used a 1/64-second delay after
each sequential connection setup and verification.
All 1024 held tunnels exchanged 8192-byte payloads per round with 0.2-second
pacing for 60.09 seconds: 216 rounds, 221184 echoes and 1811939328 verified
payload bytes. Measured echo p95 was 57.23 ms and maximum 360.63 ms, below the
fixture's experimental 1000-ms stop criterion. This is a paced workload, not an
unrestricted throughput benchmark.

At saturation, an additional connection was refused while admitted tunnels
continued working. Closing one tunnel released a slot and a new connection from
synthetic device B succeeded. Actual manager revocation of synthetic device A
closed its tunnels and rejected a new A connection while B's tunnels survived.
Final proxy admission/active counts and mock-upstream active/tunnel counts were
zero, with no mock protocol errors. The global refusal counter also includes
manager probes; its increase is not an exact count of the fixture's refused
connection attempts.

Earlier runs with a global limit of 2048 tested 2000 simultaneous tunnels: the
1-GiB run failed the 1000-ms echo criterion with a 1711.11-ms round maximum;
sampled OOM and OOM-kill counters remained zero. A 2-GiB run passed that tested
stage, with a 993.43-ms maximum. These outcomes establish neither a maximum nor
that memory alone caused the latency difference. They do not measure typical
browser-tab demand, public-route performance, long-duration stability or fair
sharing between devices.
