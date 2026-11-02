# Optional SimpleX outbound alert runtime

This optional runtime contains a dedicated SimpleX v7.0.0 process and one-shot
sender. It is a building block for the requested daily security-monitor alerts
and failed-check alerts. The separate [Java monitor](java-monitor.md) now
produces and schedules those alerts; this runtime only sends them. It
cannot automatically become a reliable pager: local command acceptance does not
establish recipient delivery, and timeout/retry can duplicate an alert.

Use [profile provisioning](simplex-alert-profile-provision.md) to establish the
dedicated identity and recipient before enabling delivery.

The base Compose file, application, manager, proxy, and parent Maven build remain
unchanged. This deployment has no credentials or mounts for Stargate services,
Docker, the browser, or AI services. Nothing interprets incoming messages or
implements user slash commands, AI, groups, or inbound control. The upstream
SimpleX process can still receive and store messages; this application ignores
those events. The WebSocket API inherently accepts upstream commands from anyone
who can reach it; network namespace isolation contains that API.

## Prepare and review

The runtime targets Linux amd64 with the existing documented patched runtime image
inputs and Java 25.0.5. It does not supply a clean-host builder. Prepare the normal
runtime inputs using [the container runbook](../containers/README.md); they contain
runtime libraries and the JRE, not live application state. Build this independent
module explicitly:

```sh
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress -f simplex-alert/pom.xml clean package
bash tools/prepare-simplex-alert.sh \
  --release-dir /absolute/path/to/verified-simplex-v7 \
  --runtime-inputs /absolute/path/to/target/container
```

The release directory must contain `simplex-chat`, `_sha256sums`,
`_sha256sums.asc`, and `release-key.asc` from the official v7.0.0 release. The
preparer performs no download and starts no services. It checks the pinned binary
SHA-256, exact artifact entry in the signed manifest, and a valid detached GPG
signature from fingerprint `BBDF7BDAD1548B16836AF5B9D53BDFD153C366BA`.
This key matches the upstream-published fingerprint; there has been no independent
out-of-band authentication of its owner. The manifest, signature, key, release
pin, AGPL license, source location, and image input hashes are retained in the
image. The original upstream binary is used without modification. The source is
[SimpleX v7.0.0](https://github.com/simplex-chat/simplex-chat/tree/v7.0.0).

The additional two upstream-required runtime libraries come from the repository's
immutable Ubuntu base image; their exact versions and file hashes are recorded in
`containers/simplex-alert/libraries.json`. See the [security review and unresolved
coverage gaps](simplex-alert-security-review.md) before deployment. A hash match
is not a security assessment.

The release binary SHA-256 is
`393279f37a57ff7a63b92cffbd583d1d8abb5ea13e28f8caea74539d7c8db91d`
and it reports `SimpleX Chat v7.0.0.11`. The pin matches
[InfoChat's recorded integration](https://github.com/zcat-app/infochat/tree/3757850ef7d66d4b2d62cd3cf0a0fa17c1b7e637).

Before starting, supply a **dedicated, stopped, already established SimpleX
profile** with the intended recipient contact. Its database prefix must be `db`
(`db_chat.db` and `db_agent.db`). Copy the whole stopped profile consistently,
including any relevant WAL/sidecar files. Do not copy a database while its owner
is running, share a live profile, or reuse a personal profile. Keep all private
keys and profile backups confidential. The directory must be mode 0700 and the
whole tree owned by numeric UID 10001; symlinks and special entries are rejected.
Inspect the intended directory before applying ownership changes.

The profile must already match the pinned v7 database schema. The launcher does
not pass `-y` or otherwise approve migrations. Matching databases can open without
confirmation; a required migration prompts for approval, and the launcher's
`/dev/null` stdin supplies EOF so startup fails before that migration. If an
upgrade is needed, perform it as a separate offline operator step with a verified,
consistent stopped backup, then verify the migrated profile before enabling this
runtime. Normal compatible-schema operation still writes ordinary SimpleX state;
this is not a read-only profile or a backup/migration workflow.

The runtime launcher does not create profiles, pair contacts or import databases.
See the [profile provisioning procedure](simplex-alert-profile-provision.md).
An operator must establish that dedicated profile and independently verify the
recipient identity and numeric contact ID before enabling the runtime. The code
validates ID syntax, not identity or whether that contact exists. It refuses
missing databases rather than creating an unpaired identity silently. Encrypted
profiles that require an interactive database password are unsupported here;
no password is accepted through process arguments or environment variables.

Set only the non-content configuration in your shell:

```sh
export SIMPLEX_ALERT_PROFILE=/absolute/path/to/dedicated/stopped/profile
export SIMPLEX_ALERT_CONTACT_ID=123

docker compose --project-name stargate-simplex-alert \
  --file compose.simplex-alert.yaml build
```

Review the output of `docker compose --project-name stargate-simplex-alert --file
compose.simplex-alert.yaml config` before use. Always use this **standalone file
and separate project name**. It is not an overlay for the base Stargate stack.
Use an explicitly unique image/project name if multiple copies are required.

## Explicit activation and sending

Starting is a deliberate operator action after profile and recipient review:

```sh
docker compose --project-name stargate-simplex-alert \
  --file compose.simplex-alert.yaml up -d
```

After deliberate activation, `unless-stopped` restarts the dedicated runtime on
failure and after host boot. A deliberate container stop keeps it stopped.
The runtime does not run the daily monitor or replay its delivery records;
accepted/uncertain-send handling remains in the separate monitor. There is no
readiness health check. A running container is not proof that SimpleX is ready
or the contact can receive messages. The sender reports `NOT_SUBMITTED` if it
cannot open its local connection; never infer that running means delivery works.

For an existing installation, source changes alone do not update the container's
policy. Use the separately reviewed
[persistence activation procedure](simplex-sender-persistence.md), preserving the
image, private profile, recipient and delivery receipts.

Supply alert text only on standard input from a producer that closes its output;
for example a reviewed, private UTF-8 file, 1–4000 bytes including newlines:

```sh
docker compose --project-name stargate-simplex-alert \
  --file compose.simplex-alert.yaml exec -T simplex-alert \
  /opt/java/bin/java -XX:ErrorFile=/dev/null -XX:-CreateCoredumpOnCrash \
  -jar /opt/simplex/simplex-alert.jar < /absolute/path/to/private-alert.txt
```

The sender writes only one result token. `ACCEPTED` means the correlated local
response identified one sent chat item for the configured numeric contact;
recipient delivery remains unknown. `REJECTED` means a recognized correlated
command error, `NOT_SUBMITTED` means no send attempt, and `UNKNOWN` means an
attempt may have reached the server. `INVALID_INPUT` means invalid input/config.
See the [transport details](../simplex-alert/README.md) for exit codes, separate
phase timeouts, the unbounded stdin wait, and why automatic retry is unsafe.

Do not put content in shell arguments, environment variables, Compose commands,
logs, or an upstream CLI invocation. The upstream v7 server prints full commands
including message text. The Java launcher redirects **both streams to `/dev/null`
before starting the child**, and Docker logging is disabled as a second measure.
The upstream message databases still retain content. Output suppression removes
upstream diagnostics; it is not a claim that all possible application writes have
been audited. The core-size limit is zero and JVM fatal core/error-file output is disabled;
host-level crash collectors and other kernel/supervisor paths were not audited.

The pinned upstream server's dependency explicitly binds IPv4 `127.0.0.1`; it
does not bind an IPv6/wildcard listener. See
[the pinned transport source](https://github.com/simplex-chat/simplexmq/blob/efaad8e73436d60f5052f07dda6b71151ad5039b/src/Simplex/Messaging/Transport/Server.hs#L167-L170).
No ports are published and the container joins only its own egress bridge. Peer
containers cannot reach that loopback listener through the container IP. The
sender is invoked inside the same container through operator-authorized Docker
exec. The service can connect directly to SimpleX's public relays: this runtime
does not provide Tor/Nym routing or host-wide outbound confinement.

The Docker administrator, host root, and any process deliberately started inside
that container/network namespace remain trusted and can reach the unauthenticated
API, impersonate contacts, or read the profile. This does not provide isolation
against those principals. Unrelated containers must never be given its namespace.

Stop only this separate project with:

```sh
docker compose --project-name stargate-simplex-alert \
  --file compose.simplex-alert.yaml down
```

The bind-mounted profile survives. Back up only while stopped, protect that copy,
and do not run two owners concurrently. Stopping or process termination during a
send can leave the result unknown.

## Automatic alerts and context preparation

Each deployment needs a reviewed dedicated profile and verified recipient.
Agree any live test with the recipient; local acceptance does not establish
phone delivery or future reliability. The [Java monitor](java-monitor.md)
maps daily observations into minimized text, records outcomes and runs on the
operator's daily timer. Follow that guide and the [alert guide](simplex-alerts-guide.md)
for blocked/unknown outcomes. The sender runtime has no access to private monitor
state or production services; the host monitor invokes its narrow sending entrypoint.

The Bash preparer requires standard GNU Linux utilities, jq and GnuPG as well
as the existing qualified runtime inputs. It verifies the copied binary and
signed manifest again before publishing a fresh private context. Existing
output is refused. For a new attempt, preserve the old context or remove only
its reviewed public build directory after checking its path. A normal failure
removes its own temporary public staging and GPG homes. SIGKILL can leave a
`.simplex-stage.*` directory: inspect that exact path before removal.
Do not use this cleanup advice for profile/database storage. Keep source files
and selected build inputs unchanged throughout staging.

The provenance inventory hashes regular files and records image symlink targets
literally; it never follows image links into the host. The context stays 0700;
the copied sender JAR/provenance are readable by the image's unprivileged UID.
