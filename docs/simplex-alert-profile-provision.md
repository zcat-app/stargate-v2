# Prepare a dedicated SimpleX alert profile

This procedure uses a dedicated SimpleX identity on the same VPS as Stargate.
The profile is new and unpassphrased, so the VPS storage, private directory
permissions, backups and host administrator protect its identity keys and
message database. It does not open, copy, decrypt or change a personal profile.
The SimpleX process may receive and store messages; Stargate does not interpret
inbound messages or commands. No AI integration is involved.

Create the private profile, scan its one-time contact QR on the intended phone,
and confirm the connected contact and its numeric ID. Agree one non-sensitive
test message with the recipient and confirm it arrived; do not automatically
retry an unknown send. This integration needs no application-registration code,
user roles or inbound command handler.

## Release and API boundaries

The pinned binary is SimpleX v7.0.0.11 with SHA-256
`393279f37a57ff7a63b92cffbd583d1d8abb5ea13e28f8caea74539d7c8db91d`.
The v7.0.0 source has `--database`/`-d` as the path prefix and an empty default
`--key` in `src/Simplex/Chat/Options/SQLite.hs`; its two filenames are
`<prefix>_chat.db` and `<prefix>_agent.db`. The parser and startup in
`src/Simplex/Chat/Options.hs` and `src/Simplex/Chat/Core.hs` create the named bot
profile only if no active user exists. That metadata does not install an inbound
handler. The retained source archive is the v7.0.0 tree; matching its version string to the
signed binary is not a cryptographic source-to-binary attestation.

In v7, `-e /connect` executes the command then exits after `-t` seconds;
`src/Simplex/Chat/Library/Commands.hs` makes a one-time invitation and
`src/Simplex/Chat/View.hs` formats the link. Creating the link needs relay
connectivity. This source-derived invitation sequence has not been replayed
end-to-end as a complete procedure. Do not assume invitation success from process exit. The upstream CLI guide describes `/connect` as a one-time invitation; the v7
command parser and help identify `/contacts` and `/code @name`. Source
also provides `/_contacts <userId>` on the local WebSocket API with numeric
`contactId`, but the local API is unauthenticated and is not exposed to a host
port in this procedure. `/_contacts` is read-only, but the server can execute
other commands: only a trusted local operator or process may access its API.

Source references: [v7.0.0 options](https://github.com/simplex-chat/simplex-chat/blob/v7.0.0/src/Simplex/Chat/Options.hs),
[database options](https://github.com/simplex-chat/simplex-chat/blob/v7.0.0/src/Simplex/Chat/Options/SQLite.hs),
[invitation implementation](https://github.com/simplex-chat/simplex-chat/blob/v7.0.0/src/Simplex/Chat/Library/Commands.hs),
[CLI guide](https://github.com/simplex-chat/simplex-chat/blob/v7.0.0/docs/CLI.md).

## Prepare

Use the [standalone runtime runbook](simplex-alert-runtime.md) to prepare and
review its image first. Inspect the exact local image ID and check that its
`/opt/simplex/simplex-chat` is the pinned release. Ensure the existing standalone
service and every other process using this **new** profile are stopped. Do not
start the regular launcher during provisioning.

Choose a new durable profile path, under a trusted parent without symlink
components. It must not already exist or overlap any existing profile or
service state. Create that one directory exclusively, mode 0700, and give only
that directory numeric UID/GID 10001. Check it is empty, a real directory, and
owned as intended; do not recursively change any pre-existing tree. Restrict
its parent so other users cannot inspect it. The path is represented by
`$profile` below; the independent host-side `$evidence` directory is new,
private, and not inside `$profile`. Its invitation output is a bearer secret.
Do not put either path or invitation into a shared log.

Set `image` to the independently inspected full `sha256:` image ID and `token`
to a fresh random lowercase hex string. Verify the exact daemon, local image,
network, filesystem and empty profile before each Docker mutation. The
following creates one uniquely labeled container with no published port; its
captured full ID is the only resource this invocation may start or remove:

```sh
umask 077
# profile, evidence, image and token are reviewed values prepared above.
docker create --pull never --cidfile "$evidence/invite.cid" \
  --name "stargate-simplex-invite-$token" \
  --label "org.stargate.simplex-provision=$token" \
  --network bridge --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 768m \
  --memory-swap 768m --ulimit core=0:0 --log-driver none \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m,mode=1777 \
  --mount "type=bind,src=$profile,dst=/profile" \
  --entrypoint /opt/simplex/simplex-chat "$image" \
  -d /profile/db -y --create-bot-display-name StargateAlerts -e /connect -t 3 \
  > "$evidence/create.out" 2> "$evidence/create.err"
```

The `-y` here is restricted
to creating a verified **empty new profile**; it is not a migration authorization
for an existing database. Before starting, inspect
the full ID, exact name, label, image, bind source, user, entrypoint/arguments,
network, limits and isolation. Abort on any mismatch or ambiguous create result.
Run `docker start --attach "$id"` with stdin from `/dev/null` and both streams
redirected to separate fresh 0600 files in `$evidence`; record the exit status.
Verify the container has exited, and check the two nonempty database files, user
and profile ownership, file types and private mode. The invitation is in the
private stdout file only if upstream reports successful `/connect`; error output
or a zero process exit alone does not establish a usable link. Never retry an
ambiguous request automatically; preserve its output and exact container ID.

Transfer the single invitation to the intended phone through a private channel.
Do not publish it or send it to an unverified contact. Create a separately named,
identically confined handshake container only after the first has exited:

```sh
docker create --pull never --cidfile "$evidence/handshake.cid" \
  --name "stargate-simplex-handshake-$token" \
  --label "org.stargate.simplex-provision=$token" \
  --network bridge --read-only --user 10001:10001 --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 128 --memory 768m \
  --memory-swap 768m --ulimit core=0:0 --log-driver none \
  --tmpfs /tmp:rw,noexec,nosuid,size=32m,mode=1777 \
  --mount "type=bind,src=$profile,dst=/profile" \
  --entrypoint /opt/simplex/simplex-chat "$image" -d /profile/db -p 17619 \
  > "$evidence/handshake-create.out" 2> "$evidence/handshake-create.err"
```

Check its full ID and configuration as above, then start that ID without an
attached stream. No port is published. While it is running, have the phone
accept the invitation. After the phone confirms its interaction, inspect the
contact using the local API described below while this process is running. Then
stop that exact ID and wait until inspection confirms it has exited. Its daemon log driver is
`none`. Never run two owners at once. A phone interaction and local contact
listing must be observed; elapsed time alone is not confirmation.

The temporary direct-native process may require forced termination. Treat a
forced or uncertain stop as interrupted shutdown: preserve the complete profile,
including WAL and sidecars, and investigate before reuse. Do not delete or repair
files to force startup. Direct-native PID 1 is a provisioning step, not the
production service owner.

To inspect contacts without sending, use a reviewed local WebSocket client
inside the same isolated network namespace as the SimpleX process. Use it
exclusively: concurrent clients can consume events from the shared queue. Do not
publish or proxy its unauthenticated port. The v7 server accepts a request
object with `corrId` and `cmd`; request `/user` and require the correlated
`activeUser` response, then use its positive numeric `user.userId` in
`/_contacts <userId>`. Require the correlated `contactsList` response and read
`contacts[].contactId` and `contacts[].localDisplayName`. The connection's
`activeConn.connStatus.type` may be `ready` or `sndReady`; the v7 source treats
both as ready. These responses and the one-time link are private. A contact
listing is not identity verification, and an unsolicited event must not be
mistaken for the response to a command. Stop if the result is missing or
ambiguous.

Confirm that the returned contact and positive numeric ID belong to the intended
phone; if absent, ambiguous or inconsistent, stop. A ready connection or displayed
name alone does not identify the recipient. Record the ID privately. As an
optional additional identity check, compare the upstream security code for that
contact with the phone over a trusted channel using `/code @<local-contact-name>`
in another stopped-owner invocation. Contact names, codes and IDs are sensitive.

Inspect and remove each stopped container only by its recorded full ID after
verifying its immutable image, name, label, mounts and state. Confirm absence
using a successful daemon query; if identity, start, stop, output or cleanup is
ambiguous, retain the exact ID and evidence and stop. Never sweep by name or
label. Keep the profile stopped until the standalone runtime is configured with
that specific profile and verified ID. The regular launcher still checks both
existing database files and does not authorize migrations.

Run the established profile under the existing `SimplexRuntimeMain` standalone
Compose service, with the selected contact ID, no published API port and Docker
logging disabled as in the runtime runbook. Inspect the resolved configuration
without replacing its security settings. Verify that the effective core-size
limit remains zero; do not lose it when rendering or translating configuration.
The launcher checks both database files, drops the SimpleX child
streams and owns its shutdown; it does not approve migrations.

Only after an explicit instruction to send a new test alert, send exactly one
agreed, non-sensitive message. Record the sender's result and ask the user to
confirm seeing it on the phone. `ACCEPTED` is a local acknowledgement, not recipient delivery;
`UNKNOWN` must not trigger an automatic retry.
