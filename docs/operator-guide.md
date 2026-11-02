# Stargate operator guide

For the container deployment and browser extension. This guide is for
the person running the server; give friends/family the separate
[user guide](user-guide.md). They need extension files, your HTTPS server address
and their own one-time code. They do not need your administrator token or SSH.

[Deployment](#1-prepare-a-deployment) · [Admin login](#2-open-the-private-manager) ·
[Give access](#3-give-each-browser-access) · [Diagnosis](#4-routine-operation-and-diagnosis) ·
[Maintenance](#5-certificates-alerts-and-updates) · [Recovery](#6-backup-and-recovery)

The release is a testing prerelease. Linux amd64 is the qualified deployment/browser
platform; other systems are not qualified. Automatic prerequisite installation
supports Ubuntu 24.04 amd64 only; see [manual setup](setup-prerequisites.md) for
other hosts.

## Know what you operate

| Part | Purpose | State to preserve |
| --- | --- | --- |
| `app` | Separate proxy and manager JVMs under one supervisor | `app-data`: administrator token, device/configuration state and requested running/stopped state |
| `tor` | Onion routing, partitioned by device credential | `tor-data` and `tor-control` |
| `i2p` | I2P router and on-demand per-device destinations | `i2p-data` and `i2p-control`, together with app configuration |
| `nym` | Shared mixnet client for ordinary websites | `nym-data` **and** `nym-secrets` |

The Nym deployment has **seven named state volumes**. These are seven roles to
preserve as a matching set, not seven servers. Native SOCKS/control interfaces
remain private. The manager controls forwarding, not Docker; it has no Docker socket.

Ordinary web stays on Nym. A route failure does not switch networks or connect
directly. The base `compose.yaml` alone does not enable Nym: include
`compose.nym.yaml` for this three-network setup. The client uses the observed
free-bandwidth mixnet path; payment/purchase flows are not implemented and free
bandwidth/provider availability is not guaranteed. This is not NymVPN/dVPN.

The VPS remains trusted. It sees routing metadata and can read HTTP content;
HTTPS destination content remains encrypted through CONNECT. Device credentials
separate access, not trust in the host. Tor isolation is per credential, I2P
identities are per credential when isolated deployment is enabled, and Nym's
client identity is shared. Browser cookies/logins/fingerprints remain outside
that isolation. See the user guide's [privacy explanation](user-guide.md#what-privacy-this-provides).

## 1. Prepare a deployment

For guided configuration preparation, use the [shell setup wizard](operator-setup-wizard.md).
Start with `bash tools/setup-wizard.sh --preview` for choices and a recap without
writes or Docker calls. Configuration uses Bash and Compose. Use
`bash tools/setup-wizard.sh --prerequisites` for the
[profile-specific checks and guided host-tool setup](setup-prerequisites.md);
native prerequisites and deliberate deployment below remain separate.

### Choose and record the installation

Record privately: source revision; actual image IDs for all four services;
Compose project name; absolute working/configuration paths; ordered Compose
inputs and environment files; exact state-volume names; public origin/ports;
and certificate directory. Keep this record with your protected recovery records.
An image tag alone is not an immutable image identity. Do not put credentials or
private keys in a deployment report, Git, chat or browser-extension package.

For a new server, follow [container installation](../containers/README.md) for
the build prerequisites and commands, then the
[Nym build/initialization procedure](native-build-tools.md#enable-nym-and-preserve-its-state).
Image preparation uses Java 25 and a prepared native builder; it is not a clean
host bootstrap from Docker alone. Existing libc, I2P and Nym fixes and their
failing-test gates must be retained. Use compatible images from the selected
source; do not substitute an unmodified upstream binary or mix old/new app and
I2P lifecycle implementations. Running prebuilt containers alone needs no host
JVM: their Java runtime is included. The host-side monitor, updater, certificate
synchronizer and Java operator helpers do require Java 25; select the wizard's
**tools** prerequisite profile when using those operations, and follow the
[root-controlled Java procedure](root-java-toolchain.md) for the root TLS service.
The [Java image-input procedure](image-input-preparation.md) gives the exact
preparer build/run commands, required native records, Nym build selection and
failure handling. The [source/bootstrap](libc-bootstrap-tools.md),
[libc compiler](libc-build-tools.md) and [I2P/Nym](native-build-tools.md)
controllers use Java/Bash; native compilation remains a separate build operation.

Select a public Nym network requester using that procedure; old example providers
are dated observations, not a current recommendation. Save its nonsecret setting
in your deployment environment. A persisted Nym client keeps its initialized
provider; changing `STARGATE_NYM_PROVIDER` alone does not rewrite it.

Nym generates its private local key-passphrase file on first initialization.
It is not a payment credential, wallet seed or NymVPN login, and it does not
encrypt every database. Preserve both Nym volumes. If initialization was
interrupted, preserve the partial files and secret before choosing recovery;
do not delete markers/keys to force startup. See [Nym state and recovery](native-build-tools.md#enable-nym-and-preserve-its-state).

### Enable encrypted remote access

Follow [remote access](remote-access.md#certificate-and-ports) to provision a
normally trusted certificate for a hostname you control, stage it privately and
generate the resolved remote Compose configuration. The generator starts nothing
and refuses to overwrite its output. Use the existing project name, every existing
Compose/environment input, the Nym overlay and the intended images/volumes.
Review the generated output before applying it.

Publish only the **HTTPS device API** and **TLS browser proxy** ports needed by
users. Keep plaintext manager/proxy ports on host loopback; keep router SOCKS,
control interfaces and Docker unpublished. An ordinary website reverse proxy/CDN
must not sit in front of the forward-proxy port. An existing website can remain
on 443 while Stargate uses separate TLS ports. Permit the selected ports in the
host and provider firewalls.

Give users the HTTPS **device API origin** as their server address, for example
`https://gate.example.org:9443`, not a download link or the proxy's port. The
extension learns the matching encrypted proxy endpoint during pairing. Never
solve a certificate problem by asking users to accept an exception or import a
private CA/key.

### Keep every command tied to that installation

For an already reviewed **resolved remote YAML or JSON** configuration, the following
shell shortcut makes the project and file explicit. Replace both example values;
run from the project checkout. It does not create or start anything:

```sh
stargate_project='REPLACE_WITH_EXISTING_PROJECT_NAME'
stargate_config='/absolute/path/to/reviewed-compose.remote.yaml'
sg() {
  docker compose --project-name "$stargate_project" --file "$stargate_config" "$@"
}
sg config --quiet
sg ps
```

Use this only after selecting the correct file/project. For a local or multi-file
deployment, keep its complete original invocation instead, including all ordered
`-f` and `--env-file` arguments. A generated remote configuration already contains resolved
settings; changing `.env` does not update that file. See
[configuration generation](remote-access.md#generate-deployment-configuration)
before changing a remote deployment. Review full configuration privately; it may
contain sensitive paths/settings.

The remaining `sg` examples assume that shortcut points at your installation.
To apply a reviewed new/replacement configuration, use `sg up -d`; this can replace
containers and interrupt active users. Do not run it against an unfamiliar file.

Before production cutover, follow [persistent configuration and startup](persistent-deployment.md)
to preserve all images/state mappings, add the existing read-only status displays
and verify restart behavior. That procedure includes the exact commands and
privilege boundaries for Docker startup, user-service lingering and checks after
an agreed reboot; preparing it starts nothing.

## 2. Open the private manager

These steps use a Linux laptop with Bash, OpenSSH (`ssh`/`scp`) and `less`.
Replace `OPERATOR@VPS_HOST` with your normal verified VPS SSH login or SSH alias;
SSH uses that login, not the Stargate administrator token. Use the same login in
every block below. If you use a custom SSH port, use your configured SSH alias
or add `-p PORT` to `ssh` and `-P PORT` to `scp` consistently. Verify an unfamiliar
SSH host key before accepting it; do not bypass a changed-host-key warning.

**On your laptop, terminal 1:** open this SSH tunnel and leave it running. The
example uses the default configured management origin/host-loopback port:

```sh
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:9080:127.0.0.1:9080 OPERATOR@VPS_HOST
```

Then open **http://127.0.0.1:9080/** on that computer. Replace `OPERATOR@VPS_HOST`
with your SSH login. If your installation uses another management port/origin,
use that exact configured origin and matching tunnel ports. Changing only the
local URL/port can cause Host/Origin rejection. Do not expose the plaintext
manager to the Internet to avoid using SSH. If Stargate is paired in this browser,
loopback is already a routing exception.

### Retrieve and keep the administrator token

The primary token is in the persistent **app-data volume**, at
`/data/admin-token` inside `app`. It is not created anew for each browser, tunnel
or login. A temporary exported copy disappearing does not delete the original.
Normal restarts retain it; destructive volume deletion or deliberate recovery
that rotates credentials is different.

For the resolved remote configuration selected above, this writes a private copy
without printing its value or putting it in command history. **Run this on the
VPS, from the project checkout**, in the shell where you selected
`stargate_project` and `stargate_config` in step 1. A fresh SSH shell needs those
values selected again; laptop shell variables do not configure the VPS shell.

```sh
(
set -e
: "${stargate_project:?Select the installation project from step 1}"
: "${stargate_config:?Select the installation configuration from step 1}"
umask 077
admin_directory="$HOME/.local/share/stargate-admin"
install -d -m 0700 "$admin_directory"
token_copy=$(mktemp "$admin_directory/.admin-token-XXXXXXXX")
trap 'rm -f -- "$token_copy"' EXIT
COMPOSE_FILE="$stargate_config" bash tools/container-token.sh \
  --project "$stargate_project" > "$token_copy"
chmod 0600 "$token_copy"
mv -T -- "$token_copy" "$admin_directory/admin-token"
)
```

Check the command succeeded before using the file. It atomically replaces that
local copy with a mode-0600 export, including when an older copy had looser
permissions. A failed export retains the previous copy. For multi-file setups,
preserve the same Compose selection when using the helper.

### Copy the exported token to your Linux laptop

**On your laptop, terminal 2** (a local terminal, not inside SSH): run the block
below. Replace the SSH login again. The remote path after `:` is relative to that
SSH account's home directory and refers to the exported copy above. The laptop
copy goes into your own private home directory. Neither command prints the token.
A failed transfer keeps any previous laptop copy unchanged.

```sh
# stargate-guide: laptop-copy
(
set -e
umask 077
stargate_ssh='OPERATOR@VPS_HOST'
admin_directory="$HOME/.local/share/stargate-admin"
install -d -m 0700 "$admin_directory"
token_copy=$(mktemp "$admin_directory/.admin-token-XXXXXXXX")
trap 'rm -f -- "$token_copy"' EXIT
scp -- "$stargate_ssh:.local/share/stargate-admin/admin-token" "$token_copy"
test -s "$token_copy"
chmod 0600 "$token_copy"
mv -T -- "$token_copy" "$admin_directory/admin-token"
)
```

### Read the laptop copy and unlock the manager

**In the same local laptop terminal**, use this viewer command. It requires an
interactive terminal and disables `less` history, input filters, configured
options and shell/editor/logging commands. It does not put the token in shell
history. Use a private terminal without session recording; the value is visible
while you read it, and terminal capture/clipboard history can retain it.

```sh
# stargate-guide: laptop-view
if test -t 0 && test -t 1; then
  env -u LESS_IS_MORE -u LESSSECURE_ALLOW LESS= LESSOPEN= LESSCLOSE= \
    LESSSECURE=1 LESSHISTFILE=- \
    less -- "$HOME/.local/share/stargate-admin/admin-token"
else
  printf '%s\n' 'Open a local interactive terminal to view the token.' >&2
  false
fi
```

1. Select only the token characters on its line and use your terminal's **Copy**
   action (commonly Ctrl+Shift+C). Press **q** to close the viewer.
2. Keep terminal 1's tunnel open. In Firefox or Brave, open
   **http://127.0.0.1:9080/**, using your exact configured origin/port if different.
   Type this in the ordinary address bar; do not use the public device API address.
3. Paste into **Administrator token**, then choose **Unlock manager**. Successful
   login shows controls including **Proxy** and **Pair a device**. Decline any
   browser offer to save this token as a password. If login fails, check the
   selected installation and tunnel; do not rotate the token as the first repair.
4. Clear the current clipboard/selection and any clipboard-manager history after
   pasting. Use the cleanup instructions below. Never paste the token into a URL,
   shell command, user pairing form, screenshot or chat.

### Clear the clipboard after pasting

For clipboard cleanup, run **one** matching block in a local laptop terminal if
its named clipboard utility is already installed:

- **Wayland**, with `wl-copy` from `wl-clipboard`:

```sh
# stargate-guide: clipboard-wayland
wl-copy --clear
wl-copy --primary --clear
```

- **X11**, with `xclip`:

```sh
# stargate-guide: clipboard-x11
printf '' | xclip -selection clipboard
printf '' | xclip -selection primary
```

If a command is missing, the desktop does not support primary selection, or a
command fails, select the harmless word **cleared** here and use **Copy**. This
replaces the current clipboard and, where supported, the last-text selection.
Clear your clipboard manager's history too, using its clear-history control:
neither these commands nor copying another word erases that history.

### Lock the manager and remove exported copies

When finished administering Stargate, choose **Lock manager** in the browser,
then close its tab. Locking ends this web session; it does not stop forwarding or
revoke paired devices. Close the viewer with **q** if it is still open.
**On your laptop**, run:

```sh
# stargate-guide: token-cleanup
stargate_ssh='OPERATOR@VPS_HOST'
rm -f -- "$HOME/.local/share/stargate-admin/admin-token"
ssh "$stargate_ssh" 'rm -f -- "$HOME/.local/share/stargate-admin/admin-token"'
```

The first command removes the laptop export; the SSH command removes the VPS
export. Check that SSH succeeds. Neither touches `/data/admin-token` in Docker;
the original stays in the persistent app-data volume for the next login/export.
Removing an export does not rotate or revoke that original token.

Close the local terminal used to view the token; this is not a guarantee against
terminal recording or prior copies. Finally, return to terminal 1 and press
**Ctrl+C** to close only the SSH tunnel you opened. Do not use a blanket SSH kill
command. Reopening the tunnel later does not require a new administrator token.

Manager sessions expire after **30 minutes**. Log in again with the same token;
you do not need to rotate it. **Lock manager** ends the web session. A manager
restart also ends sessions and unused invitations, while saved device grants
survive with unchanged configuration. Closing the manager page leaves forwarding
running. The public HTTPS device API is not the administrator control panel.

## 3. Give each browser access

A new installation starts with forwarding **stopped**. In the manager's **Proxy**
section, choose **Start** and refresh observations. Process/listener readiness is
not proof of public destination access; test each enabled route before inviting
users. Tell users about any controlled requester/destination restrictions before
a test. Do not present a restricted fixture as arbitrary-site access.

1. Give the person the correct extension archive, [user guide](user-guide.md),
   and your HTTPS server address. Let them install and prepare the browser first.
2. Under **Pair a device**, use a recognizable name such as `Alex-Brave-laptop`.
   Names allow 1–32 letters, numbers, hyphens or underscores. Select **5 minutes**
   by default; use **24 hours** only when deliberately allowing more time.
3. Choose **Create one-time code**, then send the code privately. It is shown
   only when created. Anyone holding it can redeem it once. Record its nonsecret
   **Invitation reference** if you may need to cancel it.
4. Have the user connect, review settings, restart as directed and open a page.
   Another browser/profile/device gets a separate code, even for the same person.

An unused code can be cancelled under **Pending invitations → Cancel invitation**.
Match the full invitation reference; names may repeat. Cancelling an unused code
does not revoke an already paired device. Manager restart invalidates pending
codes; saved access does not expire when a code's lifetime ends.

For **Pairing result unknown**, do not repeatedly redeem or assume no device was
created. Check for an unused new device, revoke it only if identified, and issue
a fresh code. The invitation reference does not identify a redeemed device and
a repeated name is not unique. If access was saved but settings failed, have the
user finish setup/Apply rather than issuing another code automatically.

### Revoke a lost or exposed device

Have the user find the identifier under **Settings → Advanced mode → Saved device
access**. Match it in **Paired devices**, then choose **Revoke device**. New access
is rejected and that credential's connections close after refresh, normally within
one second; other devices retain their streams. A copied credential shares that
identifier, so revocation affects all its copies. Old shared credentials remain
valid after an upgrade until you explicitly revoke them. Forgetting local access
or deleting the extension is not server-side revocation.

**Stop I2P for device / Enable I2P for device** are different: they control that
device's I2P route without revoking its Tor/Nym access. Stop/enable retains the
I2P identity; re-pairing creates a new credential/route. Retired key files remain
private in the router volume. Do not delete or reassign keys as routine cleanup.

## 4. Routine operation and diagnosis

| Observation | Meaning / action |
| --- | --- |
| Proxy process/listener ready | Local forwarding is responding. Test actual destinations separately. |
| Tor bootstrap ready | A control observation; not proof every onion service is reachable. |
| I2P route not started | Normal before first use. It starts on demand; cold tunnel building can take minutes. |
| I2P unavailable/pending | Read the per-device observation. Unknown native reload/resource state can pause new activation while existing traffic remains. Do not reset identities to make it look ready. |
| Nym listening, readiness unknown | A local SOCKS listener is not proof of exit/destination access. Use actual traffic. |
| Server observations unavailable/stale | Refresh and inspect their age. The proxy can still be running; browser settings stay on. |
| Global admission refusals | New sockets hit shared capacity. Past refusals do not establish that it is full now. |

**Start / Stop / Restart** in the manager control the proxy for every device.
Stop/Restart close its connections; desired running/stopped state persists in
app-data. Restarting the whole app also interrupts forwarding and resets its
process-lifetime counters. The manager has no native-router restart control.
For a diagnosed router issue, use the selected Compose configuration to restart
only that service, for example `sg restart i2p`. Warn affected users first; live
connections on that route can break. Do not restart/rebuild everything as the
first response to a slow page.

Read-only first checks:

```sh
sg ps
sg logs --tail 30 app tor i2p nym
```

Keep diagnostics private. Production observations omit destinations, credentials,
headers and payloads; do not turn on verbose native traffic logs or publish raw
profiles/configuration to investigate. Counters are aggregates, not user histories.
They reset with the proxy process. A timeout does not prove a form/upload failed
to arrive; tell users to retry submitted actions only when safe.

### Capacity settings

There is one configurable global connection budget, **no per-device ceiling**.
It counts client sockets including setup, not tabs or users. A busy device can
occupy the shared pool. Changing a limit does not create upstream bandwidth.

[Capacity settings and measurements](proxy-capacity.md) document
`STARGATE_MAX_CONNECTIONS` and `STARGATE_APP_MEMORY_LIMIT`. The historic 128 / 512m
fallbacks are not measured recommendations. A bounded local mock-upstream run
passed at 1024 connections with a 1 GiB app budget; it is not a public-network
capacity guarantee. Account separately for Tor, I2P, Nym and host memory.

For an existing installation, leave an unset connection override unset to retain
its stored value. For deliberate changes, follow that document's review and
app-only recreation procedure; a Compose `restart` does not apply new environment
or memory settings. Regenerate the resolved remote configuration first. Do not add a device
cap or raise limits solely because many devices are registered.

## 5. Certificates, alerts and updates

**Certificates:** Caddy/the selected issuer obtains and renews the certificate.
The staging helper copies a validated pair into the app's read-only directory
mount; mount the directory, not individual files. The proxy checks replacements
every five seconds and manager every thirty. A rejected pair retains the old
working context; an expired old certificate still fails client validation.

Use the [reviewed renewal installation procedure](remote-access.md#persistent-certificate-renewal)
for your actual paths/hostname/UID; the supplied units contain example
Caddy paths. Root owns the installed helper/units. After initial staging, check
both live TLS endpoints rather than trusting a copy result alone. For an existing
installation of the earlier helper, the [complete Java cutover sequence](remote-access.md#existing-installation-java-cutover)
includes hash checks, previous-unit backup and timer handling. For an
installation using those unit names:

```sh
systemctl list-timers stargate-tls-renewal.timer --all
systemctl show stargate-tls-renewal.service -p Result -p ExecMainStatus
sudo journalctl -u stargate-tls-renewal.service -n 10 --no-pager
```

The hourly timer copies issuer files; it does not issue certificates or monitor
phone delivery. Confirm its result and both TLS listeners on your installation.

**Daily alerts:** use the [Java monitor setup and migration](java-monitor.md),
[dedicated SimpleX v7 profile procedure](simplex-alert-profile-provision.md) and
[isolated sender runtime](simplex-alert-runtime.md). The profile lives on the
same VPS in private storage; another VPS is not required. It is separate from
personal chat profiles and is not an AI or command interface. Messages are alerts
only; no `/start`, restart or upgrade commands are implemented.

For each message's meaning and required action, use
[Understand the SimpleX alerts](simplex-alerts-guide.md). A checker failure or
recovery does not establish a browsing failure or recovery. Release/security
information requires review; the checker does not install updates.

After installing the selected operator's user units, inspect:

```sh
systemctl --user list-timers --all stargate-daily-alert-consumer.timer
systemctl --user show stargate-daily-alert-consumer.service \
  -p Result -p ExecMainCode -p ExecMainStatus
journalctl --user -u stargate-daily-alert-consumer.service -n 20 --no-pager
```

Unchanged evidence and the first baseline are quiet. Local send acceptance is
not proof of phone delivery; uncertain attempts must not be blindly retried or
cleared. Preserve the durable state and follow the consumer's recovery rules.
An enabled timer is not proof collection succeeded. Authenticated manager
release/consumer snapshots show published outcomes and age, not automatic
upgrade decisions or reliable missed-run alarms.

**Updates:** observers cover configured release/advisory inputs, including native
networks and Java/Quarkus, with retained gaps/dispositions. A new release or empty
scan is not a security verdict. Use the [runtime evidence configuration](java-monitor.md#runtime-security-evidence)
to bind observations to actual deployed image IDs. Review retained findings,
build/test compatible replacements, preserve state, then deliberately deploy.
Daily alerts never upgrade or restart Stargate automatically. Review and update
the monitor's deployed-image binding when replacing images. A rollback must use
matching images and **current compatible state**; old backups can restore revoked
access or stale I2P allocations. Follow the recovery procedure below when a data
restore is actually needed.

For the optional authenticated **Review / Install / Roll back** controls, follow
[verified image upgrades](verified-upgrades.md). That guide includes project-key
creation, signing and public-key pinning, host setup, retained patch checks,
state-preserving replacement and the exact host rollback/reconciliation steps.
No production signer/feed is preconfigured. This supports prepared compatible
images; it does not execute arbitrary build scripts or state migrations.

For what to do when a dependency alert arrives, affected-image builds, rollback
limits and refreshing monitor evidence, use the
[maintenance runbook](maintenance-upgrades.md). An upstream patch notification
is a review input; install a qualified, authenticated Stargate release that keeps
the required patches rather than replacing a native executable in a live container.

Build extension files with `bash extension/package.sh` using the project's
Java 25 JDK, and supply the
credential-free Firefox XPI/ZIP or Brave ZIP with the user guide. Test downloads
must serve the exact reviewed bytes; temporary links expire. Do not put device
credentials in packages. Follow the user's browser-specific update steps so saved
access is kept. Signing, permanent distribution and store publishing remain later.

The builder writes `extension/target/stargate-firefox.xpi`; it is a ZIP-format
archive. For the unsigned test guide's **Firefox ZIP** download, make an identical
`.zip` alias before distribution (this does not sign, upload or install it):

```sh
(
set -e
umask 077
package_directory=$(mktemp -d "$PWD/target/extension-delivery.XXXXXXXX")
cp -- extension/target/stargate-firefox.xpi "$package_directory/stargate-firefox.zip"
cp -- extension/target/stargate-brave.zip "$package_directory/stargate-brave.zip"
cmp -- extension/target/stargate-firefox.xpi "$package_directory/stargate-firefox.zip"
sha256sum "$package_directory/stargate-firefox.zip" "$package_directory/stargate-brave.zip"
)
```

Record the printed directory and compare both hashes with the qualified package
record before offering downloads. The Firefox alias must have the XPI's exact
hash. A future signed/store installation uses its own published instructions.

## 6. Backup and recovery

A volume retained by `sg down` is not a backup. **Do not use `down --volumes`,
`down -v`, volume deletion or prune as a routine restart/repair**: state loss can
destroy credentials and router identities. Back up the deployment record,
compatible images and the matching seven-volume set, including Nym's secret.
Keep an independently protected recovery key and verify decryptability. A copy
of an administrator token alone cannot restore the installation.

These are planned-downtime operations, not live snapshots. Stop and flush every
writer, keep other identity copies offline and establish exclusive Docker control
where the tool requires it. Never relax volume permissions, guess missing volume
names or manually edit running manager-owned credential files to make recovery pass.
For capture and pre-activation recovery, follow these existing procedures:

| Operation | Procedure and boundary |
| --- | --- |
| Capture a stopped matching set | [Offline volume capture](offline-volume-capture.md): explicit sources, reviewed helper and archive verification; does not stop writers for you. |
| Verify/decrypt/stage | [Encrypted archives](offline-encrypted-archives.md): needs the separately protected age recovery identity; success is not proof the snapshots are complete/coherent. |
| Import into new isolated volumes | [Authenticated archive import](offline-archive-import-docker.md), or [staged-directory import](offline-volume-import-docker.md); retain journals/helpers required by handoff. Never overwrite live volumes. |
| Prepare restored access and fleet | [Staged recovery](offline-staged-recovery.md) and [I2P fleet reset](offline-i2p-fleet-reset.md): discard old device access, rotate admin credentials, keep forwarding stopped and handle port history explicitly. Every device pairs again. |
| Review before activation | After offline preparation, use [Compose handoff](offline-volume-compose-handoff.md), its required rechecks and compatible-image/configuration review. Handoff alone does not make the stack safe to expose. |

**Optional I2P identity continuity is a later phase.** After handoff and all
pre-start recovery checks, deliberately start only the recovered stack in a
controlled configuration. Fresh pairing and valid unique port allocation must
precede [identity reassociation](offline-i2p-identity-reassociation.md). The default
recovery counter blocks allocation; continue only with independently established
complete port history or an already valid unique allocated port, as that procedure
requires. Do not guess/recycle ports or bypass the exhausted counter.

Before reassociation, stop forwarding and **all recovered services/writers again**.
Use an independently trusted destination record and the full offline procedure;
keep every other identity copy offline throughout. Resume the reviewed recovered
stack only after successful completion. Do not rerun the pre-activation handoff
after startup creates project resources; it deliberately refuses at that stage.

Keep the original installation and all duplicate identities offline during
recovery and activation. Do not start the same native identity in two places.
Re-test device access and real Tor, I2P and Nym requests after deliberate activation.
A successful offline import does not establish that the restored service can reach
destinations or that arbitrary image/database versions are compatible.
