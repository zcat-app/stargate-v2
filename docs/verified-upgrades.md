# Review, install and roll back signed image releases

The optional Java host updater accepts **prepared image releases**, not arbitrary
commands, Git branches or build scripts from the manager. Only the four existing
services (`app`, `tor`, `i2p`, `nym`) are supported. It replaces the listed services
only. Ordinary web remains on Nym. SimpleX alerts cannot trigger upgrades.

Use the [rc.3 operator bundle](https://github.com/zcat-app/stargate-v2/releases/tag/v0.1.0-rc.3)
for the corrected host helper. Unpacking does not replace a running worker; follow
the operator setup and interrupted-operation checks below.

The manager has no Docker socket. The updater runs as the operator who already
has Docker access; that is powerful host authority. The manager receives two
narrow directory mounts: public observations read-only and an action inbox.
Proxy and manager share app UID 10001, so this is a **whole app-container trust
boundary**, not isolation between those two processes. A compromised app can
request a prepared signed upgrade or rollback, but cannot select a URL, signer,
image, path, service list or command. Protect the operator's configuration, key
pin and work directory independently of the container.

Docker inspect/config responses are parsed through private temporary files and
deleted on completion/failure. They are not retained as diagnostic logs. Keep the
protected transaction configuration/state private; it can contain operator
environment values needed to check the deployment.

## Create the Stargate signing key once

Use a separate key for this project. Keep the private key on your own trusted
computer and an encrypted backup offline; the VPS only needs the public key.
The key authorizes releases and is distinct from TLS, SSH and user pairing keys.
Do not put its passphrase in arguments, environment variables, Git or chat.
OpenSSL 3 prompts for it in these commands:

```sh
set -e
umask 077
mkdir -m 700 ~/stargate-signing
cd ~/stargate-signing
test ! -e stargate-release-private.pem
test ! -e stargate-release-public.der
openssl genpkey -algorithm ED25519 -aes-256-cbc \
  -out stargate-release-private.pem
openssl pkey -in stargate-release-private.pem \
  -pubout -outform DER -out stargate-release-public.der
sha256sum stargate-release-public.der
```

Keep the displayed SHA-256 fingerprint separately. Transfer only the public DER
file to the operator's private installation directory and independently compare
its fingerprint. Never download a replacement trusted key from the release being
verified. No production signer or release feed is bundled or silently trusted.
Losing the private key prevents further releases; compromise requires stopping
updates and distributing a new independently verified pin. Automatic key rotation
is outside this first increment; retain the old transaction files for recovery.

## Prepare a release (publisher)

Build and qualify only affected images using reviewed source and existing native
patches. This updater deliberately does not rebuild from a web-submitted script.
Use [the maintenance guide](maintenance-upgrades.md#maintainer-build-only-the-affected-candidates) for a Tor-only update.
Image-input preparation and runtime-file collection now use the
[Java preparer](image-input-preparation.md). The [source/bootstrap](libc-bootstrap-tools.md),
[libc compiler](libc-build-tools.md) and [I2P/Nym](native-build-tools.md)
controllers also use Java/Bash. Native packages retain their upstream build-tool
requirements.

An application build needs the current `proxy` JAR and the complete Quarkus
`manager/target/quarkus-app` directory, not just `quarkus-run.jar`:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy,manager,updater -am package
```

Use a qualified, prepared container context matching the intended runtime fixes;
replace its generated `app/proxy.jar` and whole `app/manager` directory with those
outputs, then build only the app target with `containers/Dockerfile`. Do not
assume the old `target/container` context matches a running image: compare its
runtime inventory and patched bytes first. A stale context must not be published.
There is no automatic clean-host native builder in this increment.

For each qualified candidate, save by exact image ID, never a mutable tag:

```sh
docker image inspect YOUR_CANDIDATE_IMAGE --format '{{.Id}}'
docker image save --output app-image.tar sha256:YOUR_64_HEX_IMAGE_ID
sha256sum app-image.tar
stat -c %s app-image.tar
```

Publish the archive over HTTPS. Public GitHub releases are supported using the
full `https://github.com/OWNER/REPO/releases/download/TAG/ASSET` URLs. Upload
`release.json`, `release.json.sig` and each image archive as separate assets in
the same qualified release. Set `releaseUrl` to the manifest asset URL; the
updater appends `.sig` to that URL for its detached signature. Private or draft
GitHub releases are unsupported: no GitHub token is accepted or sent.
See [redirect policy and verification](public-release-downloads.md). This does
not authorize publishing a release or changing repository visibility.

Prepare `release.json` with the following schema. The values below are
placeholders, not an installable release:

```json
{
  "schema": 1,
  "release": "stargate-0.1.1",
  "sourceCommit": "40 lowercase hex characters",
  "createdAt": "2026-10-31T12:00:00Z",
  "expiresAt": "2026-11-07T12:00:00Z",
  "statePolicy": "no-migrations",
  "patches": {
    "containers/native/patches/glibc-CVE-2026-18374.patch": "64 lowercase hex characters"
  },
  "changes": [{
    "service": "app",
    "fromImage": "sha256:CURRENT_IMAGE_ID",
    "toImage": "sha256:CANDIDATE_IMAGE_ID",
    "fromVersion": "0.1.0",
    "toVersion": "0.1.1",
    "archive": "https://YOUR_RELEASE_HOST/app-image.tar",
    "archiveSha256": "64 lowercase hex characters",
    "archiveBytes": 123456
  }]
}
```

Include the **complete operator-selected retained patch inventory**, with its
actual file hashes; do not use just the one illustrative entry. Include every
changed service, its exact current/target image IDs, version labels and archive
size/hash. These are the release signer's source/build declarations. Sign only
after verifying upstream artifacts by their supported authenticity mechanisms,
retaining patch/build/scan evidence and checking no state migration is required.
A Stargate signature authenticates the assembled release; it does not manufacture
an upstream signature or prove a patch was applied correctly.

Sign the exact final JSON bytes on the signing computer, then upload both files.
Do not reformat the JSON after signing. The detached signature is raw 64-byte
Ed25519, not an ASCII signature file:

```sh
openssl pkeyutl -sign -rawin -inkey ~/stargate-signing/stargate-release-private.pem \
  -in release.json -out release.json.sig
```

Java 25's verifier was checked against OpenSSL's encrypted Ed25519 signing path.
See the official [OpenSSL signing reference](https://docs.openssl.org/3.0/man1/openssl-pkeyutl/)
and [Java signature API](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/security/Signature.html).

## Configure the operator's updater

Prerequisites: Linux, Java 25, Docker/Compose with `config --hash` and `up --wait`,
a reviewed existing four-service deployment and verified backup, sufficient disk
for archives/old images, a protected persistent complete Compose configuration,
the pinned public DER file and a compatible signed release feed. No system package
installation is performed. A signature is mandatory; there is no bypass switch.

Choose a private persistent installation directory, for example
`$HOME/.local/share/stargate-updater`. Its ancestors must be owned by root or the
operator and not group/other writable; root-owned sticky `/tmp` is tolerated for
isolated tests, but use persistent storage for production. Never use a shared
writable checkout/configuration directory as updater authority.

```sh
umask 077
install -d -m 0700 "$HOME/.local/share/stargate-updater"
install -m 0600 updater/target/stargate-updater-0.1.0-SNAPSHOT.jar \
  "$HOME/.local/share/stargate-updater/updater.jar"
```

Place the checked public file there as `public.der`. Save a **complete resolved
Compose file** there as `compose.json`, mode 0600, using your installation's exact
project, source files and environment. The `sg` function from the operator guide
selects those inputs; for that example installation:

```sh
sg config --format json > "$HOME/.local/share/stargate-updater/compose.json"
chmod 0600 "$HOME/.local/share/stargate-updater/compose.json"
```

This is not permission to substitute repository defaults for an existing
deployment. The updater requires selected Compose hashes to match running
containers before preview and before installing. If they differ, reconcile and
review deliberately; do not alter Docker labels to make the check pass.

Create `config.json` mode 0600 with absolute real paths and checked values:

```json
{
  "workDirectory": "/home/OPERATOR/.local/share/stargate-updater/work",
  "composeFile": "/home/OPERATOR/.local/share/stargate-updater/compose.json",
  "project": "YOUR_EXISTING_PROJECT",
  "dockerSocket": "/run/docker.sock",
  "releaseUrl": "https://YOUR_RELEASE_HOST/release.json",
  "publicKeyFile": "/home/OPERATOR/.local/share/stargate-updater/public.der",
  "publicKeySha256": "YOUR_INDEPENDENTLY_CHECKED_64_HEX_FINGERPRINT",
  "sourceDirectory": "/home/OPERATOR/stargate-v2",
  "patches": {"containers/native/patches/glibc-CVE-2026-18374.patch": "ITS_ACTUAL_SHA256"},
  "preserve": {
    "app": {"/usr/lib/x86_64-linux-gnu/libc.so.6": "ITS_INSTALLED_SHA256"},
    "tor": {"/usr/lib/x86_64-linux-gnu/libc.so.6": "ITS_INSTALLED_SHA256"},
    "i2p": {"/usr/bin/i2pd": "ITS_INSTALLED_SHA256"},
    "nym": {"/opt/nym/nym-socks5-client": "ITS_INSTALLED_SHA256"}
  },
  "maxArchiveBytes": 2147483648,
  "waitSeconds": 120
}
```

Choose the archive ceiling for actual release sizes/disk budget; this example is
an updater input, not a proxy connection/resource limit. The ceiling can be up to
16 GiB per archive. HTTPS uses system trust, follows only the validated redirects
described in [public release downloads](public-release-downloads.md), and bounds
transfer size/time. Operational downloads use direct HTTPS, as selected; browser routing
is unchanged. `localArtifactDirectory` optionally allowlists an absolute directory
for offline `file:` releases/tests. Omit it for HTTPS deployment. It is not
configurable from the manager.

The Docker endpoint is explicitly pinned to this local Unix socket; Docker's
active context and `DOCKER_HOST`/`DOCKER_CONTEXT` cannot redirect the worker.
For rootless Docker, use its actual protected operator-owned socket, commonly
`/run/user/UID/docker.sock`. TCP/SSH endpoints and symlinked socket paths are
refused. The configured operator must already have access to that daemon.

Populate the full patch inventory: existing libc patch, I2P identity/lifecycle
patches and all three Nym patches. Measure runtime preservation hashes from exact
reviewed images using an **unstarted** container, not live volumes:

```sh
sha256sum containers/native/patches/*.patch containers/i2p/*.patch containers/nym/*.patch
validation_id=$(docker create --network none --entrypoint /never-start EXACT_IMAGE_ID)
docker cp "$validation_id:/usr/lib/x86_64-linux-gnu/libc.so.6" ./checked-libc
sha256sum ./checked-libc
docker rm --volumes "$validation_id"
```

Repeat for other selected regular files. Keep I2P/Nym patched executables in the
policy when updating other parts of those images. Changing a protected executable
correctly blocks installation: a new patched native-client build requires a
separately reviewed policy transition, not deletion of a failing guard. The
example preserves libc only for app/Tor; include it for I2P/Nym too when they
contain the retained libc backport. Source-patch hashes alone are not application
proof. Image runtime defaults (user, entrypoint, environment, health check, etc.)
must remain equal; migrations and runtime-contract changes need a separate
reviewed procedure. Non-default device I/O limits and Compose `deploy` resource
policies are unsupported and refused; ordinary configured resource limits are
checked against live values, including out-of-band `docker update` changes.

Start once to create the work directory/subdirectories:

```sh
java -jar "$HOME/.local/share/stargate-updater/updater.jar" serve \
  "$HOME/.local/share/stargate-updater/config.json"
```

It creates `work/public/status.json` with phase EMPTY. Stop with Ctrl-C before
installing the service.
The work root is operator-owned 0700; `public` is 0755 and `inbox` 0733. Those
child modes permit the narrowly mounted app UID access while other host users
cannot traverse the root. Never expose the children through another service or
weaken the parent. Requests are 0644 so the operator can read app-UID-owned files;
they contain only action/approval hash, no credentials.

The worker publishes complete observations at 0644 and keeps private configuration
and journals at 0600, explicitly setting file modes before atomic replacement.
This also applies with the service's restrictive umask. A published status file
left at 0600 by an older worker is replaced with the correct mode when the fixed
worker next publishes; do not make the private work root traversable to repair it.

Enable `compose.upgrade.yaml` in the chosen deployment, with
`STARGATE_UPGRADE_WORK` set to that absolute work path. It binds **only** these two
children. Never mount the entire root or Docker socket. The app must contain the
new manager/supervisor code before it can display controls. Adding these mounts
and environment is a deliberate one-time app recreation with the existing volumes;
`restart` does not add them. Re-render the protected complete configuration from
the now-selected inputs and confirm it matches that deployment before continuing.
The private signing key is not needed for this host bootstrap.

Install the fixed user service from the checkout. Select the same qualified Java
as the operator tools; a system `/usr/bin/java` may be an older release on a new
host. This command requires simple absolute installation/Java paths and replaces
all template placeholders. It changes only the selected operator's user service;
the root certificate service requires its separately protected Java installation.

```sh
set -e
upgrade_home="$HOME/.local/share/stargate-updater"
updater_java=$(bash tools/with-toolchain.sh bash -c 'readlink -e -- "$(command -v java)"')
case "$upgrade_home:$updater_java" in *[!A-Za-z0-9_./:-]*) echo 'Choose simple absolute installation and Java paths' >&2; exit 1;; esac
test -x "$updater_java"
"$updater_java" --version
mkdir -p "$HOME/.config/systemd/user"
sed -e "s|@INSTALL_DIRECTORY@|$upgrade_home|g" -e "s|@ABSOLUTE_JAVA@|$updater_java|g" \
  updater/systemd/stargate-updater.service.in > "$upgrade_home/stargate-updater.service"
install -m 0600 "$upgrade_home/stargate-updater.service" \
  "$HOME/.config/systemd/user/stargate-updater.service"
systemd-analyze --user verify ~/.config/systemd/user/stargate-updater.service
systemctl --user daemon-reload
systemctl --user enable --now stargate-updater.service
systemctl --user status stargate-updater.service --no-pager
```

For operation after logout/reboot, have the host administrator enable lingering
for the chosen operator (`sudo loginctl enable-linger OPERATOR`) and verify
Docker's startup. This user service does not enable Docker or change existing
container restart policies.

Keep the supplied user unit's host UID view. Its explicit PrivateTmp=no avoids
the implicit user namespace that systemd creates for PrivateTmp in a user service;
that namespace leaves host-root owners unmapped and conflicts with the worker's
strict root/operator ancestry and local-socket checks. Do not accept nobody-owned
ancestors or weaken those checks. NoNewPrivileges=yes and UMask=0077 remain.
Application-level temporary files stay under the protected work directory.
See the [systemd 255 execution documentation](https://www.freedesktop.org/software/systemd/man/255/systemd.exec.html#PrivateUsers=).
The app-facing observation and request files also need the supplied shared-read
modes; do not normalize them to private-only modes that block UID 10001.

The worker freezes its configuration for a transaction. Changing that file/key/
patch policy is not a way to repair a failed check; restarting with an unexplained
configuration hash change is refused. Keep the reviewed configuration with its
transaction, and finish or diagnose the transaction before planning a deliberate
policy/key transition.

## Review and install

1. Unlock the private manager as administrator. Choose **Review available
   upgrade**, then refresh observations. Fetch/signature failure offers no new
   installable plan; inspect the host log. A rejected refresh can retain an older
   valid transaction, whose release, expiry and identity remain visible.
2. Review the release, declared versions, exact old/target images, signer
   fingerprint, patch list, expiry and interruption. The signature is already
   verified. Archive bytes and runtime preservation are verified at install time.
   Check the release's compatibility/build/scan notes and retain a verified backup.
3. Choose **Install reviewed upgrade**. This is explicit approval of this prepared
   transaction, not permission for later releases. Re-preparing—even the same
   release—changes the approval token. Queued does not mean installed.
   Keep other administrators/automation from changing this project's Docker
   resources until the transaction finishes; filesystem checks do not lock the
   Docker daemon against external operators.
4. Refresh until INSTALLED or a failure. Downloads can make observations stale
   while the host is busy; controls disable until fresh observations return.
   Only listed services restart. Their live connections can break; app replacement
   temporarily removes the manager and ends its administrator session. Sign in
   again with the saved admin token. Saved device grants/identities remain in
   their existing volumes; the updater does not rotate them.
5. Check real Tor/I2P/Nym requests and device pairing, not just container health.
   INSTALLED confirms expected images, container policy/mounts and running/healthy
   observations. It is not proof of destination access or anonymity. Refresh the
   daily monitor's selected image/scan bindings after a successful replacement;
   it must not silently reuse old image evidence.

Missing/invalid/expired signatures, changed keys/patches/configuration/runtime
bytes/defaults, stale approvals, damaged archives and unready services fail.
There is no direct-network routing fallback or automatic global rebuild.

**Keep the generated `work/active.compose.json` image override in later operator
commands**, otherwise an old source image tag could be reapplied:

```sh
upgrade_home="$HOME/.local/share/stargate-updater"
docker_socket=$(jq -er '.dockerSocket' "$upgrade_home/config.json")
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host "unix://$docker_socket" compose --project-name YOUR_PROJECT \
  --file /ABSOLUTE/INSTALL/compose.json \
  --file /ABSOLUTE/INSTALL/work/active.compose.json ps
```

Use the same two files/project for intended subsequent lifecycle commands. Do not
prune the previous images while rollback may be needed. A new reviewed release
starts a new transaction and replaces the rollback button's target; prior journals
and signed manifests remain under `work/history` and `work/releases`.

## Rollback and interrupted operations

Runtime comparisons ignore only the ordering of uniquely named environment
variables, uniquely targeted mount specifications and complete bind strings.
Every value and mount option is still compared; duplicate environment names or
mount targets are refused. Resolved mounts, other runtime policy fields and
ordered command arguments remain strict. Explicit null and an empty array compare
equally only for HostConfig `Dns`, `DnsOptions` and `DnsSearch`; missing fields,
populated values and their ordering remain distinct. Comparisons use copies, so
an existing journal and its transaction hash do not need rewriting.

For an ordinary failure or installed release, choose **Roll back to previous
images** in the manager. It uses the transaction's exact recorded images, unchanged
configuration and same mounts. It retains the **latest volume data**, including
writes after upgrade. It does not restore a backup or undo data/schema changes;
that is why state migrations are unsupported. Expiry blocks a new installation,
but does not block rollback of an already verified transaction with the same
trusted key/patch policy. Interrupted installs are never automatically replayed.

If the manager cannot start, submit the same fixed request from the host. Run as
the operator; stop on any command failure and use the exact private install path:

```sh
set -e
upgrade_home="$HOME/.local/share/stargate-updater"
plan=$(jq -er '.plan | select(test("^[a-f0-9]{64}$"))' "$upgrade_home/work/state.json")
request=$(mktemp "$upgrade_home/work/inbox/.operator-request-XXXXXX")
trap 'rm -f -- "$request"' EXIT
jq -nc --arg plan "$plan" '{action:"rollback",plan:$plan}' > "$request"
chmod 0644 "$request"
ln -T -- "$request" "$upgrade_home/work/inbox/request.json"
```

A pre-existing request makes `ln` fail; inspect the host rather than overwrite it.
Check progress/logs with `journalctl --user -u stargate-updater.service -n 30
--no-pager`. REQUEST_FAILED does not claim an upgrade succeeded. An interrupted
claimed request is retained privately; PREPARED becomes REVIEW_REQUIRED and needs
fresh review/approval.

**UNCERTAIN means a Docker command timed out.** The updater kills its owned command
process tree and blocks automatic actions; the Docker daemon may already have
received work. Do not repeatedly click rollback. Stop the updater, inspect the
project and ensure no compose operation/other administrator is changing it. Use
the transaction's prewritten rollback file, only its listed services:

```sh
set -e
upgrade_home="$HOME/.local/share/stargate-updater"
systemctl --user stop stargate-updater.service
# Inspect the process list and this exact project's containers before proceeding.
project=$(jq -er '.project' "$upgrade_home/config.json")
compose_file=$(jq -er '.composeFile' "$upgrade_home/config.json")
docker_socket=$(jq -er '.dockerSocket' "$upgrade_home/config.json")
release_id=$(jq -er '.releaseId | select(test("^[a-f0-9]{64}$"))' "$upgrade_home/work/state.json")
service_lines=$(jq -er '.changes | select(type=="array" and length>=1 and length<=4) |
  map(.service) | select(length==(unique|length)) |
  select(all(.[]; .=="app" or .=="tor" or .=="i2p" or .=="nym")) | .[]' \
  "$upgrade_home/work/releases/$release_id/release.json")
mapfile -t changed_services <<< "$service_lines"
test "${#changed_services[@]}" -ge 1
test "${#changed_services[@]}" -le 4
for service in "${changed_services[@]}"; do
  case "$service" in app|tor|i2p|nym) ;; *) exit 1;; esac
done
env -u DOCKER_HOST -u DOCKER_CONTEXT -u DOCKER_TLS -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
  docker --host "unix://$docker_socket" compose --project-name "$project" --file "$compose_file" \
  --file "$upgrade_home/work/rollback.compose.json" \
  up --detach --no-deps --no-build --pull never --wait --wait-timeout 120 \
  "${changed_services[@]}"
java -jar "$upgrade_home/updater.jar" reconcile-rollback "$upgrade_home/config.json"
systemctl --user start stargate-updater.service
```

Reconciliation verifies exact previous images, unchanged mounts/policy and ready
containers before marking ROLLED_BACK. Stop if it refuses; preserve the journal,
archives and logs for diagnosis. Never edit phases/hashes to report success, run
`down -v`, delete volumes, prune images, rotate identities or reset pairing as an
upgrade repair. If configuration/patch/key files have drifted, recover their
reviewed copies or perform a separately diagnosed manual recovery first.
