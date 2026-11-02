# Container installation

The base Compose configuration runs three services: `app` contains a small process supervisor and separate
Java proxy/Quarkus manager JVMs; `tor` contains the Tor client; `i2p` runs the pinned i2pd release with the documented identity-failure patch. No Docker socket,
host PID namespace, host networking or systemd installation is required. Add
`compose.nym.yaml` for the ordinary-web Nym route described below.

## Build and start

The prepared-builder libc path uses a separately prepared `stargate-v2-libc-build`
container and source chroot. The fixed-input bootstrap can instead prepare a
new, independently labeled builder. First satisfy the host prerequisites;
previously built packages under `target/native` do not establish a clean rebuild.

First build the Java host tools using the verified toolchain (see
[prerequisite setup](../docs/setup-prerequisites.md)):

```sh
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress -pl bootstrap-tools,libc-tools,native-tools -am package
```

Run `bash tools/check_libc_builder.sh` for a read-only prerequisite diagnostic.
It checks the local patch hash, container state and existence of paths named by
the input manifest. An unknown result may indicate inaccessible paths or a Docker
error. It does not verify source hashes, patch application, dependencies or build
results, and does not bootstrap the builder or prove a clean rebuild.

### Prepare libc source on a clean host

On Linux, run as an ordinary user with the verified Java 25 JDK and trusted distribution
`/usr/bin/dpkg-source`, `/usr/bin/patch` and the unpacker's archive tools already
installed:

```sh
bash tools/prepare_libc_source.sh --workspace-parent /tmp
```

This source-only command creates a fresh mode-0700 workspace under the existing
parent directory. It fetches the three pinned Ubuntu source files and the
DSC-required `glibc_2.39.orig.tar.xz.asc` from the fixed
[official HTTPS archive](https://archive.ubuntu.com/ubuntu/pool/main/g/glibc/).
The auxiliary signature has its own additive `source_auxiliary_files_sha256`
manifest field; the existing builder still checks its original three inputs.
The command verifies every downloaded SHA256 and the unchanged local patch hash,
and checks that the auxiliary digest and 833-byte size agree with the verified
DSC. These are Git-pinned integrity checks, **not publisher signature
authentication**. Missing signing keys may produce warnings in `unpack.log`;
no keys are imported and normal `dpkg-source` checksum checks remain enabled.

Only the trusted unpacker runs with umask 022, so extracted source directories
remain mode 0755 and regular files remain mode 0644 or 0755 for tests that
change user. The command checks these modes before and after the backport; it
does not repair archive permissions. The surrounding workspace stays mode 0700,
helper files and logs are private, and patch subprocesses keep umask 077.
Copy the source tree into the isolated builder before running tests as other users;
the private workspace itself is deliberately not traversable by them.

The trusted unpacker applies Ubuntu's existing patch series, then the command
applies the exact local backport only to its regular, non-linked target. It
requires one full exact preimage, zero fuzz and the exact expected postimage.
A line-number offset is allowed: this pinned Ubuntu source matches at line 305
instead of the patch header's upstream line 355. `patch-check.log` and
`patch-apply.log` retain that observation.

The printed workspace retains inputs, source, logs and `status.json`, including
the target's before/after hashes. Any failed preparation remains `incomplete`;
keep its evidence and rerun to create another fresh workspace. Existing source
trees are never reused. No dependencies are installed, no chroot or container is
created and no compilation or source build/test commands run. A `prepared`
source tree is **not a usable chroot, complete bootstrap or libc build proof**;
this command does not populate the separately prepared builder below.

Offline boundary checks (including synthetic source extraction with the real
system tools):

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml -Dtest=SourcePreparerTest test
```

### Prepare the candidate clean-builder CA seed

Prepare a temporary HTTPS trust bundle for the
pinned Ubuntu noble amd64 base. It does not create or validate a builder.
The candidate official Ubuntu image manifest is
`sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc`.
Its verified image layer has APT, gpgv and the Ubuntu archive keyring, but no
installed CA bundle. It is not asserted to match the existing builder.

Download these exact files over HTTPS using the host's normal trusted TLS setup:

```sh
snapshot=https://snapshot.ubuntu.com/ubuntu/20261027T000000Z
seed_downloads=$(mktemp -d /tmp/stargate-libc-seed-downloads.XXXXXXXX)
curl --fail --location --output "$seed_downloads/noble-updates.InRelease" "$snapshot/dists/noble-updates/InRelease"
curl --fail --location --output "$seed_downloads/noble-updates-main.Packages.xz" "$snapshot/dists/noble-updates/main/binary-amd64/Packages.xz"
curl --fail --location --output "$seed_downloads/noble-ca-certificates.deb" "$snapshot/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.1_all.deb"
bash tools/prepare_libc_seed_ca.sh \
  --inrelease "$seed_downloads/noble-updates.InRelease" \
  --packages "$seed_downloads/noble-updates-main.Packages.xz" \
  --ca-deb "$seed_downloads/noble-ca-certificates.deb" --workspace-parent /tmp
```

The helper requires trusted system `gpgv`, `dpkg-deb` and the pinned Ubuntu
archive keyring. It uses gpgv to verify
its pinned signer and release bytes. It checks the signed index's size and
SHA256, then the CA package's signed record, size and SHA256. It reads the 120
packaged Mozilla certificates with `dpkg-deb` and writes a bundle in a new
private workspace; it neither installs the package nor alters host trust.
This snapshot's signed release has no `Valid-Until` field; the helper does not
perform a freshness check. The package and release are intentionally fixed,
so a different snapshot requires review and new pins. The bundle remains an
intermediate for a future isolated bootstrap, not a general trust-store update.

To check the dependencies, first prepare source and the CA bundle using
the commands above. In a **new disposable** container from the exact candidate
image, copy the prepared source, four source files and bundle to `/build`.
Configure only the fixed snapshot URL above for `noble`, `noble-updates` and
`noble-security`, with `main universe`, both `deb` and `deb-src` entries and
`signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg`. Verify the copied
hashes and source before running these commands inside that container:

```sh
apt-get -o APT::Update::Error-Mode=any -o Acquire::https::CAInfo=/build/bootstrap-ca.pem update
DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::CAInfo=/build/bootstrap-ca.pem install -y ca-certificates build-essential
apt-get -o APT::Update::Error-Mode=any update
DEBIAN_FRONTEND=noninteractive DEB_BUILD_OPTIONS= DEB_BUILD_PROFILES= \
  apt-get build-dep -y /build/glibc_2.39-0ubuntu8.9.dsc
DEBIAN_FRONTEND=noninteractive apt-get install -y quilt autoconf debhelper texinfo xsltproc \
  rdfind symlinks netbase gperf systemtap-sdt-dev libaudit-dev libcap-dev \
  libselinux1-dev libgd-dev dpkg-dev xz-utils gettext
cd /build/glibc-2.39
DEB_BUILD_OPTIONS= DEB_BUILD_PROFILES= dpkg-checkbuilddeps
```

Record the commands, exit codes and `dpkg-query` package versions. The helper's
shorter `DEPS` list alone is not the complete source-declared dependency set.
A successful dependency check does not compile libc, run its tests or create
the build chroot. Use a new disposable container for this check.

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml -Dtest=CaSeedTest test
```

### Select an independently prepared builder

The build helper also accepts an explicit, independently prepared fresh builder.
This selection does not create its `/work/root` chroot or make that chroot ready.
The fixed-input bootstrap in
[the dependency-seed runbook](../docs/libc-dependency-seed.md#prepare-a-fresh-builder)
creates and checks such a chroot. Readiness does not mean libc has built or
passed its native tests.
A separately prepared builder must contain the pinned patched source and its
archives, checked build dependencies, and the mount and namespace prerequisites. Use a new running builder with a unique label
`org.stargate.libc.fresh-builder=<32 lowercase hex digits>` and record its full
container ID and full `sha256:` image ID when creating it. Do not reuse the
existing builder or its source tree. For example, with those recorded values:

```sh
bash tools/build_container_libc.sh \
  --fresh-builder-id "$builder_id" --expected-image-id "$builder_image_id" \
  --builder-marker "$builder_marker" --output-dir /tmp/my-new-libc-proof-output
```

All four options are required together. The output directory must be a new
absolute path with real directory parents; the helper creates it privately and
never writes its artifacts to `target/native`. It rejects the existing
builder's reserved names, verifies the selected container ID, image, running
state and label, and rejects host or shared mounts, published ports, privileged
mode and host namespace settings before changing source. Only a container-owned
`/work` tmpfs is allowed as a mount. It also rejects certain previous build
outputs and stamps. These checks do not independently prove that every source
and build input is fresh. The helper uses a uniquely named mount helper, verifies
its captured ID and fixed configuration, then prints its ID, name and label before
starting it. It verifies the helper again before cleanup and uses the same
build-only mount/ptrace permissions and
unmodified package test commands as the existing builder. If helper identity
verification or cleanup fails, retain the reported ID and investigate it; do
not remove containers by a shared name. A failed run retains the private output
directory and selected builder evidence. It must not be treated as a successful
build.

A successful package build does not establish complete container-image
reproducibility or browser behavior. Inspect its native test results and retain
all unsupported cases and failures; do not waive tests to produce packages.

Offline target-selection and command checks:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f libc-tools/pom.xml test
```

### Build with the existing prepared builder

Prepare images on Linux with the verified Java 25.0.5 JDK and Maven 3.10.0:

Image-input preparation and runtime-file collection now use Java 25:
see [the current procedure](../docs/image-input-preparation.md).
They consume already verified native outputs. Source/bootstrap, libc and I2P/Nym
controllers now use Java/Bash; see [bootstrap commands](../docs/libc-bootstrap-tools.md)
and [libc build commands](../docs/libc-build-tools.md). Native source package
maintainer tools retain their upstream build requirements.

```sh
bash tools/build_container_libc.sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl native-tools -am package
bash tools/build_i2p.sh
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress package
bash tools/prepare-image-inputs.sh
docker compose build
docker compose up -d
```

Build output hashes are provenance, not a guarantee that another environment
will reproduce the same packages or complete images.

The libc step uses the prepared `stargate-v2-libc-build` container and its
`/work/root` chroot, with the source/patch inputs in `native/glibc-inputs.json`.
It runs the original Debian package checks with `/proc` and `/dev` mounted in a
temporary build helper. The helper's mount/ptrace permissions apply only to the
build; the runtime restrictions below are unchanged. Retries clean generated
package staging and rerun the checks while retaining compiled objects. Matching
debug symbols are retained under `target/native` for Valgrind verification and
are excluded from the runtime images.

The I2P build verifies the pinned release source and narrow patch, then builds the
router and process owner in a separate tool container. It retains the existing
verified runtime libc; the builder and compiler are not deployed.

Image preparation currently requires Linux amd64 and uses `jlink` from its JDK;
the pinned Tor package is also amd64.
Users of a built image need Docker/Compose and their browser, without a host JVM,
Maven or Node installation. Cross-platform browser verification is currently on
Linux amd64; Windows/macOS Docker Desktop and arm64 are not qualified here.

Open **http://127.0.0.1:9080/**. Export the generated administrator token into a
private file with the exact Compose configuration/project selected for this
installation, following the [operator procedure](../docs/operator-guide.md#retrieve-and-keep-the-administrator-token):

Use that procedure's exact command: it stages privately and atomically publishes
a mode-0600 copy, including on repeat exports. For CLI options, run
`bash tools/container-token.sh --help`.

Check that export succeeded, then read the file in a trusted private viewer and
enter its value in the login form. Protect or remove this exported copy. The
helper uses Bash, Docker Compose and standard GNU utilities; no image
utilities are required. The manager uses a random, HttpOnly, SameSite=Strict
session cookie that expires after 30 minutes. The token is never put in a URL or
given to the extension. Native POST forms require the session, a separate CSRF
secret, the expected Origin and an allowed Host. JSON administrator APIs retain
their separate bearer-token requirements. Logging out invalidates the session;
manager restart invalidates web sessions while preserving browser-pairing grants.

The UI contains no scripts. Its CSP has `script-src 'none'` and `style-src 'self'`.
Charts.css 1.2.0 and its MIT license are bundled locally. Fixed CSS percentage
classes provide chart geometry without inline styles or external requests.

Use Start, Stop and Restart in the manager. A first installation starts with
forwarding stopped. The last requested running/stopped state survives replacement
of the app container. Start is idempotent. Start/Restart require both an actual
proxy response and listener ownership by the supervised PID; Stop requires
process termination and a refused endpoint. Closing the page or restarting only
the manager JVM preserves forwarding. Restarting the whole app container
interrupts forwarding and resets its process-lifetime counters.

Name a device and create a one-time pairing code. Each redemption creates a new
credential; fresh installations do not seed shared Firefox/Brave credentials. Follow the
[extension instructions](../extension/README.md) to pair and apply the proxy.
Use a dedicated profile: the base configuration routes .onion through Tor and .i2p through I2P, and refuses
ordinary public web destinations unless the Nym overlay is enabled. Stable Firefox uses a temporary unsigned add-on
during verification; permanent installation needs signing. Brave's built-in Tor
windows and onion-window restriction must both be off in this browser instance.

## Ports, state and scope

Only `127.0.0.1:8881` (browser proxy) and `127.0.0.1:9080` (manager) are published.
Set `STARGATE_PROXY_PORT` and `STARGATE_MANAGER_PORT` before starting Compose to
use other local ports; the manager advertises those host ports to the extension.
Changing ports requires reapplying the browser configuration.

The app has a frontend bridge for published ports and an internal backend bridge
to Tor and I2P. Both routers use the separate egress bridge. Their SOCKS/control
ports are not host-published. The app's frontend permits ordinary outbound
connectivity; these settings do not claim egress confinement after JVM compromise.
All services use UID 10001, read-only root filesystems, dropped capabilities,
`no-new-privileges` and bounded memory/process counts. Private configuration and
Tor data live in named volumes. Only the control-cookie volume is shared with
the app, read-only; Tor's other state is separate.

I2P has its own persistent router data volume. Its SOCKS port 4447 and TLS
I2PControl port 7650 are private. The app generates a persistent random control
password before I2P starts; the manager pins the router's local TLS certificate.
The certificate private key stays in the I2P data volume. Production i2pd logs
are disabled because upstream messages can contain destination names. Manager
observations distinguish router bootstrap, each device's SOCKS availability and
past received traffic. Each paired credential has a separate persistent destination
and private SOCKS port; i2pd credentials themselves do not provide Tor-style isolation.
A responding device listener reports network readiness unknown; actual destination
traffic is reported separately, and a greeting alone is insufficient. First use can take minutes.

The isolated deployment activates device destinations on the first I2P request.
Native idle is disabled: any open connection, including a silent WebSocket or CONNECT
tunnel, keeps its destination running. After the last connection closes, a 60-second
cooldown precedes unloading; `i2p.cooldownSeconds` accepts 1–3600 seconds. Keys and
nonrecycled port mappings survive unloading. Registered profiles share a 256 KiB private
configuration file; a pairing that would exceed it fails without replacing the existing
configuration. A failed redemption consumes its one-time code. Before pairing more
than 128 profiles, upgrade the manager and proxy together to versions that both
support more than 128. Do not downgrade either component while more than 128 profiles
remain; revoke enough profiles first. An older proxy rejects such a configuration and
clears its credential snapshot on refresh, disrupting authorization and connections.
Near the storage limit, pairing can succeed while the later I2P port mapping cannot
fit; that device's I2P remains unavailable. Revoke unused devices to free space, then
allow the manager to reconcile the mapping. Existing mappings and identities are
preserved. This storage limit is separate from runtime capacity. New activations require
fresh I2P-container resource observations. Native allocations are serialized until
acknowledged with a positively observed listener and a newer resource sample; remote
warm-ups can then overlap. Admission retains 32 MiB and 16 tasks of free headroom
for the next activation plus each still-warming destination. A warm-up allowance is
released on successful SOCKS CONNECT or 30 seconds after its listener was observed.
These conservative allowances and the existing 384 MiB/128-task container bounds
are guards, not a proven supported-user ceiling. A listener does not mean the public
I2P route is ready. Pending requests retain their setup deadline; active connections
are never evicted to admit another device. Public-network setup may still exceed a
browser's own timeout.

Upgrade the app and I2P images together: the matching native reload acknowledgment
patch is required. Mixed old/new binaries are unsupported. Unknown reload/resource
state freezes lifecycle mutation; the manager displays the pending/unavailable
observation. Existing traffic is retained, while new requests may time out. A forced
proxy kill can leave destinations loaded until the next proxy start; a normal stop
publishes an empty fleet after closing its connections.

The manager can stop/enable I2P for one device without stopping its Tor/Nym
routes or another device's I2P route. Stop/enable retains identity; revocation leaves
retired keys in private storage, and re-pairing allocates a new identity/port. Back up
configuration and I2P state together. Follow the [operator recovery
procedure](../docs/operator-guide.md#6-backup-and-recovery) for identity or key
failures. The router/host and private backend trust boundary remain shared;
any trusted container able to reach those NoAuth listeners can use their identities.
Nym remains shared. Copying a pairing also copies access to that device identity.

The manager controls the forwarding process. Tor and I2P lifecycle remains a Compose
operation:

```sh
docker compose restart tor i2p
docker compose logs --tail 30 app tor i2p
docker compose down
```

`down` retains configuration and keys. `down --volumes` deletes this installation's
credentials, Tor state and I2P router state. The manager owns atomic credential edits. The running proxy refreshes them every
250 ms, without network lookups. New pairings/revocations normally take effect
within one second. Revocation closes only that credential's active connections.
Older credentials remain valid on upgrade and may be shared; pair devices again
and revoke the older IDs explicitly. Do not edit the file concurrently with the
manager. Network/configuration changes still require an app restart.

Final images copy the runtime files generated by `tools/prepare-image-inputs.sh`.
Build the helper with `mvn --offline --batch-mode --no-transfer-progress -pl image-preparer -am package` first.
For Nym, keep `--nym` and the explicitly selected matching `--nym-build-dir`;
an older default build can fail the retained lifecycle/shared-client checks.
See [preparation and failure handling](../docs/image-input-preparation.md).
To fetch current distribution security packages, refresh the package source
stage, regenerate those files, and replace the images:

```sh
docker build --no-cache --target os-packages \
  --tag stargate-v2-os-packages:local \
  --file containers/Dockerfile target/container
bash tools/prepare-image-inputs.sh
docker compose build
docker compose up -d
```

A normal cached preparation can reuse its APT layer; rebuilding only the final
Compose targets does not refresh prepared runtime files. Distribution updates
cover only packages that the distribution has published. Retain required local
patches and assess remaining advisories separately; a package refresh alone
does not establish that known findings are resolved. Replacing the app interrupts
forwarding.

For a VPS, use SSH forwarding or a private tunnel to the loopback management port.
The base configuration does not publish an Internet-facing HTTP management site or
implement HTTPS/WebAuthn/mTLS administration. Container co-location shares the
application user's trust boundary; it is not isolation between compromised JVMs.

## Offline staged recovery preparation

For operator-prepared stopped matching snapshot copies, the separate
[encrypted archive tool](../docs/offline-encrypted-archives.md) packs and verifies
the five named volume roots (seven with Nym), retaining numeric ownership as
archive metadata. It does not establish that the supplied snapshots are complete
or matching. Staging, import and capture use the separate commands in that guide;
packing alone performs none of them and never activates an installation.

Older snapshots can restore revoked credentials. For stopped, separately staged
matching volumes, the explicit [offline preparation command](../docs/offline-staged-recovery.md)
discards all device credentials, rotates the administrator token, and durably
keeps forwarding stopped. Every device must pair again. It is not a backup or
restore command, and it does not resolve historical I2P port allocation rollback.

## Aggregate graphs

Graphs show process-wide Tor, I2P and Nym connection counts and forwarded bytes. HTTP body
bytes and raw CONNECT/WebSocket tunnel bytes are counted; headers and SOCKS
negotiation are excluded. Failures count proxy-generated upstream 502/504 errors,
not destination HTTP response codes. No destination, profile, client address or
individual stream is retained. A private atomic snapshot is replaced each second;
there is no traffic-history database or per-request journal.

The UI labels fresh, unavailable/stale and last-process observations separately.
Restarting the proxy starts new counters, while restarting the manager does not.
These aggregates are not a promise of anonymization or browser-wide leak protection.

## Optional ordinary-web Nym route

Use the additional `compose.nym.yaml` file to opt in. The base Compose deployment
keeps ordinary web destinations rejected. The overlay publishes no additional
ports and gives only the Nym container access to its persistent router state and
mode0600 key-passphrase file in separate named volumes. Back up both volumes.
Removing the overlay disables the route on the next app recreation without
changing browser pairing credentials.

See [Nym setup and state](../docs/native-build-tools.md#enable-nym-and-preserve-its-state) for the pinned
client build, current provider setting, exact commands, payment limitations and
manual recovery after interrupted initialization. The passphrase encrypts local
private keys; it is not a wallet seed or a payment credential.
