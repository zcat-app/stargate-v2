# Act on an update alert

An alert means a checker observed a change or could not finish. It does not mean
the new release fixes your deployment, that your route is broken, or that an
upgrade has been installed. First use the [alert guide](simplex-alerts-guide.md)
to identify the component and observation. Checker recovery is not traffic
recovery. Unchanged observations can be quiet even while a failure persists;
inspect the manager's snapshot age and the Java monitor's service result too.

## Operator: install a qualified Stargate release

For the normal operator, use a qualified **Stargate image release**, rather than
installing Tor/i2pd/Nym/JDK packages directly into a running container. Existing
native patches, libraries and state compatibility matter. A version notification
does not authorize removing those patches or weakening a failed test.

1. Record the source, exact four image IDs, complete resolved Compose inputs,
   project, volume names and persistent bind paths. Follow
   [persistent configuration](persistent-deployment.md); do not recreate a
   recovered installation using repository defaults. Keep the active signed
   upgrade override in later commands if one exists.
2. Read the candidate's changes, build/scan records, remaining vulnerabilities,
   state compatibility and rollback limits. Verify its release signature against
   the independently pinned project key. A checksum fetched beside an unknown
   file does not authenticate its publisher. Review any native-client change and
   preserved-byte policy transition separately; do not delete a failing guard.
3. Arrange a maintenance window and exclusive control of this project's Docker
   resources. Make and verify the matching stopped-volume backup using
   [backup/recovery](operator-guide.md#6-backup-and-recovery), including both Nym
   roots. Keep the decryption key separate and protect old images/configuration.
   Ordinary backups do not include the external deployment records automatically.
4. Use [Review, Install and Roll back](verified-upgrades.md#review-and-install).
   That procedure contains the exact host setup, key pinning, manifest signing,
   manager actions, CLI fallback and interrupted-transaction commands. Installing
   ends active connections in replaced services; app replacement also ends the
   administrator web session. Log in again with the retained token. Queueing an
   action is not confirmation it finished.
5. Confirm exact installed IDs, unchanged volume mappings, startup policy and
   private native ports. Test actual Tor, I2P and Nym requests in saved Firefox
   and Brave pairings. Check revoked access remains rejected and no credentials
   reached controlled destinations. Container health and SOCKS greetings alone
   do not prove destination access.
6. Refresh the monitor evidence for the actual installed images as below. Retain
   the candidate manifest, signature, exact configuration, transaction and route
   observations with the protected installation record. Do not prune rollback
   images or erase failed evidence to obtain a green status.

Each installation needs a configured signer/feed and the one-time app/updater
bootstrap described in the upgrade guide. The host worker does not rebuild
source, run arbitrary release scripts or handle state/schema migrations. Image
archives and manifests must be available over HTTPS. The updater supports
public GitHub release assets through bounded, validated redirects; private
release authentication is not supported. See [public release downloads](public-release-downloads.md).

Rollback restores the previous **images**, retaining the latest volume data.
It does not undo writes, resurrect a deleted key safely or revert a schema.
Follow [rollback/reconciliation](verified-upgrades.md#rollback-and-interrupted-operations)
and keep failed/interrupted copies offline when their completeness is unknown.
Do not restore an old backup merely to undo an image update: it can restore
revoked credentials and stale I2P allocation history. Use the separate recovery
gates and identity procedures when a real data restore is required.

## Maintainer: build only the affected candidates

This section is for preparing a reviewed release, not automatic operator action.
Use a separate checkout/workspace and a new context/tag for each candidate.
Authenticate newly chosen upstream inputs using that project's supported release
mechanism before updating source pins. Retain signed metadata, key fingerprints,
archive hashes and source/patch review. The existing hashes describe the selected
baseline; they do not authenticate a newly chosen version or prove a patch works.

| Changed input | Source and required checks | Candidate targets to consider |
| --- | --- | --- |
| Proxy/manager or Netty/Quarkus | Root `pom.xml`, Java code; normal Maven tests, authentication/privacy/lifecycle and real browser checks | `app`; also `nym` when its included proxy JAR/runtime changes |
| Java runtime | `containers/java-runtime.json`, authenticated JDK/toolchain pins and image-input preparation; qualify the new runtime | `app` and `nym`; the separate SimpleX runtime also embeds Java |
| Tor | Authenticated Tor repository Release → Packages → two pinned .deb files in `containers/tor-packages.json`; retain patched OS files | `tor` only for a Tor-only change |
| i2pd | Pinned release/source plus both local identity/lifecycle patches; owner binary and lifecycle/identity tests | `i2p`; coordinate matching app protocol changes when needed |
| Nym | Released source/lock, security, lifecycle and shared-client patches; all named Rust and TLS regressions, build-info and binary checks | `nym`; coordinate launcher/protocol changes when needed |
| libc or common runtime libraries | Authenticated native inputs, existing backport, full package checks and calibrated control/patched regression; inventory actual role files | Every image containing changed library bytes; qualify the separate sender too |
| SimpleX sender/release/libraries | Its signed public release, pinned libraries, stopped dedicated-profile backup and supported schema; no automatic migration | Separate `simplex-alert` image/project; not one of the four signed-updater targets |

The Dockerfile shows Java in app/Nym, not Tor/i2pd. The Nym image contains the
proxy JAR for its launcher. Inspect the actual changed runtime/classes and image
inventories rather than rebuilding all images by habit. Keep native unchanged
images when their inputs and bytes are unaffected.

For Java app changes, build from the reviewed source with the selected toolchain:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress \
  -pl proxy,manager -am package
```

Missing cache entries require an intentional online dependency resolution;
failed tests require diagnosis. Do not pass skip-test or native `nocheck` flags.
Build the controller JAR before its Bash launcher; the exact native commands,
input admissions and failure records are in [native tools](native-build-tools.md)
and [libc tools](libc-build-tools.md), with bootstrap in the container guide.
Prepare a new context with the [Java image-input procedure](image-input-preparation.md),
including the selected Nym build directory and complete manager output.

For each actually affected role, substitute its reviewed prepared context and a
new local candidate tag. `app` below is an example, not a reason to rebuild it
for a Tor-only update:

```sh
candidate_context='/absolute/path/to/new-qualified-context'
candidate_tag='stargate-v2-app:REPLACE_WITH_UNIQUE_CANDIDATE'
docker build --file containers/Dockerfile --target app \
  --tag "$candidate_tag" "$candidate_context"
docker image inspect "$candidate_tag" --format '{{.Id}}'
```

For a Tor-only change, authenticate the official repository's signed Release,
then its SHA-256 for the amd64 Packages index, then each Tor/GeoIP package's
version, filename and SHA-256 against the reviewed `containers/tor-packages.json`.
Check the signing key against [Tor's published installation instructions](https://support.torproject.org/little-t-tor/getting-started/installing/).
A package hash alone is not repository-signature verification. The helper below
checks the pinned package hashes and metadata; it does not fetch or authenticate
a new upstream release for you. With the exact reviewed base image ID, verified
package directory and a new output directory:

```sh
tor_base='sha256:REPLACE_WITH_FULL_REVIEWED_BASE_IMAGE_ID'
tor_context="$PWD/target/tor-update-candidate"
tor_packages='/absolute/path/to/verified-tor-packages'
bash tools/prepare-tor-update.sh "$tor_base" "$tor_context" "$tor_packages"
docker build --target tor --file containers/Dockerfile \
  --tag stargate-v2-tor:REPLACE_WITH_UNIQUE_CANDIDATE "$tor_context"
```

The preparer exports an unstarted base container without product state mounts.
It checks non-Tor regular-file bytes and directory modes, including the retained
libc backport, while replacing the selected Tor/GeoIP files and metadata. It
refuses existing output and unsafe destination links. Keep its output and exact
image ID for release qualification. Do not deploy by copying private example
project names or dropping an existing active override.

For SimpleX, use [its independent runtime guide](simplex-alert-runtime.md).

Keep new immutable image IDs and selected packages/runtime hashes, scan those
images, review applicability/backports and retain unresolved findings. Qualify
the intended image transitions and rollback using synthetic/controlled state,
then real browsers, before signing. Rebuilding a source commit alone does not
guarantee identical images: the OS package source stage can contact mutable
repositories. The signed release pins the assembled archives and image IDs;
retain the actual build inputs and evidence. Do not publish a partially qualified
context or infer image reproducibility from the fixed Java-build evidence.

## Refresh deployed security evidence

Do this after a deliberate image replacement, not by rewriting scan JSON to
match a desired ID. Work in a new private evidence directory. Preserve old
selections and dispositions with their original hashes.

1. Obtain each actual container's full `.Image` ID and check its expected role.
   Scan that exact image using the reviewed scanner/database. Retain the raw
   output and database timestamp; a scan is incomplete coverage, not clearance.
2. Extract selected regular runtime files from an **unstarted** container of
   that exact image, with no state mounts. The
   [monitor evidence guide](java-monitor.md#runtime-security-evidence) defines the selection schema,
   source-graph association and its operator-assertion limits. Preserve the
   file-to-image mapping and raw scan bytes; Trivy `Metadata.ImageID` is the
   Docker identity, while `ArtifactID` has a different meaning.
3. Review findings against released source, selected bytes and exposure. A
   disposition belongs to its exact image/scan/finding tuple; rebind only after
   verifying the unchanged evidence. Unknown applicability remains unknown.
4. Update a copy of the private Java monitor configuration with those selection,
   runtime-container and disposition paths, keeping the existing ledger policy,
   contact and dispatch history. `collect` does not publish alerts or send, but
   it does refresh its selected recorder; use a separate staging recorder/output
   while checking new evidence. Do not run concurrent writers on live state.

```sh
bash tools/with-toolchain.sh java -jar /absolute/reviewed/monitor.jar \
  collect --config /absolute/private/staging-monitor-config.json
```

Exit 0 means selected observations completed; 2 means unknown collection and 4
means refused/incomplete. Inspect retained evidence, not just the exit code.
Reconcile and deliberately install the reviewed production selection during the
maintenance window using [the Java monitor guide](java-monitor.md). Keep its
timer/history and no-retry handling. This command does not activate the selection,
prove phone delivery or assert that a vulnerability is fixed. Running the daily
`run` action can send a real alert and must use the intended recipient.
