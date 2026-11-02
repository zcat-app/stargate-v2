# Java daily security monitor

The daily monitor now runs on Java 25. It checks Nym, i2pd, Tor packages,
Temurin, Quarkus, age and the selected Netty JAR, plus Netty/Quarkus repository
advisories and the selected runtime image evidence. It sends short change alerts
through the existing Java SimpleX sender. It accepts no chat commands and never
upgrades packages automatically.

Inspect the installed JAR and preserve its state when replacing it. A source
checkout update does not replace a running or scheduled monitor.

The [SimpleX alert guide](simplex-alerts-guide.md) explains the phone messages,
component names, examples and read-only operator checks. Message wording is
separate from event detection, retained baselines and no-retry delivery handling.

When configured with the existing monitor overrides, the manager displays the
sanitized collection and consumer snapshots.
The collector remains a separate host process because it needs Docker image
metadata. The manager receives no Docker socket or private monitor files.

## Build and configure

Use the existing Java 25 installation and Maven:

```sh
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress -pl monitor -am package
```

The executable is `monitor/target/stargate-monitor-0.1.0-SNAPSHOT.jar`.
Retain its SHA-256 and reviewed source revision when installing it. Daily runs
need Java 25, Docker/Compose access and the already configured SimpleX runtime;
they require no SQLite process. The Java dependencies come from the existing
project BOM. Source pins remain source declarations, not signed security verdicts.

Prepare a private JSON configuration using [the example](../monitor/config.example.json).
Replace every path and recipient with the existing reviewed deployment values.
Do not paste contact links, passwords, private keys or profile contents into it.
The contact ID is the existing numeric contact in the dedicated sender profile.

`recorder`, `ledger` and `dispatch` must be separate operator-owned 0700
directories. `output` must be operator-owned 0755. Private files must be owned
by the operator, mode 0600, regular, single-link files; symlinks are refused.
Paths must be absolute and normalized. Directory overlap and inode aliases are
refused. The existing dedicated sender profile remains owned by 10001:10001,
mode 0700. Its contents are never read by this monitor.

Every run passes the selected security inputs to the runtime collector:
`security_selection`, `security_runtime_containers`, `security_dispositions` and
`security_max_age_seconds`. The selected container image IDs must match fresh
Docker observations. Supplied Trivy scans must name those same image IDs in
`Metadata.ImageID`. `ArtifactID` is retained separately: Trivy 0.76.1 defines it
as an image-and-repository identifier, not the Docker image ID. See the
[released report schema](https://raw.githubusercontent.com/aquasecurity/trivy/v0.76.1/pkg/types/report.go).
Extracted-file/image associations remain operator assertions. Stale identities,
changed images, malformed or incomplete OSV responses fail to unknown. OSV and
scanner findings remain candidates: applicability, backports, exposure and
complete coverage are not established. A release check is not an upgrade verdict.

```sh
java -jar /absolute/reviewed/monitor.jar collect --config /absolute/private/config.json
```

`collect` refreshes private evidence without creating alert events or sending.
Use a staging recorder/output configuration for verification. Exit 0 means all
selected observations completed, 2 means collection unknown, and 4 means the
operation was refused or incomplete. Public output contains no browsing data,
credentials, profile data, advisory details or raw upstream responses.

## Runtime security evidence

Set `security_selection` to a private JSON file describing the exact running
images and independently extracted files. For example, replace every sample
ID/path before use:

```json
{
  "schema_version": 1,
  "images": [{
    "role": "app",
    "image_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scan": "/absolute/private/app-trivy.json",
    "files": [
      {"image_path": "/app/example.jar", "local_path": "/absolute/private/extracted/example.jar"},
      {"image_path": "/opt/java/release", "local_path": "/absolute/private/extracted/java-release"}
    ]
  }]
}
```

Allowed roles are `app`, `tor`, `i2p`, `nym` and `sender`, each once. Every selected
image requires a readable Trivy scan; `scan: null` is not supported. The scan's
`Metadata.ImageID` must match the full selected Docker configuration image ID.
Use neither mutable tags nor registry manifest digests. An empty `files` list
does not mean no other components exist. Extract files from that exact image
without state mounts and retain the extraction method privately; supplying a
path does not authenticate its relationship to the image.

Set `security_runtime_containers` to a separate private file mapping the same
role set to actual running local container names:

```json
{"schema_version": 1, "containers": {"app": "your-app-container"}}
```

The monitor reads names, full IDs, image IDs and running state through Docker,
then saves its identity observation privately. Missing, stopped, mismatched or
ambiguous containers, malformed responses and stale identity observations fail
to unknown. Do not omit a role to imply that its software is absent. Choose a
positive `security_max_age_seconds` appropriate to the collection duration.

For selected Nym source-graph evidence, merge this optional property into the
same selection object, retaining its `schema_version` and `images`:

```json
{
  "source_graphs": [{
    "role": "nym",
    "binary_image_path": "/opt/nym/nym-socks5-client",
    "build_metadata_image_path": "/opt/nym/security-build.json",
    "graph_path": "/absolute/private/nym-cargo-osv.json"
  }]
}
```

Only one Nym graph is supported. Both image paths must be listed in Nym's selected
files. Graph source commit/lockfile hashes must match the selected build metadata,
and its binary hash must match the selected binary. This is a metadata association,
not reconstruction or attestation of the compiled binary. Only crates.io registry
packages enter these advisory queries; workspace/Git packages, feature/platform
selection, build dependencies, patches and linked code still need review.

`security_dispositions` names a private assessment file. Use an empty
`dispositions` array if there are no reviewed assessments. An individual entry
has this shape; the sample finding and hashes are illustrative:

```json
{
  "schema_version": 1,
  "dispositions": [{
    "role": "app",
    "image_id": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "scan_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    "target_index": 0,
    "id": "CVE-2026-1234",
    "package": "libc6",
    "installed_version": "2.39-local",
    "status": "backport_evidence",
    "note": "Explain the assessment and its limits.",
    "evidence_files": ["/absolute/private/evidence.txt"]
  }]
}
```

Allowed statuses are `retained_unassessed`, `backport_evidence`,
`component_absence_evidence` and `other_operator_assessment`. An entry requires a
note and at least one retained evidence file. The exact image, scan hash and
finding must match uniquely; changed bytes do not inherit an old assessment.
The report hashes evidence but does not decide whether a patch works or whether
an absence search is complete. Raw findings remain visible.

Scanner inventories, embedded JAR/JDK metadata and OSV queries are partial.
Advisory matches are candidates, not an applicability decision; source/version
matching and an empty finding list are not security clearance. Keep all raw
reports, mappings and assessment files private, and review the
[remaining security gaps](simplex-alert-security-review.md#what-monitoring-does-not-establish).

## Upgrade an already running Java monitor

This is a Java-to-Java replacement using the existing compatible configuration
and ledger schema. It is separate from the one-time legacy import below. **Never
run `init` or `import` against an existing Java ledger.** Review schema compatibility
in the candidate's `MonitorMain.Config` and `MonitorLedger.validate` first; stop
if it differs. Keep the configuration, recorder, ledger, dispatch attempts/results,
public output files and accepted receipts. Do not reset baselines, clear blocked
work or replace public snapshot files/inodes during installation.

Use the same operator and user manager as the installed monitor. First record
`systemctl --user cat` and `show -p ExecStart` for its service and timer, the timer's
enabled/active state, installed JAR hash, selected Java path and source revision.
Stop any additional scheduler/producer using these paths. Stop the timer, then
wait for the existing one-shot service to finish naturally; do not stop/kill it
mid-send. Check from the same operator session:

```bash
systemctl --user stop stargate-daily-alert-consumer.timer
systemctl --user show stargate-daily-alert-consumer.service -p ActiveState -p SubState -p Result -p ExecMainStatus
systemctl --user list-jobs --no-pager
```

Proceed only when the service is inactive or failed and no start/stop job remains.
If it is activating/running/deactivating, wait and repeat the checks. An old failure
must be understood before activation of the replacement. Leave the timer stopped
on failure; timer re-enablement is deliberate, not an exit trap.

Use existing trusted `jq` for the configuration/backup examples; stop if it is
unavailable. Stage the reviewed candidate without replacing the old JAR. The following paths
are examples: replace them with the actual installed paths, and keep the selected
config's existing absolute state/profile/input paths. Run the commands separately,
check every exit status, and retain the variables in this operator shell. The
expected candidate hash must come from the reviewed build/release record.

```bash
monitor_config=/absolute/private/config.json
monitor_old_jar=/absolute/installed/monitor.jar
monitor_java_home=/absolute/qualified/jdk-25.0.5+8
monitor_upgrade=/absolute/private/monitor-upgrade-REVIEWED_REVISION
monitor_expected_sha256=REPLACE_WITH_REVIEWED_CANDIDATE_SHA256
mkdir -m 0700 "$monitor_upgrade"
install -m 0600 monitor/target/stargate-monitor-0.1.0-SNAPSHOT.jar "$monitor_upgrade/monitor.jar"
printf '%s  %s\n' "$monitor_expected_sha256" "$monitor_upgrade/monitor.jar" | sha256sum --check
cp -p -- "$monitor_old_jar" "$monitor_upgrade/previous.jar"
cp -p -- "$monitor_config" "$monitor_upgrade/previous-config.json"
systemctl --user cat stargate-daily-alert-consumer.service > "$monitor_upgrade/previous-service.txt"
systemctl --user cat stargate-daily-alert-consumer.timer > "$monitor_upgrade/previous-timer.txt"
"$monitor_java_home/bin/java" --version
"$monitor_java_home/bin/javac" --version
"$monitor_java_home/bin/jlink" --version
```

Expect Java/compiler/linker `25.0.5` and the intended build `25.0.5+8`. Use the
wizard's qualified absolute JDK path or another reviewed protected JDK, not the
shell's unqualified `java`. Ensure the JAR and its parents are owned by the
operator and not writable by another user; keep this versioned directory in place
while the installed service refers to it. Save the actual old unit fragment and
any drop-ins from the paths shown by `systemctl --user cat` as private files too;
its combined output above is a review record, not an installable unit with drop-ins.
With all writers quiescent, make private byte-preserving backups of the configured
recorder, ledger, dispatch and output directories (`cp -a` into separate empty
0700 backup parents), retaining the original live directories and files in place.
Retain every attempt/result receipt even when its outcome is uncertain. For the
state-directory backups, after confirming each configured path is the intended
existing directory and no writers remain:

```bash
(
set -eu
for monitor_role in recorder ledger dispatch output; do
  monitor_state_path=$(jq -er --arg k "$monitor_role" '.[$k]' "$monitor_config")
  test -d "$monitor_state_path" && test ! -L "$monitor_state_path"
  mkdir -m 0700 "$monitor_upgrade/backup-$monitor_role"
  cp -a -- "$monitor_state_path" "$monitor_upgrade/backup-$monitor_role/tree"
done
)
```

Stop on any failed command; retain partial backups and leave the timer stopped.

Verify the candidate collector using a separate private probe config. Copy only configuration values and use new probe
recorder/output/ledger/dispatch paths. Keep the existing source root, selected
security evidence, dedicated sender profile and recipient values. This `collect`
command performs observations (including Docker/network access) but does not
create events or dispatch messages; it must not use the live recorder/output.

```bash
mkdir -m 0700 "$monitor_upgrade/probe"
mkdir -m 0700 "$monitor_upgrade/probe/recorder" "$monitor_upgrade/probe/ledger" "$monitor_upgrade/probe/dispatch"
mkdir -m 0755 "$monitor_upgrade/probe/output"
jq --arg p "$monitor_upgrade/probe" '.recorder=($p+"/recorder") | .output=($p+"/output") | .ledger=($p+"/ledger") | .dispatch=($p+"/dispatch")' "$monitor_config" > "$monitor_upgrade/probe/config.json"
chmod 0600 "$monitor_upgrade/probe/config.json"
"$monitor_java_home/bin/java" -jar "$monitor_upgrade/monitor.jar" collect --config "$monitor_upgrade/probe/config.json"
jq -e '.checks.temurin.observation.source_baseline | .source == "containers/java-runtime.json" and .version == "25.0.5"' "$monitor_upgrade/probe/recorder/latest-report.json"
```

Expect collection exit 0 and baseline check `true`. Exit 2 means unknown collection;
4 means refused/incomplete. Keep the timer stopped and investigate any nonzero exit,
null baseline or unexpected source/version. This probe does not validate sending,
phone delivery or the live ledger; it leaves the existing blocked/uncertain work
untouched. Do not use `run` as an installation test until deliberate activation.

Copy the service template to its staging name and edit that file locally:

```bash
install -m 0600 manager/release-monitor/systemd/stargate-daily-alert-consumer.service.in "$monitor_upgrade/stargate-daily-alert-consumer.service"
```

Replace `@ABSOLUTE_JAVA@`, `@MONITOR_JAR@` and `@MONITOR_CONFIG@` with complete
systemd-quoted argument tokens (including enclosing double quotes and escaping
backslashes/quotes); reject newline, control or `%` specifier characters in these
example paths. Replace `@TIMEOUT_START_SECONDS@` with the existing reviewed
positive timeout. Use the qualified
`.../bin/java`, **versioned candidate** JAR above, unchanged live config path and
reviewed timeout. Retain the installed timer's 09:00 Europe/Prague schedule,
freshness policy and `Persistent=true`. Replace every placeholder; compare against
the installed fragment/drop-ins and review the effective command. Save the rendered
service as `$monitor_upgrade/stargate-daily-alert-consumer.service`, then:

```bash
systemd-analyze --user verify "$monitor_upgrade/stargate-daily-alert-consumer.service"
install -d -m 0700 "$HOME/.config/systemd/user"
install -m 0644 "$monitor_upgrade/stargate-daily-alert-consumer.service" "$HOME/.config/systemd/user/stargate-daily-alert-consumer.service"
systemctl --user daemon-reload
systemctl --user cat stargate-daily-alert-consumer.service
systemctl --user show stargate-daily-alert-consumer.service -p ExecStart
```

Stop if a drop-in or other unit search path changes the reviewed command. Repeat
the candidate SHA-256 check above, and verify ExecStart names its exact path, the qualified
Java and **original live config** before proceeding. The next command is the
explicit activation boundary: `run` can advance the existing ledger and send an
alert through the configured contact. Run it once, then inspect the result,
private evidence and sanitized snapshots without dumping private data into chat:

```bash
systemctl --user start stargate-daily-alert-consumer.service
systemctl --user show stargate-daily-alert-consumer.service -p Result -p ExecMainStatus
journalctl --user -u stargate-daily-alert-consumer.service -n 10 --no-pager
```

Expect `Result=success`, `ExecMainStatus=0` for a complete quiet/accepted run.
Exit 2 preserves unknown observations; exit 4 requires investigation. In particular,
`blocked_uncertain` / `future_collection_blocked=true` or
`fresh_observation_required` is **not** permission to retry a send or erase a
marker. An accepted existing receipt can acknowledge pending work without resending;
a new fresh observation then requires a separately reviewed activation. Retain the
timer stopped until that condition is resolved. No automatic retry is added.

Only after the new reader, effective unit and deliberate activation are accepted,
restore the recorded scheduling intent (do not enable a previously disabled timer):

```bash
systemctl --user enable --now stargate-daily-alert-consumer.timer
systemctl --user list-timers stargate-daily-alert-consumer.timer --all
```

A persistent timer can catch up immediately. If installation fails before activation,
retain the candidate evidence and restore the saved original unit/drop-ins and old
JAR path, verify/reload and inspect ExecStart before considering scheduling. Never
restore old ledger/dispatch snapshots over live state after a candidate has run.
If state advanced, rollback requires explicit schema/history reconciliation with
all durable receipts; the backup is evidence, not a mechanism to resend alerts.

### Older installed collectors

Before removing an old source checkout, inventory every service, timer and
manual launcher using it. Older collectors can read different baseline inputs
from their configured source root. A successful build of a new JAR does not
replace those scheduled readers. Use the separate probe above, inspect the first
live baseline, and keep a protected compatible source/configuration copy with
the old JAR for rollback. Never switch an old collector to an incompatible new
source tree, reset its fingerprint to hide a lost baseline or overwrite advanced
ledger/receipt state.

## Import a legacy monitor once

Stop the old timer and service before migration; also stop any separately
scheduled producer against the same state. Retain the old unit, database,
existing recorder files, dispatch markers and bridge byte-for-byte. Missing legacy
lock files may be created by the importer; existing evidence is not rewritten.
Do not erase uncertain work
or reset baselines to force a successful migration.

Choose a **new empty** private ledger directory in the Java configuration. Keep
the existing dispatcher directory and recipient/profile. Keep the existing public
snapshot paths so the manager's read-only inode mounts remain valid. The importer
requires no pending ledger event and a fully acknowledged bridge receipt. It
locks the old recorder, ledger, bridge and dispatcher using Linux flock, verifies
the exact legacy schema and database integrity, and reads SQLite in read-only
mode. It preserves epoch, sequence, health, baselines and advisory history.

```sh
java --enable-native-access=ALL-UNNAMED -jar /absolute/reviewed/monitor.jar \
  import --config /absolute/private/config.json \
  /absolute/old/ledger /absolute/old/bridge
```

Only this one-time import uses Java 25's native API and the host's existing
`libsqlite3.so.0` and `libc.so.6`. It downloads no native dependency. Daily Java
execution requires no native-access option. Import refuses an existing new
ledger, unresolved work, unsupported schema, journal files, changed database
bytes or a concurrent legacy writer. An exact older ledger schema without the
later Quarkus advisory table can also be imported without altering it.

For a genuinely new installation, `init --config /absolute/private/config.json`
creates a new ledger instead. Never use `init` to replace migration/history.

## Schedule and recover

### Install a fresh daily schedule

Use this after configuring the monitor, preparing its persistent directories,
and initializing a genuinely new ledger or importing compatible existing state.
For an installed Java monitor, use the state-preserving upgrade procedure above
instead. Do not run two producers against the same recorder, output or ledger.

The sender invokes fixed `/usr/bin/docker` with rootful
`unix:///var/run/docker.sock`, project `stargate-simplex-alert`, service
`simplex-alert`, and `compose.simplex-alert.yaml` beneath the configured
`source_root`. Its child environment is cleared, then receives only a fixed
PATH and the configured profile/contact values; ambient Docker/Compose overrides
cannot select another daemon or project. The operator needs access to that
socket and the dedicated runtime must already be running with the intended
profile and recipient. A rootless daemon or differently named sender project is
not selectable here. Configuration validates metadata/ID syntax; it does not
verify or change the running runtime's recipient. Installing the schedule neither
starts nor rebuilds that runtime.

Stage **both** [service](../manager/release-monitor/systemd/stargate-daily-alert-consumer.service.in)
and [timer](../manager/release-monitor/systemd/stargate-daily-alert-consumer.timer.in)
from the reviewed checkout. Select a new private staging directory:

```sh
monitor_unit_stage='/absolute/private/unit-stage'
test ! -e "$monitor_unit_stage"
test ! -L "$monitor_unit_stage"
install -d -m 0700 "$monitor_unit_stage"
install -m 0600 manager/release-monitor/systemd/stargate-daily-alert-consumer.service.in \
  "$monitor_unit_stage/stargate-daily-alert-consumer.service"
install -m 0600 manager/release-monitor/systemd/stargate-daily-alert-consumer.timer.in \
  "$monitor_unit_stage/stargate-daily-alert-consumer.timer"
```

Edit those two staged files. In the service, replace `@ABSOLUTE_JAVA@`,
`@MONITOR_JAR@` and `@MONITOR_CONFIG@` with complete double-quoted systemd
argument tokens naming the qualified Java executable, installed monitor JAR and
private JSON configuration. Escape embedded backslashes/quotes; reject control,
newline, carriage-return, `%` and `$` characters in these example paths.
Use positive decimal seconds for `@TIMEOUT_START_SECONDS@`, allowing the chosen
collection enough time to finish. This is systemd command syntax: do not put
shell exports, pipes or redirections in `ExecStart`.

In the timer, replace `@DAILY_ON_CALENDAR@` with the selected literal expression,
for example `*-*-* 09:00:00 Europe/Prague`. Keep `Persistent=true` unless
intentionally changing catch-up behavior. Verify all substitutions and the actual
calendar without starting anything:

```sh
rg '@[A-Z_]+@' "$monitor_unit_stage/stargate-daily-alert-consumer.service" \
  "$monitor_unit_stage/stargate-daily-alert-consumer.timer"
systemd-analyze --user verify \
  "$monitor_unit_stage/stargate-daily-alert-consumer.service" \
  "$monitor_unit_stage/stargate-daily-alert-consumer.timer"
systemd-analyze calendar '*-*-* 09:00:00 Europe/Prague'
```

Expect no placeholder matches (`rg` exit 1), successful unit verification and
the intended next calendar occurrence. Use your selected calendar in the last
command. These checks do not validate live state, recipient identity, Docker
access or network behavior. Inspect any service drop-ins and relevant user-manager
environment; do not assume interactive shell settings reach a scheduled service.

Inventory user/system timers, cron entries and wrappers using these same paths.
Disable each actual competing producer and let active work finish naturally. If
the standard standalone producer timer is installed, use:

```sh
systemctl --user disable --now stargate-release-observations.timer
systemctl --user is-active stargate-release-observations.service
```

Require that producer's service to be inactive before continuing. Disabling a
timer does not stop an already running producer; do not kill one to hurry setup.
This example does not disable other cron/system jobs. Keep their previous settings
for recovery, and investigate unresolved monitor sends before scheduling.

Install both reviewed units as the same operator, then reload the user manager:

```sh
install -d -m 0700 "$HOME/.config/systemd/user"
install -m 0600 "$monitor_unit_stage/stargate-daily-alert-consumer.service" \
  "$HOME/.config/systemd/user/stargate-daily-alert-consumer.service"
install -m 0600 "$monitor_unit_stage/stargate-daily-alert-consumer.timer" \
  "$HOME/.config/systemd/user/stargate-daily-alert-consumer.timer"
systemctl --user daemon-reload
systemctl --user cat stargate-daily-alert-consumer.service stargate-daily-alert-consumer.timer
systemctl --user show stargate-daily-alert-consumer.service -p ExecStart
```

Expect the exact reviewed Java/JAR/configuration paths and chosen calendar. Stop
if another unit or drop-in changes them. For operation after logout/reboot, follow
[Docker startup and operator lingering](persistent-deployment.md#deliberate-activation-and-later-restart);
lingering alone does not guarantee a completed daily check or phone delivery.

The first activation makes real observations and can send a change/failure alert.
When ready for those effects, run it **once**, then inspect its result:

```sh
systemctl --user start stargate-daily-alert-consumer.service
systemctl --user show stargate-daily-alert-consumer.service \
  -p Result -p ExecMainCode -p ExecMainStatus
journalctl --user -u stargate-daily-alert-consumer.service -n 20 --no-pager
```

Run separately and retain each exit. Expect `Result=success` and
`ExecMainStatus=0` for a complete quiet/accepted run. A successful journal read
does not repair a failed activation. Exit 2 means incomplete collection; exit 4
requires investigation, including blocked/uncertain work. A service timeout or
signal is uncertain even if an older snapshot still looks fresh. Do not start an
immediate second pass to clear a failure or resend an alert.

Only after reviewing the initial result and retained state, enable the timer:

```sh
systemctl --user enable --now stargate-daily-alert-consumer.timer
systemctl --user list-timers --all stargate-daily-alert-consumer.timer
systemctl --user show stargate-daily-alert-consumer.timer -p NextElapseUSecRealtime -p LastTriggerUSec
```

Check the next activation and any immediate persistent catch-up. A timer event
while the oneshot is active does not start a second instance. Enabling a timer
does not establish successful collection, phone delivery or a missed-run alarm.

For an intentional manual run instead of the service, with no concurrent writer:

```sh
java -jar /absolute/reviewed/monitor.jar run --config /absolute/private/config.json
```

This has the same collection/send effects; it is not an extra setup check.
To pause future activations:

```sh
systemctl --user disable --now stargate-daily-alert-consumer.timer
```

Allow any current oneshot to finish and inspect its result. If an emergency
requires stopping it, preserve all state and treat sending as uncertain.

### Recover blocked or incomplete work

The service has no automatic restart. A durable UNKNOWN attempt marker precedes
every external send. An accepted durable receipt can finish acknowledgement
after a crash without resending. A missing/uncertain/rejected receipt blocks
future collection and requires operator investigation; never remove markers to
retry. Local acceptance does not prove phone delivery. When recovering existing
work, the next activation requires a fresh observation; it does not silently
collect over that work. Keep the original ledger/archive as evidence. Do not
switch back to the old writer after Java advances its ledger: the histories have
diverged and require explicit reconciliation.

The public status is unknown whenever any selected collection is incomplete,
including repeated failures that produce no new alert. Snapshot files keep their
inodes and use POSIX locks compatible with existing manager readers. No image
rebuild is needed for this monitor migration.

To enable the manager display, add `compose.release-monitor.yaml` and
`compose.consumer-monitor.yaml` to the deployment's existing complete Compose
file list. Set `STARGATE_RELEASE_SNAPSHOT_FILE` and
`STARGATE_CONSUMER_SNAPSHOT_FILE` to the two existing public files, and select
positive `STARGATE_RELEASE_MAX_AGE_SECONDS` and
`STARGATE_CONSUMER_MAX_AGE_SECONDS` values appropriate to the daily schedule.
Validate the full Compose configuration before recreating only the app. These
overrides mount only the sanitized files, read-only.
Keep all existing deployment overrides and volumes.
