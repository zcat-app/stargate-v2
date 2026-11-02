# Persistent configuration and startup

Prepare a persistent configuration before enabling automatic startup. Back up the
matching state and schedule any container recreation: it interrupts active users.
Do not reboot a host until its effective configuration and startup services are ready.

Use the exact installation/project selected by the `sg` function in the
[operator guide](operator-guide.md#keep-every-command-tied-to-that-installation).
Keep every existing image override, environment input and state-volume name.
The base files use `unless-stopped`; a recovered test configuration can explicitly
override that with `no`. Inspect the effective configuration and containers.

## Prepare a private persistent copy

Run as the Docker-authorized operator, from the intended checkout. The commands
require Bash, jq, Docker Compose and standard GNU tools. The chosen directory
must be new and on persistent local storage, outside `/tmp` and shared writable
directories. They start or restart nothing:

```sh
set -e
umask 077
deployment_dir="$HOME/.local/share/stargate/deployments/production-candidate"
test ! -e "$deployment_dir"
test ! -L "$deployment_dir"
install -d -m 0700 "$deployment_dir"
sg config --quiet
sg config --format json > "$deployment_dir/previous.compose.json"
chmod 0600 "$deployment_dir/previous.compose.json"
jq '.services |= with_entries(.value.restart = "unless-stopped")' \
  "$deployment_dir/previous.compose.json" > "$deployment_dir/compose.json"
chmod 0600 "$deployment_dir/compose.json"
docker compose --project-name "$stargate_project" \
  --file "$deployment_dir/compose.json" config --quiet
```

`production-candidate` is an example new name, not an existing live path. If
preparation fails, keep its files private, correct the cause and choose a new
candidate directory; never deploy a partially written result. If the `sg`
function is unavailable, define it first with the exact installation inputs.
For a new remote installation, the existing wizard can instead write its new
resolved file directly to a private persistent location; retain the same checks
below. This copy does not resolve an incorrect original deployment selection.

Review the files privately using `LESSHISTFILE=- less -- "$deployment_dir/compose.json"`.
Compare source and candidate; the initial copy above changes only restart policy:

```sh
diff -u \
  <(jq -S 'del(.services[].restart)' "$deployment_dir/previous.compose.json") \
  <(jq -S 'del(.services[].restart)' "$deployment_dir/compose.json")
jq -e '.services | keys == ["app","i2p","nym","tor"]' "$deployment_dir/compose.json"
jq -e '.services | all(.[]; .restart == "unless-stopped")' "$deployment_dir/compose.json"
jq -r '.services | to_entries[] | [.key,.value.image,.value.restart] | @tsv' \
  "$deployment_dir/compose.json"
```

Expected: the diff is empty and both `jq -e` checks succeed for the standard
four-service deployment. Compare each image against the actual running image
IDs and each volume's complete resolved name against the installation record.
Record custom services separately instead of silently discarding them. A stale
image tag, old Tor override or different volume mapping is a stop condition.

Check every bind source, environment file, TLS directory, updater work path and
monitor file. All paths needed after reboot must exist on persistent storage;
a copied JSON file can still refer to temporary inputs. Do not move private keys
by broadly changing permissions. TLS staging remains owned `10001:10001`,
directory `0750`, certificate/key `0600`; use the existing certificate procedure.
Retain source, image, configuration and state records together privately.

## Add the existing manager status displays

The [Java monitor](java-monitor.md) must already publish the two sanitized files
on persistent storage. Do not create a fake successful snapshot or mount its
private recorder, ledger, dispatcher, profile, or Docker socket into the app.
Select explicit freshness limits reflecting the daily schedule. For example,
129600 seconds permits 36 hours; it is an operator choice, not a missed-run alarm.

```sh
export STARGATE_RELEASE_SNAPSHOT_FILE=/absolute/persistent/public/snapshot.json
export STARGATE_CONSUMER_SNAPSHOT_FILE=/absolute/persistent/public/consumer-snapshot.json
export STARGATE_RELEASE_MAX_AGE_SECONDS=129600
export STARGATE_CONSUMER_MAX_AGE_SECONDS=129600
test -f "$STARGATE_RELEASE_SNAPSHOT_FILE"
test ! -L "$STARGATE_RELEASE_SNAPSHOT_FILE"
test -f "$STARGATE_CONSUMER_SNAPSHOT_FILE"
test ! -L "$STARGATE_CONSUMER_SNAPSHOT_FILE"
docker compose --project-name "$stargate_project" \
  --file "$deployment_dir/compose.json" \
  --file compose.release-monitor.yaml --file compose.consumer-monitor.yaml \
  config --format json > "$deployment_dir/with-monitor.compose.json"
chmod 0600 "$deployment_dir/with-monitor.compose.json"
docker compose --project-name "$stargate_project" \
  --file "$deployment_dir/with-monitor.compose.json" config --quiet
```

Review that only the two intended read-only file mounts and freshness settings
were added. `bind.create_host_path: false` must remain present. The manager shows
published collection/consumer outcomes and age, not advisory details or an
assurance of phone delivery. Missing, malformed, stale or locked observations
remain unknown. Keep the files' inodes when publishing updates, as the Java
monitor does; replacing an inode needs a deliberate app recreation to rebind it.

## Deliberate activation and later restart

Do this only in the reviewed maintenance window. Use the chosen final file,
including monitoring/updater settings if selected, and the original project.
The following command can recreate containers and interrupt users; it must not
build images or delete state:

```sh
final_config="$deployment_dir/with-monitor.compose.json"
docker compose --project-name "$stargate_project" --file "$final_config" \
  up --detach --no-build
docker compose --project-name "$stargate_project" --file "$final_config" ps
```

For a candidate without monitor mounts, select its reviewed `compose.json`
instead. Never run `down -v`, prune or remove old images/volumes as preparation.
After a signed upgrade, keep its `work/active.compose.json` override in every
subsequent command as described in [the upgrade guide](verified-upgrades.md).

Check every selected container's image, mounts, publications and restart policy,
then log into the manager with the retained token and test all enabled routes in
the actual paired browsers. Retain the exact IDs and observations. Container
health is not destination access. Native ports must remain private; plaintext
manager/proxy host ports remain on loopback.

Docker must start after host boot. Inspect before changing system services:

```sh
systemctl is-enabled docker.service
systemctl is-active docker.service
systemctl --user list-timers --all stargate-daily-alert-consumer.timer
sudo systemctl list-timers --all stargate-tls-renewal.timer
loginctl show-user "$USER" -p Linger
```

If Docker is not enabled, a host administrator can deliberately run
`sudo systemctl enable --now docker.service`; do not restart an already running
daemon as routine setup. Operator user timers/services need lingering for
operation after logout: `sudo loginctl enable-linger "$USER"`, then recheck.
Use an explicit qualified Java executable in rendered user units; the root TLS
job must use a root-controlled JDK accessible under its sandbox. The prerequisite
wizard does not grant these system privileges or install these services.

`unless-stopped` does not restart a container deliberately left stopped.
Bring the reviewed stack up when resuming it. Docker starting the app and the
supervisor starting forwarding are separate: a fresh installation forwards
only after Manager **Start**; the saved requested running/stopped state survives
app replacement. Manager **Stop** keeps the manager available and saves stopped
forwarding. Manager **Restart** interrupts proxy connections. Restarting a
container does not add new mounts/settings or undo a saved forwarding stop.

At an agreed real reboot, use the same configuration/project to inspect startup,
log in again and test Tor/I2P/Nym. Web sessions end on manager restart; saved
pairing and router identities should remain. An isolated container restart proves
less than a host reboot; check actual recovery before relying on automatic startup.
On failure, inspect the exact service/container and retained state. Do not erase
markers, reset grants or swap to repository default volumes to force startup.

Once the installation's startup setup is complete, routine reboots need no manual
container-start, TLS-sync or permission-inspection command. The configured
services and timers handle startup and certificate synchronization. Permission
inspection is a setup/diagnostic check, not a command to repeat after every reboot.
If a service fails to
recover, inspect that failure before attempting recovery; automatic startup does
not guarantee current destination access.
