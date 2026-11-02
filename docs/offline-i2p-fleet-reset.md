# Offline I2P control fleet reset (Compose only)

Use this procedure on the matching **staged** Compose volumes after offline
credential recovery and before the first recovered Compose startup or pairing.
A stopped or crashed proxy can leave device tunnels in `tunnels.conf`; i2pd can
read that old fleet on startup. This operation replaces that one file with an
empty private file. It does not change keys, router data, credentials, saved app
ports or the I2P port counter. It does not establish identity authorization,
port history, or router readiness.

Keep the original installation and **every copy of its identities offline**.
Stop all staged services, separately stop i2pd and any other writer, disable
automatic restarts, and retain exclusive control of the volumes throughout. The
supervisor gate cannot stop an already running or independently started i2pd.
These are operator attestations; the command cannot verify them. Do not perform
this operation against live volumes. Direct-JVM and systemd deployments are
unsupported because this protocol relies on the updated Compose supervisor.

1. Securely stage the complete matching volume set and run
   [offline credential recovery](offline-staged-recovery.md) to completion,
   including the independently attested port-history option only if warranted.
   Stop and resolve any incomplete recovery first.
2. While every copy and service remains stopped, run the fleet reset below and
   require exit status zero and `I2P_FLEET_RESET`. An error, interruption, or
   missing success message means the installation must remain offline.
3. Only after success, follow the separately planned recovered Compose startup
   and pairing process using updated matching images. Forwarding remains stopped
   until explicitly started. If reassociating an old identity, first allocate
   the freshly paired device's valid unique port, stop all services again, and
   follow [offline identity reassociation](offline-i2p-identity-reassociation.md).
   Keep all other identity copies offline throughout.

The staged app and I2P control roots must be distinct absolute normalized paths,
without symlink components, owned by the invoking unprivileged UID and GID with
mode `0700`. The app's `proxy.properties` and `proxy-desired` must be private
single-link regular `0600` files with the same owner; `proxy-desired` must contain
exactly `stopped` and a newline. `tunnels.conf`, if present, must also be a
private single-link regular file owned by that UID and GID, at most 131072 bytes.
Other recovery gates must be absent. Linux procfs, POSIX ownership and modes,
atomic rename and durable directory sync are required. Exclusive access is
mandatory; file checks do not protect against concurrent writers.

Build an updated jar with Java 25 and cached Maven dependencies, then run it
against the staged directories:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy package
java -cp proxy/target/stargate-proxy-0.1.0-SNAPSHOT.jar \
  app.zcat.stargate.proxy.OfflineI2pFleetReset \
  --staged-app "$STAGED_APP_DATA" --staged-i2p-control "$STAGED_I2P_CONTROL" \
  --ack-all-copies-and-services-offline
```

For Docker named volumes, first inspect the exact existing staged volume names
and labels under exclusive control of the local daemon. A mistyped volume name
can silently create a new empty volume. Confirm no helper or service is running
and no writer can start. With volumes owned by `10001:10001`, run a trusted
updated image containing this command and the identity startup gate:

```sh
docker run --rm --pull=never --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:mode=1777 \
  --entrypoint /opt/java/bin/java \
  --mount "type=volume,src=$STAGED_APP_VOLUME,dst=/run/staged-app,volume-nocopy" \
  --mount "type=volume,src=$STAGED_I2P_CONTROL_VOLUME,dst=/run/staged-i2p-control,volume-nocopy" \
  stargate-v2-app:local -XX:-UsePerfData -cp /app/proxy.jar \
  app.zcat.stargate.proxy.OfflineI2pFleetReset \
  --staged-app /run/staged-app --staged-i2p-control /run/staged-i2p-control \
  --ack-all-copies-and-services-offline
```

This standalone helper starts no service and has no network. Do not use Compose
`run`, which may start dependencies. Use the updated matching app and I2P images
for any eventual activation; an older supervisor does not enforce this gate.

The reset uses the existing supervisor-gated `identity-recovery-incomplete`
name with the distinct `I2P-FLEET-RESET-1` record. Ordinary credential recovery
rejects the name and identity reassociation rejects the different record; neither
can clear a fleet-reset gate. The command writes and syncs the gate and its app
directory before atomically replacing the fleet with a synced empty file, then
syncs and verifies the control directory and removes and syncs the gate last.
A crash can leave a private `.fleet-reset-*.tmp` file in the control directory;
it is not the active fleet and is not adopted by a retry.

After any nonzero exit or interruption, keep **all copies and i2pd offline**,
even if no gate is visible. With a complete matching gate, correct the cause and
rerun the same command on the same volumes. A partial, malformed, or foreign gate
is not automatically adopted or removed: retain the staged state for offline
inspection, or securely restage the complete matching snapshots and repeat
credential preparation and the reset. Do not remove a gate to force startup. If
the final gate deletion cannot be synced, the command attempts to restore it;
persistent storage failure can prevent repair, so absence of a gate after failure
is not proof of completion. This is not a hardware or power-loss certification.
