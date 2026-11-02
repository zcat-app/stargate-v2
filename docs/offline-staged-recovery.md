# Offline staged recovery preparation (Compose only)

The separate [encrypted archive tool](offline-encrypted-archives.md) can pack and
verify and securely stage operator-prepared matching snapshots. This preparation
command still requires an already securely staged copy and must run successfully
after archive staging before any later use.

An older snapshot can restore credentials revoked after the snapshot. This command
unconditionally discards **every** restored device credential and its per-device
I2P settings, rotates the administrator token, and disables automatic forwarding
startup. Every device must pair again. It does not detect rollback, create or
extract backups, restore volumes, or establish that a restored installation is
ready to expose.

Use only private, separate **staged copies** of the complete matching Compose
volume set. Keep the original installation offline; never run two copies of its
identities. All app/supervisor, proxy, manager, Tor, I2P and optional Nym processes
must be stopped, with no concurrent configuration writer, for the whole operation.
The command cannot prove these preconditions. Do not point it at an existing
running installation. Direct-JVM/systemd deployments are unsupported by this
procedure because they lack the Compose supervisor startup gate.

Retain the five base volumes together (`app-data`, `tor-data`, `tor-control`,
`i2p-data`, `i2p-control`); with Nym, retain `nym-data` together with its matching
`nym-secrets`. Securely stage these before using this utility. The command
only changes files in the staged `app-data` directory. It does not inspect the
other volumes or prove their consistency, identity continuity or decryptability.

Build the updated proxy jar from the repository root with Java 25 and Maven:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy package
```

Offline Maven requires cached dependencies. With an ordinary connected build,
omit `--offline`. Set the following to the existing **staged** app-data directory,
owned by the invoking user, mode `0700`. Its `proxy.properties` and `admin-token`
must be regular files, mode `0600`, with that same owner and no hard links.
Existing `proxy-desired`, `manager.properties` and `recovery-incomplete` files must
meet the same requirements. Symlinks in the supplied path or any of these files
are rejected. The path must be absolute, normalized, and end in `proxy.properties`.

Preparation refuses any `volume-import-incomplete`, `identity-recovery-incomplete`
or `identity-recovery-preparing` entry, including a partial file or dangling link.
It cannot complete an interrupted volume import or clear its gate. For an import
failure, discard and recreate the **whole destination set** from the trusted
matching staged source; do not remove the marker or rerun credential preparation
to bypass it. Only the updated importer can remove its own gate after a completed
copy. Older failed or unconfirmed imports may have no separate marker and must
also be discarded. Use matching tools and supervisor from this version.

```sh
STAGED_APP_DATA=/absolute/private-staging/app-data
java -cp proxy/target/stargate-proxy-0.1.0-SNAPSHOT.jar \
  app.zcat.stargate.proxy.OfflineRecovery \
  --discard-restored-credentials \
  --staged-config "$STAGED_APP_DATA/proxy.properties"
```

The same class ships in `/app/proxy.jar` of the updated application image. If the
staged directory is instead owned by container UID/GID `10001:10001`, use this
standalone, network-disabled container. Its explicit entrypoint bypasses the
supervisor; it mounts only the staged app-data directory and starts no service:

```sh
STAGED_APP_DATA=/absolute/private-staging/app-data
docker run --rm --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /opt/java/bin/java \
  --mount "type=bind,src=$STAGED_APP_DATA,dst=/recovery" \
  stargate-v2-app:local \
  -cp /app/proxy.jar app.zcat.stargate.proxy.OfflineRecovery \
  --discard-restored-credentials --staged-config /recovery/proxy.properties
```

Use an image rebuilt from this version; older images do not contain the command
or incomplete-recovery startup gate. Do not use Compose `run` for this step: the
normal service mounts refer to installation volumes and can start dependencies.

The command checks file ownership and permissions, the isolation key and the
supported configuration-key schema without DNS or network access. It does not
fully validate every proxy setting. It then writes and syncs `recovery-incomplete`.
The updated supervisor refuses startup while
that marker exists, **before** initialization or opening any app listener. Next,
the utility atomically writes and syncs `proxy-desired=stopped`, rewrites
`proxy.properties` without any `profile.*` properties and with the selected I2P
counter in the same atomic replacement, replaces `admin-token`
with a cryptographically random token, and removes stale `manager.properties`.
It syncs each replacement and its parent directory. Only after verifying those
changes, including the exact selected I2P counter, does it remove and sync the
incomplete marker. No non-atomic rename
fallback is permitted. The filesystem must support atomic rename and directory
sync; I/O failures produce a nonzero exit status.

Treat only exit status `0` and `STAGED_RECOVERY_PREPARED` as completed preparation.
Any error or interruption means keep the staged installation offline. If the
`recovery-incomplete` marker exists, leave it in place and rerun the **same command** after correcting
the cause. Do not manually remove it to force startup. A rerun safely discards all
credentials again and rotates the administrator token again. A failed final
marker sync attempts to recreate the gate; persistent storage failure can prevent
that repair, so a nonzero exit always requires offline inspection/rerun even if
the marker is absent. This is a local file transaction, not a storage-failure or
power-loss certification.

Before the first recovered startup or pairing, use the
[offline I2P control fleet reset](offline-i2p-fleet-reset.md) while all services
and identity copies remain stopped. A stopped snapshot may retain device tunnels
that i2pd could otherwise read at startup.

The utility never prints either old or new secrets. On a later, separately planned
startup using the updated image, the supervisor regenerates manager configuration
from the new `admin-token`. Retrieve it privately with the usual local token tool
for that recovered installation; log in again and pair every device anew. The
rotated administrator token invalidates old bearer authentication and old signed
pairing grants when that regenerated manager starts. Manager web sessions and
pending one-time codes are process-local. Forwarding remains stopped until an
administrator explicitly starts it. Do not start services as part of this
preparation step.

Unrelated configuration values, including `isolation.key`, are preserved.
By default, the archived `i2p.nextPort` is replaced with **65536**, the exhausted
sentinel, even if I2P device isolation is disabled or absent. An archived counter
cannot reveal ports allocated after that snapshot. New isolated I2P allocations
remain blocked; re-enabling a device does not unblock them. Shared I2P and Tor/Nym
configuration are preserved, but this preparation does not establish route readiness.
When the supervisor later adds a missing isolation default, it preserves the
existing counter. Its proxy configuration rewrites use synced temporary files
and atomic rename; these checks do not certify power-loss or storage-failure behavior.
In an existing fleet, a device with a validated unique saved port can still be
stopped and enabled while new allocations are exhausted. Staged preparation
removes all restored profile mappings and does not recover one through that control.

An operator with an **independently trusted complete allocation history** may
instead explicitly attest the highest allocated port: the maximum numeric port ever
allocated, not the most recent allocation by time. The history must cover every
allocation for this installation through its final shutdown, including allocations
after the snapshot, subsequently revoked devices, branches, other copies and
manual allocations. All copies must be offline and no writer may operate during
recovery. The command cannot verify the history, its provenance, or that copies
are stopped. The command rejects a claimed highest port below one less than a valid archived
next-port counter (except 65536), or below any archived profile port, including orphaned
profile settings; malformed or out-of-range archived port values also cause the
attested operation to fail before mutation. The value 65536 is ambiguous: it can
mean natural exhaustion or a prior recovery quarantine. Independently trusted
history must resolve which applies; the command cannot infer it. If any history
is missing or uncertain, use the default quarantine; do not guess a high port. The choice does not restore identities or establish
matching-volume or native-state safety.

To use the attested history, append both options in this exact order to the same
command above, replacing the example with the independently established value:

```sh
java -cp proxy/target/stargate-proxy-0.1.0-SNAPSHOT.jar \
  app.zcat.stargate.proxy.OfflineRecovery \
  --discard-restored-credentials --staged-config "$STAGED_APP_DATA/proxy.properties" \
  --highest-allocated-i2p-port 15000 --ack-complete-i2p-port-history
```

The allowed highest-allocated value is 14446 through 65535. **14446 means no port
was ever allocated**; 65535 means the range is exhausted and remains blocked.
The command sets the next port to one above the supplied value even when I2P
device isolation is disabled or absent, so a later switch to isolation uses the
attested bound. It still performs the entire credential reset and token rotation. It rejects missing, malformed or
unacknowledged options before beginning the transaction. A rerun, even with a
different value or without these options, discards all device credentials and
rotates the administrator token again. Never run it on a live installation. After
any interruption, keep all copies offline and rerun the full preparation with the
appropriate options. This procedure cannot certify storage durability or prove
that the operator's history is complete.

For a narrowly scoped, separately attested reassociation after fresh pairing, see
[offline I2P identity reassociation](offline-i2p-identity-reassociation.md).

Properties comments, order, whitespace and duplicate key representation may
change. Retired I2P keys/router state and Tor/Nym state are untouched. Re-pairing
generates a fresh random device ID; it does not recover or deliberately reattach
an old I2P identity. Keep the original backup offline if old identities may be
needed later. This command does not reconstruct a historical high-water mark,
restore identity continuity, or establish native-state safety. Matching I2P
volume consistency still requires separate verification.
No Nym compatibility or native database/reply-store consistency is established
here.

Run the focused regression checks without services:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy \
  -Dtest=OfflineRecoveryTest,OfflineRecoveryGateTest,ProxyConfigTest,SupervisorInitializationTest test
```

Manager allocation, pairing/status and rendered controls can be checked separately:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl manager \
  -Dtest=I2pDevicesTest,PairingTest,I2pDeviceStatusTest,WebUiI2pControlsTest test
```
