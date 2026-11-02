# Offline I2P device identity reassociation (Compose only)

This command associates one existing I2P device key with a **freshly paired**
device in a stopped staged installation. It does not restore old device
credentials, regenerate a key, change `i2p.nextPort`, start a service, or recover
historical port allocations. Pairing and port allocation must already have been
completed by the normal manager. Identity selection and authorization are the
operator's responsibility: an old key is not evidence that its previous owner
is still authorized.

Follow [offline staged recovery](offline-staged-recovery.md) first, including
credential discard and the [offline I2P fleet reset](offline-i2p-fleet-reset.md)
before the first recovered startup. The default exhausted counter prevents a fresh isolated
port from being allocated. Proceed only when a complete allocation history was
independently established and used with that command's explicit history
attestation, or a new device has already received a valid unique isolated port.
Do not guess or recycle a port. Pair the new device and allocate its port, then
stop forwarding and stop **every** staged service and writer. Keep the original
installation and every other copy of its identities offline throughout pairing,
this operation, and subsequent activation. The command cannot verify that all
copies are stopped, that the chosen identity remains authorized, or that the
device was freshly paired; the two acknowledgement flags are operator
attestations of these conditions.

Use a private staged matching Compose volume set. The app-data, I2P data and
I2P control roots must be distinct, absolute normalized directories owned by
the invoking unprivileged UID and GID with mode `0700`. `proxy.properties` and
`proxy-desired` must be regular single-link `0600` files owned by that UID and
GID; `proxy-desired` must contain exactly `stopped` followed by a newline.
The old device ID must no longer be an active profile. The new ID must be a
valid active profile with a unique allocated port below the unchanged next-port
counter; a profile disabled for I2P is accepted if it already has such a port.
Orphaned saved ports also must be valid and unique. The target key
filename must be absent before a new transaction. Symbolic links in supplied
paths, hard-linked files outside a matching interrupted transaction, unsafe
modes or ownership, malformed keys and duplicate device destinations are
rejected. Only the managed `device-<sha256-of-device-id>.dat` files directly
in the I2P data root are inspected for duplicate destinations. The scan streams the directory and accepts at most 100,000 managed keys, matching
the existing archive entry limit; each must have valid supported signing
material. Large sets can take significant offline processing time. Copies or aliases
elsewhere require independent operator control.

The staged I2P control `tunnels.conf` must be absent, an empty regular `0600`
single-link file, or exactly the generation-only fleet published by the lifecycle
when no devices are active. It must have the same UID/GID as the invoking user.
Any device section, key, port, other content, symlink, or unsafe file is rejected.
The check is repeated before completion. Stop all services and use the offline
fleet reset if needed; do not edit a live control volume. This identity command
does not clear the fleet.

Provide the independently trusted expected destination in a separate private,
caller-owned `0600` single-link file. It must contain exactly the lowercase
52-character base32 destination followed by `.b32.i2p`, optionally followed by
one newline. The value must come from an independently trusted record, not from
the candidate key being selected. Keep the file and the device IDs private.
The command does not print the destination, device IDs, key contents or
credentials. Command arguments can still be visible in process listings and shell
history; use a private administrative environment.

Build the updated jar with Java 25 and Maven, then invoke the command with the
values obtained privately by the operator:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy package
java -cp proxy/target/stargate-proxy-0.1.0-SNAPSHOT.jar \
  app.zcat.stargate.proxy.OfflineI2pIdentityRecovery \
  --staged-app "$STAGED_APP_DATA" \
  --staged-i2p-data "$STAGED_I2P_DATA" \
  --staged-i2p-control "$STAGED_I2P_CONTROL" \
  --old-device "$OLD_DEVICE_ID" --new-device "$NEW_DEVICE_ID" \
  --expected-b32-file "$PRIVATE_EXPECTED_B32_FILE" \
  --ack-authorized-fresh-pair --ack-all-copies-and-services-offline
```

For staged Docker named volumes owned by UID/GID `10001:10001`, use a
**trusted updated image** built from this version; older images lack both this
command and the identity startup gate. Under exclusive control of the local
Docker daemon, inspect the exact volume names and labels and confirm they are
the intended existing staged volumes. Confirm every helper and original service
is stopped and no other writer can start. Docker may silently create a new empty
volume if a name is mistyped, so do not rely on this command to establish volume
identity. Set the variables to those inspected names and to the private expected
file, which must itself be readable and owned by `10001:10001` with mode `0600`.
Use the same privately supplied device ID variables as above:

```sh
docker run --rm --pull=never --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:mode=1777 --entrypoint /opt/java/bin/java \
  --mount "type=volume,src=$STAGED_APP_VOLUME,dst=/run/staged-app,volume-nocopy" \
  --mount "type=volume,src=$STAGED_I2P_DATA_VOLUME,dst=/run/staged-i2p-data,volume-nocopy" \
  --mount "type=volume,src=$STAGED_I2P_CONTROL_VOLUME,dst=/run/staged-i2p-control,volume-nocopy" \
  --mount "type=bind,src=$PRIVATE_EXPECTED_B32_FILE,dst=/run/expected-b32,readonly" \
  stargate-v2-app:local -XX:-UsePerfData -cp /app/proxy.jar \
  app.zcat.stargate.proxy.OfflineI2pIdentityRecovery \
  --staged-app /run/staged-app --staged-i2p-data /run/staged-i2p-data \
  --staged-i2p-control /run/staged-i2p-control \
  --old-device "$OLD_DEVICE_ID" --new-device "$NEW_DEVICE_ID" \
  --expected-b32-file /run/expected-b32 \
  --ack-authorized-fresh-pair --ack-all-copies-and-services-offline
```

This standalone container uses an explicit Java entrypoint and starts no service.
Direct-JVM and systemd deployments are unsupported because they lack the
Compose supervisor gate. Linux with procfs, POSIX ownership and permissions,
file link counts, same-filesystem hard links and durable directory sync is
required. Filesystems that cannot provide these operations are unsupported.
The utility cannot prevent a concurrent writer; offline operation and exclusive
access are mandatory.

Only native default i2pd destination files with exactly 679 bytes, Ed25519 type 7
and crypto type 0 are accepted; this also applies to other managed device files
inspected for duplicates. Offline-signature, nondefault, legacy compatibility and
extended formats are rejected. The command hashes the full public destination,
compares it to the independently supplied value, and signs and verifies a fixed
domain-separated challenge using Java Ed25519. This checks signing-key
consistency. Native i2pd creates destination encryption fields as random padding,
so this check does not prove an encryption key pair or native router readiness.

Private `identity-recovery-preparing` and `identity-recovery-incomplete` files
are both startup gates: the supervisor refuses initialization and ordinary
offline credential recovery refuses to run while either exists, including when
one is a dangling symlink. The complete private plan binds the old and new
derived filenames and full key digest. Before changing the key directory, the
command writes and syncs that plan in the preparing file, publishes the final
marker with a no-overwrite hard link, syncs the app directory, and then removes
the preparing name and syncs again. It publishes the target key with another
no-overwrite hard link, syncs and verifies it, retires the old name, syncs again,
and removes the final marker only after verification. Intermediate hard links
are intentional and accepted only for the exact plan-bound file pairs.

An interrupted initial preparing write can be retried when the original key
still exists, the target does not exist, and the private single-link preparing
file contains exactly a prefix of the supplied plan. A partial record verifies
only its recorded prefix; it cannot identify plan fields that were never written.
No key mutation has started at this point. The command removes and syncs that
verified temporary file before writing the complete supplied plan again. If the
final marker and preparing name both exist, they must be the same private
two-link file with the complete matching plan. Unrelated or unsafe files are
never removed. The archive and volume-copy tools reject hard-linked files, and
ordinary credential recovery refuses both gates, so resume in the original
staging directories rather than copying an interrupted transaction.

Treat only exit status zero and `I2P_IDENTITY_REASSOCIATED` as success. Any error
or interruption means keep **all copies offline**, including when no marker is
visible. After correcting the cause, rerun the exact same command with the same
inputs against the same staged directories. The command refuses an unrelated
target, and a complete published marker must match the supplied plan. A malformed or ambiguous marker is not automatically
repaired; retain the complete staged state for offline inspection. A preparing
file left while only the target key exists is ambiguous and is not adopted; it
requires offline inspection. If the staged transaction cannot be resolved,
securely restage the complete matching snapshots and repeat credential recovery,
fleet reset and pairing before attempting reassociation again. Do not remove
either gate to force startup. If the final marker-directory sync fails, the utility
tries to recreate the marker, but persistent storage failure may prevent that
repair; consequently an absent marker after a nonzero exit is not proof of
completion. This is not a certification of hardware or power-loss behavior.
No service is started by this procedure.

## Scope

Key reassociation does not prove native router readiness, public-network access
or a full backup restore. Independently trusted identity and complete port
history, current authorization and exclusive offline access remain required.
