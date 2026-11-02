# Offline import into fresh local Docker volumes

`tools/offline_volume_import_docker.sh` creates a new labeled five-volume set
(or seven with `--nym`) and copies a stopped, already staged set into it. It
runs no product service, recovery command, or activation. The new app-data
contains the recovery gate and requires the existing
[OfflineRecovery procedure](offline-staged-recovery.md) before any later use.
A successful copy does not establish matching state, compatibility, identity
continuity, or readiness to expose an installation.

**Exclusive control of the local Docker daemon is required throughout the
operation.** Stop the original installation and every writer, prevent all other
Docker clients and automation from creating, removing, attaching or modifying
resources, and keep both source and target sets offline. Docker has no atomic
exclusive named-volume creation; listings, unpredictable names and labels do
not defend against a competing daemon client. The acknowledgement flag records
that the operator accepts this precondition; the tool cannot enforce it. Use
only the daemon reached at `unix:///var/run/docker.sock` on this same Linux
host. Docker Desktop, remote daemons, user namespace remapping, rootless Docker,
and non-local volume drivers are not established by this procedure. Docker
administrators and the helper image are trusted; a compromised daemon or helper
can access or change mounted state. Maintain source isolation and prevent
concurrent filesystem writers or mount changes throughout.

No Java helper image is bundled or certified. Before use the operator must
independently obtain and assess a **local immutable image ID** (`sha256:` plus
64 lowercase hex digits), including provenance, current security advisories,
Java and OS dependencies and update policy. The helper must supply executable
Java 25 at `/opt/java/bin/java`, its required Linux runtime libraries, and
support the required mount paths and Linux filesystem operations. Do not infer
safety from a tag, digest, or this document; known image/dependency advisories
must be assessed separately. The wrapper never pulls an image. Its initializer
runs that trusted image as UID 0 with only `CAP_CHOWN`, and the copier runs it as
UID/GID `10001:10001` with all capabilities dropped; both have network disabled,
read-only root filesystem, no-new-privileges and no Docker socket. Seven-volume
direct import and production recovery are not qualified by this procedure.
Build the tools using the
[adapter guide](../backup-docker-tools/README.md).

The source must be an operator-prepared, complete matching staged set at an
absolute normalized host path without symlinks, owned by host UID/GID
`10001:10001`, mode `0700`. Its content and all per-root restrictions are
explained in [offline volume import](offline-volume-import.md). The Docker daemon
must be able to bind that same local path. Provision private durable plaintext
staging and sufficient disk space; staging authenticity, Nym selection, source
consistency, identity continuity and I2P port history are operator obligations.
The journal directory must already exist, be mode `0700`, and belong to the
unprivileged invoking user and group. Source and journal paths must be disjoint.
Do not use a repository script with sudo. The caller also needs a trusted local
Docker CLI and permission to use the daemon; no remote API or socket is mounted
into either helper.

```sh
tools/offline_volume_import_docker.sh \
  --source /absolute/private-staged-set \
  --journal-dir /absolute/private-journals \
  --helper-image sha256:REPLACE_WITH_FULL_VERIFIED_LOCAL_IMAGE_ID \
  --ack-exclusive-local-daemon
```

Use `--nym` for both matching Nym volumes. The tool writes and syncs a private
journal containing all planned names before issuing volume or container
mutations. It checks daemon listings for name collisions, verifies volume
labels, local driver and options, checks container attachments, and inspects
helper configuration before starting it. It uses `volume-nocopy` to avoid
populating targets from the image. The initializer checks every target root is
empty before setting `10001:10001` ownership and mode `0700`. The copier mounts
the source read-only, the new target volumes under a private temporary parent,
and private snapshots of the helper JARs read-only; it verifies the copied data
and leaves its fresh recovery gate. Successful output identifies the private journal containing
the role-to-volume mapping. Both stopped helper containers remain, identifiable
by the journal. When using the Compose handoff below, retain both until the
handoff and its immediate pre-activation recheck have succeeded; both checks
also require the retained helper JAR snapshots. Afterward, the operator may remove
the helpers after verifying their exact IDs. The wrapper does not remove any resources.

Use the updated copier and app image together. The copier syncs a separate
`app-data/volume-import-incomplete` before any copied content and removes it only
after the complete import is verified and synced. The updated supervisor and
credential, fleet and identity recovery tools refuse that marker. Credential
preparation cannot repair or clear a failed import; discard the entire failed
volume set. Older failed imports can lack this marker and must also be discarded.

Treat only exit status zero and `OFFLINE_DOCKER_IMPORT_CREATED_RECOVERY_REQUIRED`
as success. The journal contains planned names even on failure; names alone do
not prove creation or ownership. On any failure, timeout, interruption, daemon
ambiguity, or uncertain journal sync, keep all sets offline and independently
inspect the private journal, exact resource identities, labels, containers and
attachments before any manual action. A Docker client timeout, error, or
interruption can leave a helper container running; inspect it and stop it offline
before attempting any cleanup. Do not retry into any possibly touched volumes; discard/recreate the
whole destination set only after independent inspection. There is no automatic
rollback or deletion, cross-volume atomicity, secure erasure, or guarantee after
SIGKILL, host loss or storage failure. Journal writes or even its creation may be
uncertain after storage failures; inspect the journal directory and Docker daemon.

## Prepare the imported app-data volume

Keep the original installation, imported volumes and all services offline under
the same exclusive-daemon precondition. Select the **app-data** volume name and
both helper container IDs from the successful private journal. Before proceeding,
inspect the exact existing volume and both exact containers using the same local
daemon. Do not use the mount command below if any inspection fails or its output
is ambiguous: Docker can automatically create a missing named volume when a
container is created.

```sh
APP_VOLUME=REPLACE_WITH_APP_DATA_VOLUME_FROM_PRIVATE_JOURNAL
IMPORT_TOKEN=REPLACE_WITH_TOKEN_FROM_PRIVATE_JOURNAL
INIT_ID=REPLACE_WITH_INITIALIZER_CONTAINER_ID_FROM_PRIVATE_JOURNAL
COPY_ID=REPLACE_WITH_COPIER_CONTAINER_ID_FROM_PRIVATE_JOURNAL
APP_IMAGE_ID=sha256:REPLACE_WITH_VERIFIED_UPDATED_APP_IMAGE_ID

docker --host unix:///var/run/docker.sock volume inspect "$APP_VOLUME"
docker --host unix:///var/run/docker.sock container inspect "$INIT_ID" "$COPY_ID"
docker --host unix:///var/run/docker.sock image inspect "$APP_IMAGE_ID"
```

Confirm the volume's exact name matches the journal, its driver and scope are
`local`, it has no driver options, its `org.stargate.offline-import` label equals
`IMPORT_TOKEN`, and its `org.stargate.offline-import-role` label is `app-data`.
Confirm both container IDs match the journal, both carry that import-token label,
and both are stopped. Check that no other container is attached to this volume
and prevent any competing client from attaching, deleting or replacing it. Verify
that `APP_IMAGE_ID` is the intended locally available immutable image ID, built
from the updated version containing the recovery command and startup gate, and
that it declares no additional image volumes. Independently assess the image's
provenance and security; do not use a tag in place of the verified ID. These
checks depend on the operator's trusted daemon and do not protect against a
concurrent privileged Docker client.

Only after those checks, run the standalone command below. It mounts only the
selected imported app-data volume and explicitly bypasses the supervisor. It
cannot pull the image, starts no product service, and leaves the other volumes
unmounted and offline.

```sh
docker --host unix:///var/run/docker.sock run --rm --pull=never \
  --network none --read-only --user 10001:10001 \
  --cap-drop ALL --security-opt no-new-privileges \
  --entrypoint /opt/java/bin/java \
  --mount "type=volume,src=$APP_VOLUME,dst=/recovery,volume-nocopy" \
  "$APP_IMAGE_ID" \
  -cp /app/proxy.jar app.zcat.stargate.proxy.OfflineRecovery \
  --discard-restored-credentials --staged-config /recovery/proxy.properties
```

The command removes the gate only after its credential reset has completed and
been verified. Treat only exit status zero and `STAGED_RECOVERY_PREPARED` as
success. On any failure or interruption keep everything offline, inspect the
exact volume and rerun the same recovery command as described in
[offline staged recovery](offline-staged-recovery.md); do not manually remove the
gate. A failed final sync can leave the gate's state uncertain, so a nonzero exit
requires inspection and rerun even if the marker is absent. This prepares app-data
only; it does not activate the installation. New isolated I2P allocations remain
blocked by default. The optional attested history setting in offline staged
recovery requires the maximum numeric port ever allocated, supported by an
independently trusted record covering every allocation through
final shutdown, including revoked devices, post-snapshot allocations and branches,
and all copies offline. The command cannot verify that history. This does not
establish matching-volume compatibility, native identity continuity, or route safety.


## Handoff to Compose

After the credential recovery above succeeds, perform the
[offline I2P control fleet reset](offline-i2p-fleet-reset.md) on the matching
imported app-data and I2P control volumes while all copies remain offline.
Then follow the [isolated Compose handoff](offline-volume-compose-handoff.md)
to validate and map the journaled names before any deliberately chosen startup.
These steps do not establish identity continuity or readiness to expose services.
