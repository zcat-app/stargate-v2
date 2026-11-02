# Capture stopped Docker volumes into an encrypted archive

`tools/offline_volume_capture_docker.sh` reads an explicitly selected matching
five-volume set, or seven-volume set with Nym, through one new isolated helper.
It creates a new age-encrypted archive using the existing
[archive codec, encryption and full-decryption verification](offline-encrypted-archives.md).
The helper mounts every source volume read-only with `volume-nocopy`. The command
does not stop source containers, create/remove volumes, alter source permissions
or ownership, prepare credentials, restore data, or start product services.

Before running it, stop and flush every app/supervisor, proxy, manager, Tor, I2P
and optional Nym writer. Keep them stopped, prevent host writers and competing
Docker clients, and independently establish that the selected volumes are a
complete matching set. The required acknowledgements record the operator's
responsibility; they do not establish application-level coherence, native state
compatibility, provenance, identity continuity or recoverability. Docker attachment
inspection cannot discover every host writer or bind-mount alias. A competing
Docker administrator or mount change can defeat before/after checks.

Use the exclusive rootful local daemon at `unix:///var/run/docker.sock`.
Rootless daemons are rejected. The helper explicitly uses the host user namespace
so numeric source ownership is not silently remapped during capture. Select a reviewed,
locally available immutable helper image ID in `sha256:...` form. It must provide
Java 25 at `/opt/java/bin/java`, its required Linux runtime libraries, and declare
no image volumes. No helper image is bundled or certified. The helper must support
the bind and volume mount paths used by the tool.
The command never pulls images. Review the helper image and these tools before
use; a matching image ID alone is not provenance. The unprivileged host account
must already have authorized daemon access. Do not run this repository command
with sudo or grant additional source permissions.

## Explicit source selection

Create an owner-only mode-0600 JSON selection file outside the sources. It must
contain exactly `version`, `volumes` and `containers`; duplicate JSON keys are
rejected. `volumes` maps each role to its exact existing local volume name.
`containers` lists the full 64-character lowercase Docker IDs of every container
currently attached to those volumes, including stopped read-only consumers.
Use at most sixteen distinct IDs. Listed containers must actually attach to the
set, remain in `created` or `exited` state and have no running, paused, restarting
or dead state. An unattached volume is permitted only under the same operator
matching-set and offline attestations; an unused listed container is rejected.

A seven-volume template follows; replace every example value with the reviewed
selection. The container-ID placeholders deliberately require replacement.

```json
{
  "version": 1,
  "volumes": {
    "app-data": "existing_project_app-data",
    "tor-data": "existing_project_tor-data",
    "tor-control": "existing_project_tor-control",
    "i2p-data": "existing_project_i2p-data",
    "i2p-control": "existing_project_i2p-control",
    "nym-data": "existing_project_nym-data",
    "nym-secrets": "existing_project_nym-secrets"
  },
  "containers": [
    "REPLACE_WITH_FULL_STOPPED_APP_CONTAINER_ID",
    "REPLACE_WITH_FULL_STOPPED_TOR_CONTAINER_ID",
    "REPLACE_WITH_FULL_STOPPED_I2P_CONTAINER_ID",
    "REPLACE_WITH_FULL_STOPPED_NYM_CONTAINER_ID"
  ]
}
```

Use `--nym` with both Nym roles. For five-volume capture, omit both Nym mappings,
the Nym container ID when it no longer attaches to the selected set, and `--nym`.
A five-volume capture cannot establish that Nym was unused. Only standard `local`
volumes with local scope and no driver options are supported; remote/plugin
volumes and nested source filesystems are rejected.

## Capture and verify

Prepare separate caller-owned mode-0700 output and journal directories on private
local storage with sufficient space for bounded temporary plaintext, ciphertext
and verification files. Paths must be absolute, normalized and free of symlink
components; output and journal paths cannot contain commas or newlines. The
output name must not exist. Keep the native age identity outside the output/work
directory and selected source volume paths. Follow the existing archive document
for the independently reviewed age binary, its trusted SHA-256, native X25519
recipient/identity and protected independent key copy.

```sh
tools/offline_volume_capture_docker.sh \
  --source-config /absolute/private-selection.json \
  --output /absolute/private-archives/new-capture.age \
  --journal-dir /absolute/private-journals \
  --helper-image sha256:REPLACE_WITH_REVIEWED_LOCAL_IMAGE_ID \
  --age /absolute/operator-reviewed/age \
  --age-sha256 REPLACE_WITH_TRUSTED_BINARY_SHA256 \
  --identity /absolute/separate-private-key/identity.txt \
  --recipient REPLACE_WITH_MATCHING_NATIVE_AGE_RECIPIENT \
  --nym --ack-writers-stopped --ack-matching-set \
  --ack-exclusive-local-daemon --ack-reviewed-helper-image
```

The helper runs as `0:0` with all capabilities dropped except `DAC_OVERRIDE`,
which permits reading private mixed-UID source files without changing them and
writing one newly created mode-0600 plaintext archive. Every source volume is
read-only. Its only writable host bind is that fresh file inside the caller's
new mode-0700 working directory; it receives no Docker socket, host PID namespace,
network, source host directory bind or age identity. The root filesystem is
read-only. Limits are 512 MiB of memory with equal memory/swap ceilings, two CPUs,
128 processes, no core dumps, an 8 GiB file-size limit and a 30-minute helper-call
timeout. The private copied helper JARs and all mounts/limits are checked
before starting it.

The helper inventories sources without following links, uses the existing bounded
USTAR packer twice, compares both archives and the before/after metadata inventory,
and syncs the capture file. Source volume name, creation metadata, mountpoint,
driver, options and labels are checked before/after, as are stopped-container
identities/states and named-volume attachments. Docker volume names have no
immutable UUID: matching inspected fields cannot prove that no replacement or
daemon restart occurred. The exclusive-daemon/offline assumptions remain required.

After the new helper has exited and been removed by its verified ID, the host
validates the complete archive, encrypts it using the existing pinned age runner,
fully decrypts it, compares the plaintext digest and validates it again. Sources
are rechecked before exclusive publication of the new mode-0600 ciphertext file.
Only exit status zero and `OFFLINE_DOCKER_CAPTURE_ENCRYPTED_VERIFIED` indicate
completed capture/verification. The current `offline_backup.sh verify` command
can authenticate and validate this format without extraction; use its existing
syntax and the same independently reviewed age inputs.

## Metadata and failure boundaries

Volume roots and contents keep their numeric UID/GID, ordinary mode bits and
whole-second modification times in the archive, including root-owned and Nym
entries. The tool never silently changes volume-root metadata to fit staging.
It preserves neither access/subsecond times nor ACLs, xattrs, capabilities,
sparse layout or hard-link relationships. The current codec allows only regular
single-link files and directories: at most 100,000 entries, 8 GiB of archive,
2 GiB per file, 32 components and 255 UTF-8 path bytes. Symlinks, special files,
repeated inodes, set-ID/sticky modes and unrepresentable metadata fail capture.

Preserved mixed ownership or root modes may be unsupported by the current
unprivileged `offline_backup.sh stage` and directory importer. Successful capture
and `verify` do not promise that those tools can stage this particular metadata,
or establish a complete restoration procedure. Do not normalize source ownership
or permissions to make capture pass. Credential reset, I2P history decisions,
identity preparation, matching Nym compatibility and activation remain separate.

On failure, keep all source writers offline and inspect the private journal.
Cleanup stops/removes only the newly created helper whose full ID and complete
requested isolation can still be verified. It never searches for a cleanup target
by name or operates on source container IDs. If creation returned no reliable ID,
or isolation/removal is uncertain, the helper outcome and private working files
are retained for operator inspection; no output is confirmed. Do not reuse partial
working state or remove journal evidence to retry. Ordinary successful cleanup
removes only fresh fixed working files. Storage failures, SIGKILL or host loss can
leave partial private plaintext or uncertain output durability; no secure erasure
or cross-volume atomic snapshot is claimed.

Build the Java adapters and run their synthetic checks using
[the adapter guide](../backup-docker-tools/README.md). Those checks use fake
Docker responses and optional pinned native age binaries with synthetic keys.
Five-volume capture, real mixed-UID capture and production recovery are not
qualified by this guide; do not infer compatibility for another daemon or helper
image from a successful synthetic test.
