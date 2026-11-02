# Import an encrypted archive into fresh Docker volumes

`tools/offline_archive_import_docker.sh` authenticates an offline encrypted archive using the pinned local age executable before contacting Docker. It checks the canonical archive and requires every entry to have UID and GID 10001, all volume roots to have mode 0700, and files to be owner-readable. Other ownership and modes are not normalized. Archives containing an incomplete volume import are rejected. A five-root archive creates five destination volumes plus scratch; a seven-root archive creates seven plus scratch. Existing volumes are never imported into.

This is an offline operation. The operator must have exclusive control of the rootful local Docker daemon, trust the immutable local Java helper image and the helper JARs, and confirm that the archive represents a compatible, matching stopped state. The helper image must provide Java 25 at `/opt/java/bin/java`, its Linux runtime libraries, and the required mount paths; no helper image is bundled or certified. Five-volume imports and production recovery are not qualified by this procedure. Build the tools as described in the [adapter guide](../backup-docker-tools/README.md). The command invokes neither an image pull nor a product service. The native age executable must be independently verified and its SHA-256 supplied; the existing archive tool's native X25519 identity constraints apply. The identity never enters a helper.

Create a private, operator-owned 0700 directory separate from the archive, age binary and identity. Provide absolute normalized paths without symlinks, commas or newlines. Run as an unprivileged user with access to the local daemon:

```sh
tools/offline_archive_import_docker.sh \
  --archive /absolute/path/backup.age \
  --identity /absolute/path/identity.txt \
  --age /absolute/path/age --age-sha256 INDEPENDENTLY_VERIFIED_SHA256 \
  --private-dir /absolute/private-directory \
  --helper-image sha256:IMMUTABLE_LOCAL_IMAGE_ID \
  --ack-exclusive-local-daemon --ack-trusted-image --ack-matching-state \
  --ack-plaintext-retention
```

A successful run retains the authenticated plaintext spool, helper code snapshots, both stopped helper containers, all destination volumes and the scratch volume. On failure, resources may be absent, running, or left in an uncertain partial state; retain and inspect them. Scratch may contain staged plaintext. The helper containers retain read-only bind mounts to the spool and source snapshots. The journal identifies the private directory and records the actual resources and outcomes. This is not secure erasure. Restrict access to the host directory and daemon storage, and account for all plaintext copies when planning their eventual disposal.

The root helper has only `CHOWN` and initializes empty fresh volume roots; the staging and copy helper runs as 10001 with no capabilities. The existing staging and import APIs check the archive again, create a fresh recovery marker, sync and verify the copied tree, and keep the separate import-incomplete marker until the copy completes. A failure or ambiguous Docker outcome may leave partial resources or plaintext. Keep every copy offline, retain and inspect the journal and all planned resources; never retry into those volumes or guess at cleanup. No automatic retry, pruning, or cleanup occurs.

For a successful journal, use [the Compose handoff](offline-volume-compose-handoff.md) to generate and review the external-volume override. The archive journal has its own schema and records its actual `init` and `archive` helpers and scratch volume. Both stopped helpers, every recorded volume, the private authenticated plaintext spool and the helper JAR snapshots must remain present and unchanged for handoff checks; the handoff rehashes the spool. The scratch volume is never part of the Compose override. For the credential-preparation instructions, use the `archive` helper ID from this journal wherever the existing instructions say copier or `COPY_ID`. Before any activation, separately complete credential preparation and the I2P identity/history decisions and fleet reset described in [offline volume import](offline-volume-import-docker.md) and [offline staged recovery](offline-staged-recovery.md). This command does not activate products, establish identity continuity, or verify a complete recovery.

Build and run the synthetic checks using the [adapter guide](../backup-docker-tools/README.md). These checks do not establish recovery of real profiles or activated services.
