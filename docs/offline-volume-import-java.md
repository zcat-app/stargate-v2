# Offline staged volume import with Java

The Java `VolumeImport` command copies an operator-prepared, stopped staged set
into an isolated set of empty, private volume roots. It does not stop services,
call Docker, create volumes, prepare restored credentials, start services, or
establish that the source represents matching and consistent snapshots. Keep
all source and destination copies offline and prevent concurrent access for
the entire operation. Follow the trust and recovery guidance in
[Offline volume import](offline-volume-import.md).

Linux with glibc, Java 25, local storage supporting file and directory `fsync`,
and an unprivileged caller with matching real/effective UID and GID are required.
The source and destination parents and all volume roots must belong to that UID
and GID and have mode `0700`. They must be separate absolute normalized paths;
no path component may be a symlink. Destination roots must be distinct, empty,
and disjoint from the source. Each set must contain exactly `app-data`,
`tor-data`, `tor-control`, `i2p-data`, and `i2p-control`, plus both `nym-data`
and `nym-secrets` when `--nym` is supplied. This command does not remap owners.

After building the standalone module, substitute already prepared paths:

```sh
bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml package
bash tools/with-toolchain.sh java --enable-native-access=ALL-UNNAMED \
  -cp backup-tools/target/stargate-backup-tools-0.1.0-SNAPSHOT.jar \
  app.zcat.stargate.backup.VolumeImport \
  --source /absolute/private-staged-set \
  --destination /absolute/private-empty-volume-roots
```

Add `--nym` only when both matching Nym roots are included. Only exit status 0
with `OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED` confirms completion.
The destination remains offline with `app-data/recovery-incomplete` present;
complete the separate credential recovery procedure before any further use.
Identity recovery transaction markers are retained.

Before copying any data, the importer creates and syncs
`app-data/volume-import-incomplete`, then creates and syncs the credential
recovery marker. Source entries are inspected and opened relative to held
no-follow descriptors. Symlinks, hard links, special files, nested filesystems,
unsupported ownership and modes, repeated inodes, an existing import-incomplete
marker, and changes detected during the operation are rejected. The limits are
100,000 entries, 8 GiB total file data, 2 GiB per file, 32 path components and
255 UTF-8 path bytes. File bytes are hashed during copying and after reading
back; ownership, modes, whole-second modification times, inventory and source
metadata are checked. Only after the full set has been verified and synced is
the import-incomplete marker removed and the app directory synced. If that last
step fails, the importer attempts to restore the marker.

On any failure or interruption, keep all copies offline and discard and recreate
the **entire** destination set before retrying. Do not remove either marker to
bypass recovery. A crash, power loss or storage error can leave an incomplete
set; the markers depend on storage honoring sync operations and on software
honoring the gates. This operation is not a power-loss or storage-failure
certification. The module is in the root build. The separate Java/Bash Docker adapters
provide the [staged Docker command](offline-volume-import-docker.md); this core
command itself still makes no Docker calls.

Synthetic tests run with `bash tools/with-toolchain.sh mvn -o -f backup-tools/pom.xml test` when Maven
dependencies are cached. They use temporary roots and include injected failure,
mutation, gate-restoration, ownership/mode and link cases; they do not exercise
real volumes or start services.
