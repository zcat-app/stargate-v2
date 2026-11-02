# Offline import into isolated volume roots

`bash tools/offline_volume_import.sh` copies an operator-prepared staged set into a
separate set of operator-provisioned **empty, isolated volume root directories**.
It makes no Docker calls and starts no services. It cannot determine whether a
path is a Docker volume, whether mounts are new or unused, or whether processes
are stopped. A successful copy is not activation or a complete recovery.

The operator must keep the original installation and all app, supervisor, proxy,
manager, Tor, I2P and optional Nym processes offline throughout this procedure,
and prevent any other process from writing or attaching the sources or targets.
Never import into existing installation volumes. Provision a complete new,
isolated set and verify its identities and isolation independently; paths and
inode checks cannot detect every bind-mount alias or prevent concurrent changes.
The five roots must be a complete matching snapshot; add both matching Nym roots
with `--nym` when Nym identity/state is needed. The tool cannot establish source
provenance, authenticity, cross-volume consistency, logical completeness, Nym
compatibility, I2P identity continuity or historical port high-water marks.
Nym selection is the operator's responsibility; five roots do not prove Nym was
unused. External settings and image inputs are outside this copy.

Use Linux with glibc and Java 25 as an unprivileged user with matching real and
effective UID/GID. The source and destination parent must be absolute normalized
paths without symlink components, separate from each other, owned by that
UID/GID and mode `0700`. Each must contain exactly these directory names:

```text
app-data  tor-data  tor-control  i2p-data  i2p-control
```

With `--nym`, both must additionally contain `nym-data` and `nym-secrets`. Source and destination volume roots must be owned by that UID/GID and mode
`0700`; all destination roots must be empty. Nested source directories must
be owned by that UID/GID with owner read, write and execute permissions; their
other permission bits are preserved exactly, including `0755`. Confidentiality
depends on the private volume roots and operator mount controls. Nested
directories are created `0700` while copying and receive their original mode
after their contents have been copied. Every source file must have that
same numeric UID/GID, be owner-readable, and have one link. Only ordinary files
and directories are supported; symlinks, special files, set-ID/sticky modes,
repeated inodes and nested filesystems are rejected. The tool does not change
ownership. Mounts/filesystems that assign another group are unsupported. A staged
set owned by `10001:10001` requires a matching unprivileged execution environment;
do not run a writable repository script with sudo. The target filesystem must
support exclusive creation and file/directory `fsync`. No network filesystem or
storage-failure behavior is certified.

Build the helper with `bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml package` first. Then run:

```sh
bash tools/offline_volume_import.sh \
  --source /absolute/private-staged-set \
  --destination /absolute/private-isolated-volume-parent
```

Add `--nym` for the seven-root set. The utility inspects the entire source and
all empty targets first. Its first target write creates a fresh mode-0600
`app-data/volume-import-incomplete` and syncs it and its directory. It then creates
and syncs a separate `app-data/recovery-incomplete` before copying content.
An old source `recovery-incomplete` marker is discarded; an existing source
`volume-import-incomplete` is rejected, never discarded or adopted. Identity
transaction markers are preserved. It copies exclusively using descriptor-relative
no-follow operations, checks source metadata for changes, verifies copied file
contents and final inventory, and syncs files and directories. It preserves file
permission bits, numeric ownership and file/directory modification times to whole
seconds. The new recovery marker gets a fresh timestamp. It does not preserve
access times, subsecond modification times, ACLs,
xattrs, SELinux labels, capabilities, sparse layout or hard-link relationships.
Limits are 100,000 entries, 8 GiB of total file contents, 2 GiB per file, 32 path
components and 255 UTF-8 path bytes. Same-account concurrent modification and
mount changes are outside its protection.

Only after all roots have been copied, verified, checked again against the source
and synced does the importer remove and sync `volume-import-incomplete`. A failed
final sync attempts to restore that marker; storage failure can prevent this.
The updated supervisor refuses startup while either marker exists. Credential
preparation, I2P fleet reset and identity reassociation refuse any existing
`volume-import-incomplete`, including partial files or dangling links. None can
clear it. Do not remove it manually: discard and recreate the entire failed
destination set from the original trusted matching staged set.

Treat only exit status zero and `OFFLINE_VOLUME_IMPORT_CREATED_RECOVERY_REQUIRED`
as a completed copy. Keep the remaining `recovery-incomplete` gate in place until the existing
[OfflineRecovery procedure](offline-staged-recovery.md) succeeds on the imported
`app-data/proxy.properties` while everything remains stopped. That step discards
restored credentials, rotates the admin token, and removes the gate after it
verifies its changes. The gate is honored only by the
updated Compose supervisor; it cannot prevent other software from starting.
Preparation still does not establish the installation is safe to expose.

Use the importer, recovery tools and supervisor built from this version together;
older tools do not enforce the separate import gate. Existing successfully
imported or staged sets without it retain their credential-preparation behavior.
Its absence cannot prove that a set imported with an older tool completed: discard
and recreate every older failed or unconfirmed import. This update cannot
retroactively identify those sets.

On **any failure or interruption**, keep everything offline and discard and
recreate the entire isolated destination set before retrying. The command does
not delete or roll back partial copies. Cross-volume copying and sync are not
atomic; a crash, SIGKILL, host loss, disconnected storage or failed sync can leave
partial data, an absent or incomplete gate, or uncertain durability. Inspect the
exact isolated set offline and do not reuse it. No secure erasure is promised.
Use encrypted private storage for staged credentials and dispose of copies under
local security policy.

Run synthetic tests with
`bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml test`.
For the complete five/seven-root encrypted archive and credential-recovery
chain, set the three native test variables exactly as documented in
[the archive guide](offline-encrypted-archives.md#check-the-tools).
The [Java importer reference](offline-volume-import-java.md) explains the core
command. Synthetic tests do not establish a production recovery; they do not
start production services or access real volumes.
