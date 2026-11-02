# Offline encrypted snapshot archives: pack, verify and stage

`bash tools/offline_backup.sh` creates a single age-encrypted, uncompressed USTAR
archive from an **operator-prepared, stopped, matching snapshot set**. Before
publishing it, `pack` fully decrypts it with the supplied recovery identity,
checks that the plaintext exactly matches the packed archive, and validates
the entire archive. `verify` repeats full authentication and archive validation
without extracting anything. `stage` authenticates and validates the complete
archive, then extracts it into a new, private, offline staging directory.

This command creates and stages archives; it does not provide a complete backup or
recovery workflow. It does not collect snapshots, stop services, use Docker,
read running volumes, import data into live volumes, sanitize restored credentials, start
services, or activate an installation. It cannot establish that the supplied
directories are matching, complete in application content, or consistently
flushed. A successful result means the supplied set was encrypted, decryptable
with this key, and structurally valid under the contract below.

## Prerequisites and trust

- Linux with glibc providing `statx` and `posix_spawn_file_actions_addclosefrom_np`, Java 25, a local filesystem supporting file/directory
  `fsync`, hard links and Linux `renameat2(RENAME_NOREPLACE)`, and sufficient private disk space. There is no fallback
  when these filesystem operations fail. Network filesystems and unusual
  storage semantics have not been certified.
- An explicitly selected native **age v1.3.2** executable and its expected binary
  SHA-256 obtained through independently trusted release verification/policy.
  The tool checks the opened ELF executable against that digest, executes the
  same opened descriptor, and accepts only a file owned by the invoking user or
  root, executable, without set-user-ID/set-group-ID bits, and not group/world
  writable. Before executing it, the child must successfully set Linux
  `no_new_privs`, preventing privilege gains through executable file capabilities
  or set-ID executables. The caller is responsible for
  choosing the actual supported age release: an arbitrary binary plus its own
  matching digest is not provenance. The tool never searches `PATH`, downloads,
  installs, builds, or cryptographically verifies a release proof. `--version`
  text is not accepted as provenance.
- The coordinated linux-amd64 release has binary SHA-256
  `eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c`.
  Copying this value alone is not independent release authentication. Upstream
  [Sigsum verification instructions](https://github.com/FiloSottile/age/blob/v1.3.2/SIGSUM.md)
  explain the release signing keys and policy. Release-proof verification and
  dependency assessment are separate from this product tool; neither this
  checksum check nor successful roundtrip establishes that the dependency is
  vulnerability-free. Never obtain a binary and its expected checksum solely
  from the same untrusted location.
- One native X25519 recipient and exactly one matching native X25519 identity.
  SSH keys, passphrases, plugins, and multiple identities are unsupported. The
  identity must be a regular single-link file, owned by the invoking user with
  mode `0600`, outside the snapshot, ciphertext-output and verification-working
  directories. Keep the original identity and a protected independent copy
  separately from the archive. The tool does not generate or manage keys.
- Run **unprivileged** as a user already able to read every prepared source
  directory/file. Root and set-ID execution are rejected. Source, output and
  verification-working directories must belong to that user with mode `0700`.
  Every source volume root must also belong to the caller’s effective UID/GID and have mode `0700`. No UID/GID is changed. A host account that cannot read private container
  `10001:10001` files cannot pack them using this tool; arrange an appropriate
  operator-controlled snapshot/access environment first. Do not run a writable
  repository script under `sudo`, grant broad source permissions, or add a
  Docker/privileged workaround to these commands.

All app/supervisor, proxy, manager, Tor, I2P and optional Nym writers must have
been stopped before the snapshots were prepared. Keep them stopped and prevent
concurrent writers to snapshots, keys, executables, outputs and working paths
throughout the operation. The program detects many source changes while reading;
that check does not prove a consistent snapshot or defend against another
process with the same account's access. Symlink path components are rejected.
Paths must use a single leading slash; double-slash anchors are rejected.

The source directory must contain **exactly** these five directory names:

```text
app-data/
tor-data/
tor-control/
i2p-data/
i2p-control/
```

With `--nym`, it must additionally contain **both** `nym-data/` and `nym-secrets/`.
There is no one-volume Nym mode. The tool checks directory names and file
structure, not native state compatibility, logical content completeness, or
whether these snapshots actually belong to the same installation.

**Nym selection is an operator declaration.** The tool does not parse
`app-data/proxy.properties` to cross-check `nym.enabled`, inspect the original
Compose/environment configuration, or discover omitted volumes. If five roots
from a Nym-enabled installation are supplied without `--nym`, `pack` and
`verify` can succeed even though that installation's Nym state was omitted.
For any snapshot whose Nym identity/state must be retained, explicitly choose
`--nym` and supply both matching Nym roots, even if Nym is temporarily disabled.
A successful five-root archive check does not prove that Nym was unused.

## Commands

Build the Java helper first with `bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml package` (requires cached Maven dependencies). Use the [prerequisite wizard](setup-prerequisites.md) if the selected Java/toolchain is missing.

Use separate private locations for sources, ciphertext output, verification
scratch space and the recovery key. The following paths are placeholders for
already prepared offline copies and a separately provisioned key/executable:

```sh
umask 077
AGE_BINARY=/absolute/verified-age-v1.3.2/age
AGE_BINARY_SHA256=eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c
BACKUP_IDENTITY=/absolute/private-keys/stargate.agekey
BACKUP_RECIPIENT=age1_REPLACE_WITH_THE_MATCHING_NATIVE_RECIPIENT
SNAPSHOT_SET=/absolute/stopped-snapshots
ARCHIVE_OUTPUT=/absolute/private-archives
VERIFY_WORK=/absolute/private-verify-work
STAGE_PARENT=/absolute/private-stage-parent

bash tools/offline_backup.sh \
  --age "$AGE_BINARY" --age-sha256 "$AGE_BINARY_SHA256" \
  --identity "$BACKUP_IDENTITY" \
  pack --source "$SNAPSHOT_SET" \
  --recipient "$BACKUP_RECIPIENT" \
  --output "$ARCHIVE_OUTPUT/stargate-backup.tar.age"

bash tools/offline_backup.sh \
  --age "$AGE_BINARY" --age-sha256 "$AGE_BINARY_SHA256" \
  --identity "$BACKUP_IDENTITY" \
  verify --archive "$ARCHIVE_OUTPUT/stargate-backup.tar.age" \
  --work-dir "$VERIFY_WORK"

bash tools/offline_backup.sh \
  --age "$AGE_BINARY" --age-sha256 "$AGE_BINARY_SHA256" \
  --identity "$BACKUP_IDENTITY" \
  stage --archive "$ARCHIVE_OUTPUT/stargate-backup.tar.age" \
  --output "$STAGE_PARENT/staged"
```

Add `--nym` to `pack` for the seven-directory set. The output filename must not
already exist, including as a symlink. Parent directories must already exist;
the tool creates only its own randomly named private work directory. The source
and output directories cannot contain one another. The verification working
directory must not contain the archive or identity. No command prints key
contents, file lists, credentials or subprocess diagnostics.

Treat only exit status `0` with `ENCRYPTED_ARCHIVE_VERIFIED` as pack/verify success. Pack
publishes the completed ciphertext as a single atomic no-replace hard link,
syncs its parent directory, then removes its private spool. Final ciphertext is
mode `0600`, owned by the invoking user; the source numeric owners are stored
inside the encrypted tar headers. Existing outputs are never replaced. A
nonzero exit leaves any apparent final output **unconfirmed**, including when
failure happened after publication during a storage sync.

For staging, `STAGE_PARENT` must already exist, be owned by the invoking user,
mode `0700`, and contain neither the archive nor identity. The output name must
not already exist, even as a symlink. Only exit status `0` with
`OFFLINE_STAGE_CREATED_RECOVERY_REQUIRED` confirms publication. Full age
authentication and complete archive validation finish before member extraction.
The tool uses descriptor-relative no-follow exclusive creation and a Linux
no-replace directory rename; it syncs files, directories and publication. There
is no fallback if these operations fail. Do not operate concurrently on these
paths, including from the same account. Output remains private through its
`0700` parent and top-level directory; archived member modes are retained.

Every member's numeric UID and GID must equal the caller's effective UID and GID.
Directories must have owner `rwx`; every volume root must be exactly `0700`,
and every regular file must be owner-readable. If an
archived `app-data/recovery-incomplete` exists it must be a regular `0600` file;
its contents are discarded and a fresh `0600` marker is installed before
publication. Unsupported ownership or modes are rejected before extraction.
An archived `app-data/volume-import-incomplete` entry is rejected during staging,
regardless of type or contents; it is never replaced by the fresh credential
recovery marker. Discard the entire failed import and return to the trusted
matching source. Archive pack/verify can retain and inspect that entry, but do not
certify logical completeness or make it eligible for staging. Identity recovery
transaction markers are preserved and continue to block ordinary preparation.
Filesystems that assign a different group are rejected; ownership is not remapped.
An archive containing container-owned `10001:10001` files requires a matching
unprivileged account and appropriate offline storage; root is not supported.

**The staged tree contains restored credentials and other sensitive state.** The
marker prevents the updated Compose supervisor from starting until the existing
[OfflineRecovery command](offline-staged-recovery.md) is run successfully on its
`app-data/proxy.properties`. Do not remove the marker or start services as part
of staging. A successful stage is not a recovered, imported or safe-to-run
installation, and the marker cannot gate software that does not honor it.

## Bounds, archive format and cleanup

The format is standard uncompressed USTAR inside a binary age file, not a custom
cryptographic format. Only ordinary directories and regular single-link files
are supported. Symlinks, hard-linked files, devices, sockets, FIFOs, sparse tar
entries, GNU/PAX extensions, set-ID/sticky modes, duplicate paths, traversal,
missing parents, unexpected roots, nonzero trailing/concatenated data and
malformed/truncated archives are rejected. Verification does not decompress or
extract. Source sparse files, if present as ordinary files, are stored as full
logical file contents and must fit the same limits.

Limits are 8 GiB of plaintext tar, 2 GiB per regular file, 100,000 total entries,
32 path components, and 255 UTF-8 path bytes where USTAR can represent them.
Native owner/group IDs must fit USTAR's seven octal digits (`0..2097151`).
Permission bits and numeric UID/GID are preserved without remapping; modification
time is recorded to whole seconds. ACLs, xattrs, SELinux labels, capabilities,
birth/access times, nanosecond timestamps, hard-link relationships and sparse
layout are not preserved. Do not use this tool when those are required.

Ciphertext and age stdout file sizes are bounded, and each age subprocess has a
30-minute timeout. Source files are streamed; tar metadata memory is bounded by
the entry/path limits. Plan for approximately twice the tar size in free private
scratch/output space, in addition to source snapshots and other retained
archives. Staging also needs room for both the decrypted tar spool and extracted
tree; discarded or partially extracted plaintext may remain in filesystem blocks. This is no compression or deduplication system.

Age can emit an authenticated prefix before detecting a corrupt or missing final
chunk. **Plaintext is spooled privately; no archive header, member or metadata is
inspected until the entire decrypt subprocess exits successfully.** Failed
decrypts, including partial output, are removed before returning. No partial decrypted output is accepted as an authenticated archive.

Ordinary failures attempt cleanup of only this operation's known private files.
If cleanup or publication durability cannot be confirmed, the command fails and
reports the exact private `.stargate-backup-*` location for offline inspection.
It attempts to retain or recreate that directory; persistent storage faults
can prevent even this repair, so the reported path can be absent after an error.
It never reports a cleanup failure as success. Ctrl-C and SIGTERM unwind the
operation and attempt cleanup; SIGKILL, power loss or filesystem faults can leave
private plaintext work behind, including a partially extracted, ungated tree in
`.stargate-backup-*`; publication or its durability may also be uncertain. Inspect
the operation directory and destination offline before resuming. Unlinking is not secure erasure; use encrypted storage and appropriate
swap/backups for private plaintext scratch. This is not a power-loss or
storage-failure certification.

## Recovery remains separate

Age payload authentication proves intact decryption for the recipient; it does
**not authenticate the backup creator**. Anyone holding the public recipient
can create another valid ciphertext. There is no trusted timestamp, signed
inventory, anti-rollback mechanism or historical high-water mark.

Retain original encrypted snapshots and their separate recovery keys when old
I2P identities may be needed. An archived `i2p.nextPort` cannot reveal allocations
after that snapshot. The required staged
[OfflineRecovery preparation](offline-staged-recovery.md) replaces that counter
by default with the exhausted sentinel `65536` in the same atomic configuration
replacement as credential removal, even if device isolation is disabled. New
isolated allocations remain blocked by default. The optional attested history
setting requires the maximum numeric port ever allocated, supported by an independently
trusted record covering every allocation through
final shutdown, including revoked devices, post-snapshot allocations and branches,
and all copies offline. The command cannot verify that history. It does not prove
native identity or route safety. Shared I2P and Tor/Nym configuration
are preserved. Re-pairing does not recover or deliberately reattach an old
per-device I2P key, and this archive tool does not establish identity continuity.
Native Tor/I2P/Nym state compatibility and flush consistency remain outside the
archive check. External Compose/environment configuration, software versions,
images, host settings and browser/extension state must be preserved separately
as appropriate; they are not gathered from outside the supplied roots.

The staging command does not discard restored authentication. Run
[OfflineRecovery](offline-staged-recovery.md) on the gated staged `app-data`
copy before any later separately planned use. That command does not turn this
archive operation into an automated recovery procedure.

## Check the tools

Build and run structural checks with the selected toolchain:

```sh
bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml package
```

Native integration is opt-in and requires independently authenticated local
v1.3.2 linux-amd64 age/age-keygen binaries and the matching locally built proxy
JAR. The tests check fixed binary hashes, create synthetic keys and temporary
roots, and perform no Docker, service, production-volume or network operations:

```sh
STARGATE_TEST_AGE=/absolute/verified-age-v1.3.2/age \
STARGATE_TEST_AGE_KEYGEN=/absolute/verified-age-v1.3.2/age-keygen \
STARGATE_TEST_RECOVERY_JAR=/absolute/matching-build/stargate-proxy-0.1.0-SNAPSHOT.jar \
bash tools/with-toolchain.sh mvn --offline -f backup-tools/pom.xml clean package
```

Without the selected native binaries/JAR, optional cases skip; that is not a
full-chain qualification. Stage additionally requires all roots mode
0700 and all files owner-readable with caller UID/GID; structural verification
alone does not establish stage eligibility. These requirements align stage
with the importer. Legacy archives with other modes may verify but fail stage;
keep the original and prepare a matching, private snapshot rather than bypassing
the checks. Neither passing tests nor staging establishes native identity
continuity, storage-failure durability or activation readiness.
