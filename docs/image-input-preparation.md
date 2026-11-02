# Prepare image inputs with Java 25

This prepares the context consumed by `containers/Dockerfile`. It does not build
final app/Tor/I2P/Nym images, start services, touch state volumes or publish.
The host needs Linux amd64, the pinned Java **25.0.5 JDK**, Maven to build the
helper, and Docker access. A deployed image needs no host JDK. The source baseline
is declared once in `containers/java-runtime.json`; the monitor reads the same
declaration. Changing that declaration requires separate runtime qualification.

Before replacing a checkout used by an installed or scheduled monitor, follow
the [state-preserving monitor upgrade procedure](java-monitor.md). Keep the
previous checkout and its inputs until the transition succeeds. The image
preparer does not deploy a monitor.

## Prerequisites and commands

Use the intended checkout and its verified native outputs:

- `target/native/`: the pinned patched libc package and `build-hashes.json`.
- `target/i2p-isolation-build/`: matching I2P and owner executables, patch/input
  hashes and `build-record.json`.
- For Nym, a selected build directory with `build-record.json` and
  `source/target/release/nym-socks5-client`, matching the security, lifecycle and
  shared-client pins and both required successful regression flags.
- Built proxy JAR and the **entire** manager `quarkus-app` directory.

Native compilation/bootstrap uses the separate [Java/Bash controllers](libc-bootstrap-tools.md).
This image-input helper does not
compile native code, waive failing native tests, replace local patches with
upstream binaries, initialize routers or choose a Nym requester. An old build
record failing a new gate is a reason to select/prepare compatible inputs, not
edit the record or remove the check.

Run from the checkout, as the ordinary Docker-authorized operator:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl image-preparer -am package
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl proxy,manager -am package
bash tools/prepare-image-inputs.sh --help
```

Offline Maven requires the existing dependency cache. Missing dependencies or
failed tests mean stop and resolve prerequisites; do not skip tests. The preparer
uses the repository's existing Jackson dependency and introduces no new library
dependency.

For the three-network deployment, select the compatible Nym build explicitly.
Replace the absolute placeholder with your verified build directory:

```sh
nym_build='/absolute/path/to/verified-nym-build'
bash tools/prepare-image-inputs.sh \
  --nym --nym-build-dir "$nym_build" \
  --output "$PWD/target/container" \
  --evidence "$PWD/.local-setup/image-preparation"
```

The default Nym directory is `target/nym-build`; it is not automatically the
newest compatible build. Select the directory whose build record passes every
required security, lifecycle and shared-client check.

Omitting `--nym` prepares the existing Tor/I2P context only; it cannot build the
Nym final target. For ordinary web on Nym, keep `--nym` and the Nym Compose overlay.
The default context is `target/container`; default evidence is
`scratch/research/i2p`. Explicit evidence paths avoid mixing proof runs. Protect
evidence as operator data and keep generated contexts/evidence out of Git.
Inside the checkout, a custom context must be a subdirectory of `target`, never
source directories or `target` itself. Existing output must contain the generated
context markers (JDK source hash, app JAR and app runtime record); an unrelated
directory is refused before commands. The helper also protects selected native
input locations. An external custom context must likewise be a recognized context
before replacement; use a fresh output path for a first run.

## What happens and what to check

Before downloads/builds, the helper checks the Java baseline, libc patch/package
hashes and native build version, I2P patches/owner/builder/binary hashes, and the
selected Nym security/lifecycle/shared-client bindings, binary and regression flags.
Package artifacts are verified against the existing Tor/I2P SHA-256 pins. The
pinned authenticated release inputs remain the trust input; a checksum alone
does not authenticate a newly selected upstream release.

The helper creates a fresh sibling staging directory and fresh jlink runtime,
including the JDK trust-store bytes. It builds **only the OS package source stage**
of the existing Dockerfile (normal Docker build cache may apply). This step can
contact Ubuntu repositories; it is not a fully offline or reproducible build.
The source container uses the exact resulting image ID, read-only root, no
network, no capabilities and no state-volume mounts. It is removed on success
or a normal failure. A hard kill can leave this isolated helper; inspect its
exact ID before manual removal, never prune unrelated Docker resources.

The collector retains the existing per-role package/file rules, regular-file
modes, resolved license bytes, Debian source/version metadata for scanners,
UID-10001 account definitions, `/tmp` 1777, private owned-directory scaffolding,
and I2P/Nym overrides. Parent directories and the jlink runtime have explicit
read/traversal modes, including under operator umask 077. It reads selected files
through literal Docker argv calls; there is no host TAR extraction. Host symlinks
are created after file writes. An I2P runtime record now describes the **final
overridden binary hash** together with its build record. Runtime inventory lists
symlink targets separately instead of following absolute image links into the host.

Success prints `Prepared … No final image built or deployment changed.` The
context contains `preparation-evidence/runtime-files.json` and `image-inputs.json`;
these are also copied to the selected evidence directory before publication.
Inspect selected package versions, patches/build records and the final file/link
inventory. Keep these with the source and later image/scan qualification. They
are provenance, not a security clearance or proof that routes work. File reads
and package downloads are bounded to 256 MiB per file/artifact; metadata/license
command output is bounded separately. No browsing traffic or deployed credentials
are read by the preparer.

## Failure and later image builds

Downloads, commands, missing files, malformed records and checksum/regression
failures stop preparation. No successful new context is published before checks,
collection and evidence copies complete. An existing context remains intact on
preparation failure. Evidence left by a failed attempt describes an uncommitted
candidate; it is not proof of successful publication. The sibling-directory swap
retains the prior context until the new one is ready and restores it if the swap
fails. If restoration itself fails, the error identifies the retained `.previous`
directory: stop and inspect those exact paths before recovery. Do not delete that
backup to silence an error.

Successful replacement removes the old generated context; keep any independently
needed previous context separately before running. No deployed state is stored
there. If old-context cleanup fails **after** publication, the helper reports the
committed new context and warns with the exact backup path for manual inspection;
it does not misreport this as a pre-commit failure. Never infer readiness from a
directory left by a failed command or use a partial `.image-inputs-*` stage.

No final image build or deployment is implicit. After separate review, follow
the [container procedure](../containers/README.md) or
[affected-image upgrade procedure](verified-upgrades.md); retain the exact project,
state mappings, patched runtime and Nym settings. Input preparation does not
activate upgrades, roll out a candidate or publish a release.
