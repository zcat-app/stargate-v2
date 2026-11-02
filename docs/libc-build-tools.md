# Java libc prepared-builder tools

These Java 25 tools diagnose, build and run native memory regressions in an **already prepared** libc builder. The source, CA seed, dependency seed and bootstrap commands use the separate [Java bootstrap module](libc-bootstrap-tools.md). Use the Bash launchers below.

Package the standalone module:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f libc-tools/pom.xml package
```

The Bash launchers activate the repository's shared `tools/with-toolchain.sh` helper. The host needs Bash, Java 25 and Docker. The prepared builder must already contain `/work/root`, `/build/glibc-2.39` inside that chroot, the pinned source archives, and its build tools. Docker installation, chroot preparation and source authentication are outside these commands.

The read-only diagnostic distinguishes a missing Docker CLI or successfully observed missing container from unknown Docker errors, inaccessible paths and unavailable source manifests:

```sh
bash tools/check_libc_builder.sh
```

It checks the local patch hash and existence of manifest-named paths, with 15-second Docker command deadlines. It does not verify source-archive hashes in the container, patch application, dependencies or build success. Its exit status is nonzero if any check is not `present`.

Build using the separately prepared `stargate-v2-libc-build` container:

```sh
bash tools/build_container_libc.sh
```

The controller captures the full builder ID and image ID, rejects host/shared resources, checks all three source-archive hashes and the unchanged patch hash, requires the applied patch marker and prepends the truthful local-version changelog. It preserves dependency installation, `dh_prep`, check/install stamp invalidation, private mount/pivot-root setup and `dpkg-buildpackage --no-pre-clean -us -uc -b -j4`. It never adds `nocheck` or changes upstream tests. The original completed-build reuse remains available only in prepared-builder mode. Exit status, invocation, transfer and cleanup failures remain failures.

An independently prepared fresh builder requires all four options. Values must come from its verified preparation record:

```sh
bash tools/build_container_libc.sh \
  --fresh-builder-id "$builder_id" \
  --expected-image-id "$image_id" \
  --builder-marker "$builder_marker" \
  --output-dir "$new_absolute_output_dir"
```

Fresh mode requires full IDs, the exact fresh-builder label, an unshared private container and clean build state. It creates a new mode-0700 output directory under existing non-symbolic parents and refuses overwrites. The result contains exactly the selected `libc6`, `libc-bin` and `libc6-dbg` packages plus `build-hashes.json`, preserving the existing local version and hash schema consumed by image preparation.

Both modes create a random, labeled mount helper with the original `SYS_ADMIN`/`SYS_PTRACE`, isolated builder PID namespace, security options and shared-memory configuration. The helper's full identity and resource configuration are verified before start and again before cleanup; cleanup targets only its captured full ID. A changed identity or resource configuration is reported without attempting cleanup against the unverified container. These build-only privileges are not applied to runtime containers.

The regression controller needs the separately prepared builder's control chroot, `/tmp/libc6-dbg.deb`, compiler, readelf and Valgrind tree at `/tmp/tools`. It streams that chroot into a newly created, labeled privileged runner with networking disabled. It verifies ownership before start and cleanup, never reuses or removes the old fixed-name runner, checks both ends of the streaming transfer and removes its own runner after each leg. Build-only privilege is required to mount `/proc` for native Memcheck execution.

Run the calibrated control before the patched leg, sharing a dedicated evidence directory. Omit `--evidence-dir` to use `target/libc-regression`. Include the matching debug package when installing the patched packages:

```sh
bash tools/libc_fopen_regression.sh --label control
bash tools/libc_fopen_regression.sh --label patched \
  --libc-deb \
  target/native/libc6_2.39-0ubuntu8.9+stargate20261024.1_amd64.deb \
  target/native/libc-bin_2.39-0ubuntu8.9+stargate20261024.1_amd64.deb \
  target/native/libc6-dbg_2.39-0ubuntu8.9+stargate20261024.1_amd64.deb \
  --compare
```

Every one of the twelve named cases must keep its observable semantics and report the loaded libc build ID. The control must demonstrate invalid writes; the patched leg must have zero invalid reads/writes and matching build IDs. Uninitialised-value reports remain recorded without gating the result. A failed leg exits nonzero without needing `--compare`; comparison succeeds only if both legs pass. Reports retain libc SHA-256/build IDs and raw probe/Memcheck evidence, with added probe-source and owned-runner identity bindings.

The default evidence location is `target/libc-regression`. Source directories, unrecognized existing directories, symbolic parents/log directories and linked output files are rejected. Each attempt removes its previous result and verdict before Docker operations, so an interrupted or rejected attempt cannot leave a stale result for that leg. Old leg reports do not establish authenticity or a fresh native execution.

These commands build and test native code and create privileged local Docker helpers. Host-side Java tests or inspection of saved artifacts do not substitute for running the native build and regressions on the selected inputs.
