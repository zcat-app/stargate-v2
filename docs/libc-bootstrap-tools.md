# Java libc source and bootstrap tools

The standalone `bootstrap-tools` Java 25 module supplies the libc preparation commands. Its Bash launchers use the repository's shared toolchain activation helper.

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml package
```

The host needs Linux with the supported 64-bit descriptor ABI, a full Java 25 JDK, Bash, `/usr/bin/setsid`, trusted root-owned system `dpkg-source`, `patch`, `gpgv`, `dpkg-deb`, their archive tools, and the pinned Ubuntu archive keyring. Qualification here used Linux amd64. The Java helper uses the standard Java 25 foreign-function API for existing Linux `open`, `openat`, `read`, `fsync` and `close` calls. This preserves the original nonblocking/no-follow input checks and directory-anchored private fences/journals without compiling a native helper. Launchers enable that host-only access. The produced runtime images do not acquire these build tools or archive libraries.

## Prepare source

Run as an ordinary user, with an existing real workspace parent:

```sh
bash tools/prepare_libc_source.sh --workspace-parent /tmp
```

This creates a new mode-0700 workspace, downloads the three exact Ubuntu source artifacts and DSC-required auxiliary signature from the fixed official HTTPS archive, and verifies their Git-pinned SHA-256 values. Proxies, alternate filenames and redirects are refused; reads and downloads are bounded. The DSC binds the auxiliary checksum and 833-byte size. This is integrity against the repository pins, with no publisher-signature verification claim for source preparation.

The trusted unpacker retains strong checksum checks and runs only its child under umask 022. The source must retain mode-0755 directories and mode-0644/0755 regular files; the helper does not repair archive modes. The unchanged backport requires one unique complete preimage, one supported hunk, zero fuzz and the exact postimage in its owned, regular, single-link target. Line offsets are permitted. Other helper files remain private. `status.json` records `incomplete` until every download, extraction, permission and patch gate succeeds. Failed workspaces and logs are retained; retries create a new workspace. This command does not install dependencies, create a chroot or compile libc.

## Prepare the temporary CA seed

Supply the previously downloaded, exact fixed snapshot files using the host's normal trusted TLS configuration. The snapshot is `https://snapshot.ubuntu.com/ubuntu/20261027T000000Z/`; required paths are `dists/noble-updates/InRelease`, `dists/noble-updates/main/binary-amd64/Packages.xz` and `pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.1_all.deb`.

```sh
bash tools/prepare_libc_seed_ca.sh \
  --inrelease "$seed_downloads/noble-updates.InRelease" \
  --packages "$seed_downloads/noble-updates-main.Packages.xz" \
  --ca-deb "$seed_downloads/noble-ca-certificates.deb" \
  --workspace-parent /tmp
```

The helper retains the fixed release/index/package/keyring hashes and requires exactly the pinned `VALIDSIG` signer from a successful `gpgv` process. The signed release binds the index hash and size, and the index binds the CA package's version, architecture, filename, size and hash. The bundle contains exactly 120 validated, uniquely named regular Mozilla certificate entries in deterministic order. Linked or special certificate entries fail. The private temporary `bootstrap-ca.pem` is for the isolated dependency seed; it does not modify host trust or prepare a builder.

## Prepare and review a one-shot dependency plan

Use the source and CA workspaces printed by the earlier commands. The output must be a new absolute path outside both inputs:

```sh
bash tools/prepare_libc_dependency_seed.sh prepare \
  --source-workspace "$source_workspace" \
  --ca-bundle "$ca_workspace/bootstrap-ca.pem" \
  --output "$new_absolute_output"
```

This checks the prepared status, all four archives, exact patched target, CA hash and complete source inventory. It writes private `plan.json`; no Docker command runs. Optional `--layer-quota 8G` is retained. Unsupported quota configuration fails without fallback, and configuration is never reported as independently verified enforcement.

The pinned Linux amd64 image must already be available on the selected local Docker daemon. Review the entire plan, the canonical root-owned Docker executable and its SHA-256, and the daemon identity at `unix:///var/run/docker.sock`. Execution requires explicit attestation that this is the exclusive local daemon:

```sh
bash tools/prepare_libc_dependency_seed.sh execute \
  --plan "$new_absolute_output/plan.json" \
  --docker-cli "$docker_cli" --docker-sha256 "$docker_sha256" \
  --daemon-id "$daemon_id" --ack-exclusive-local-daemon
```

Execution regenerates and compares the fixed plan, rechecks inputs, and durably consumes it before Docker access. A private Docker configuration and fixed Unix endpoint prevent ambient context/credential settings from changing the target. Every copied-input/APT stage is preceded by daemon and owned-container inspection. The original image, label, full-ID, namespace, mount, device, capability, port and resource gates remain. Before/after source archives, CA, patched file and keyring hashes, full copied-source inventories, fixed snapshot sources and exact installed-package inventory remain required. Build options/profiles are explicitly cleared for dependency checks. No libc build command appears in the dependency plan.

Success retains the inspected owned seed. Known completed failures clean only the reverified full ID and require exact stop/remove acknowledgements plus confirmed absence. An ambiguous create/client/inspection outcome, timeout, interruption or failed durable journal prohibits further unsafe actions and retains resources for exact-ID review. A consumed or attempted plan is never reused. Disk-space and writable-layer observations retain explicit unknown values and make no capacity or quota-enforcement guarantee.

Offline subcommands remain available: `claim --plan`, `verify-inputs --plan`, `verify-image --inspection`, `verify-container --inspection --marker --id --state [--layer-quota 8G]`, and `verify-source-tar --archive`. `claim` consumes a plan and is not a prerequisite to `execute`.

## Prepare a fresh builder

Use a fresh, unconsumed plan. This command executes the dependency seed and then performs the complete builder handoff:

```sh
bash tools/bootstrap_libc_builder.sh \
  --plan "$new_absolute_output/plan.json" \
  --docker-cli "$docker_cli" --docker-sha256 "$docker_sha256" \
  --daemon-id "$daemon_id" --ack-exclusive-local-daemon
```

The handoff binds the committed image to the fixed parent, ordered layers, architecture, labels and immutable ID. It verifies a new labeled builder, the exact 9-GiB executable/device-capable `/work` tmpfs, ownership, prerequisites and numeric DNS. It copies the root with the original numeric ownership, xattr/ACL, one-filesystem and exclusion flags, then creates only the specified chroot directories/devices and checks their behavior. Image and chroot input/source/package/snapshot inventories, build dependencies and fresh-build preflight must all match. No libc compilation or native regression is performed.

Success retains the seed, image and running builder and writes `bootstrap/result.json`, including full builder/image IDs and marker. Feed those reviewed values to the separate [libc build controller](libc-build-tools.md). The result means bootstrap readiness, never a rebuilt or regression-tested libc. Cleanup remains restricted to a reverified owned builder; uncertain outcomes retain resources and images.

SIGINT/SIGTERM cancel the worker with signal exit status. Private local process sessions are terminated and pipes closed before bounded reader shutdown; signals arriving in critical local cleanup are deferred. Cancellation of a Docker operation remains uncertain and retains its exact-ID resources. Neither signal handling nor a stopped local Docker client proves that daemon-side work stopped.

Use the separate [libc build controller](libc-build-tools.md) only after bootstrap reports readiness. Bootstrap success does not establish that libc builds or passes its native regressions.
