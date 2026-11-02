# Offline Docker adapter build and verification

These Java 25 adapters provide the capture, staged-volume import, authenticated
archive import and Compose handoff commands described in the corresponding
[operational guides](../docs/offline-volume-capture.md). The host needs a trusted
Java 25 runtime and local Docker CLI. The controller uses only the local rootful
socket and never mounts it into a helper. The independently reviewed immutable
helper image must contain executable Java 25 at `/opt/java/bin/java`, the
necessary Linux runtime libraries, no declared volumes, and support the mount
paths used by the commands. No helper image is bundled or certified.

From the repository root, build the adapter and its core dependency through the
selected toolchain and root reactor:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress \
  -pl backup-docker-tools -am package
```

The three `tools/offline_*_docker.sh` and `tools/offline_volume_compose_handoff.sh`
launchers activate the selected toolchain and use the built core and adapter JARs. Follow the individual guides for
selection, acknowledgements, private paths, recovery gates and failure handling:
[capture](../docs/offline-volume-capture.md),
[staged import](../docs/offline-volume-import-docker.md),
[archive import](../docs/offline-archive-import-docker.md), and
[Compose handoff](../docs/offline-volume-compose-handoff.md).

The tests use synthetic files and fake Docker responses. To additionally run
native age tests, set `STARGATE_TEST_AGE` and `STARGATE_TEST_AGE_KEYGEN` to
independently reviewed local executables, and `STARGATE_TEST_RECOVERY_JAR` to the
built proxy JAR; the tests generate private synthetic keys and data. Then run:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress \
  -pl backup-docker-tools -am test
```

Tests requiring those inputs are skipped when they are unavailable. Synthetic
checks do not establish arbitrary-version compatibility, mixed-UID source
behavior, production recovery or activated services. The adapters
preserve private journals and may retain plaintext work files after uncertain
outcomes; consult each guide before use. Archive-import handoff requires the
retained plaintext spool and rehashes it on every run. No secure erasure is
provided.
