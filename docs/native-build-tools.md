# Native dependency build tools

The I2P and Nym build helpers run on Java 25 and Bash. Package their standalone module before invoking either launcher:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f native-tools/pom.xml package
bash tools/build_i2p.sh
bash tools/build_nym.sh --work-dir target/nym-build --jobs 4
```

The build host needs Java 25, Docker, Git, GNU tar, patch, and `id`. Maven resolves Jackson and JUnit through the existing parent dependency management; this module can build independently of the parent reactor. Omit `--offline` only when the required Maven dependencies have not yet been cached. The launchers locate their repository from their own paths and activate its shared `tools/with-toolchain.sh` helper before Java. Nym resolves a relative work directory against the caller's current directory, retaining the original default of `target/nym-build`; I2P always uses the repository's `target/i2p-isolation-build`. Nym accepts 1–16 jobs and defaults to 4.

These commands perform real native builds in the existing pinned builder images. They can download source and create Docker images. They do not publish or deploy anything. Java is a build-host prerequisite; the produced native binaries do not require a runtime compiler.

I2P retains the exact pinned archive checksum and source commit, reconstructs a clean source tree, applies the two existing patches, and byte-compares every release source file before reusing incremental objects. Its existing network-disabled Docker build and compiler hardening flags are unchanged. Build records retain their existing source, patch, owner, binary, Dockerfile, and builder-image hashes.

Nym retains the release tag, source commit, dependency lock, lifecycle and shared-client patch/source checksums. It rejects undeclared tracked edits and untracked inputs. It still runs the six named shared-client regressions and the upstream `verify_cert::tests::distrusted_spki` test against source matching the shipped `rustls-webpki-0.103.16` crate, checks the distrusted root string is absent from the resulting binary, and captures build-info. A zero exit code without every expected Rust test result is a failure. Regression flags enter the build record only after those tests and all later gates succeed. Full logs remain in the build directory. Failed attempts remove any previous build record before checking inputs, so stale success cannot stand in for the new attempt.

Run the host-side regression suite with:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f native-tools/pom.xml test
```

These tests cover source admission, hash mismatches, command-plan compatibility, missing/ignored regression results, and binary root-string checks. They do not substitute for rebuilding the native binaries and rerunning their real regressions.

## Enable Nym and preserve its state

After building the native inputs, use the [Java image preparer](image-input-preparation.md)
with `--nym` and the exact verified Nym build directory. Select a current public
network requester from the official Nym node directory at
`https://validator.nymtech.net/api/v1/nym-nodes/described`. The requester address
is public, not a secret; a previously selected address is not a
current availability guarantee. Review that requester's advertised role and availability
before choosing it. A listening local SOCKS port does not prove destination access.

For a **new** three-network installation, after that preparation, set the chosen
address and review the resolved configuration before building or starting:

```sh
export STARGATE_NYM_PROVIDER='REPLACE_WITH_REVIEWED_PUBLIC_REQUESTER_ADDRESS'
docker compose -f compose.yaml -f compose.nym.yaml config --quiet
docker compose -f compose.yaml -f compose.nym.yaml build app tor i2p nym
docker compose -f compose.yaml -f compose.nym.yaml up -d
```

Do not use this new-install command against an existing deployment with another
project, configuration, image or volume selection. Preserve its complete original
invocation; follow [component maintenance](maintenance-upgrades.md) instead.
A persisted client retains its initialized provider; changing the environment
variable alone does not rewrite that configuration or its identity.

The launcher creates the private `nym-secrets` key-passphrase file once, mode
0600, and passes it only through the native child's environment. It is not a
wallet seed, payment credential or NymVPN login; it does not encrypt every
database. Keep **both** `nym-data` and `nym-secrets`, with the rest of the matching
seven-volume state set. Neither volume is published as a network interface.
The client uses the free-bandwidth mixnet path; paid credential purchase is
not implemented. Provider or free-bandwidth refusal makes the route unavailable.
No direct or other-network fallback is enabled.

Wrong or missing secrets with existing state cause failure; startup does not
generate replacement identity keys. Interrupted first initialization can leave
`initialization-started` and partial keys without `config.toml`. Preserve both
volumes and the secret, inspect the private failure evidence, and choose explicitly
between restoring a complete matching backup and initializing a new identity.
Do not remove markers or wipe an established identity to silence an error or
repair a transient network outage. Use the [operator recovery procedure](operator-guide.md#6-backup-and-recovery).
Do not enable native diagnostic destination logging in production.

Removing the Nym overlay disables ordinary-web routing on the next app recreation;
saved browser access is retained. Stop Nym using the existing complete overlay
selection first, then review a configuration without the overlay before recreating
app. An environment file's `COMPOSE_FILE` can otherwise silently restore the
overlay; use the intended explicit `-f` arguments. This is a deliberate operator
change and can interrupt users.
