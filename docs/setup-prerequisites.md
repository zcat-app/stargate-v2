# Guided operator prerequisites

Run from the checkout, without sudo:

```sh
bash tools/setup-wizard.sh --check-prerequisites
bash tools/setup-wizard.sh --prerequisites
```

The first command checks Docker/Compose and current daemon access without
installing anything. The second offers three profiles: **prepared images**,
**operator Java tools**, or **build from source**. Enter selects prepared images.
Browser users need none of these host tools. Configuration preview remains
write-free and does not run Docker; normal generation checks its Docker
prerequisites after confirmation and offers this guided step if they are missing.
A failed check does not publish a configuration; rerun after setup is ready.

Checks cover Linux amd64, Docker CLI, Compose 2.24.4+ and daemon access. The Java
profiles require the declared Java 25.0.5 runtime, compiler and linker together.
The build profile additionally checks the qualified Maven 3.10.0 baseline, its
effective Java runtime and Git. Different versions are reported as needing setup,
not silently treated as qualified. Native patched builds, successful native
regressions, Maven dependency cache, TLS staging and state/deployment selection
remain the separate prerequisites in the existing guides. This step installs
operator tools; it is not a complete native-builder or deployment installer.

For a specific read-only profile check:

```sh
bash tools/setup-prerequisites.sh --check images
bash tools/setup-prerequisites.sh --check tools
bash tools/setup-prerequisites.sh --check build
```

## What the guided step can install

Automatic installation is limited to **Ubuntu 24.04 amd64**. Other Linux amd64
hosts can be checked, but unsupported installation paths stop with an explanation.
Existing compatible tools are reused. Before installation the wizard shows the
plan, versions, privilege requirements and effects, then asks for confirmation.
Enter accepts that displayed plan; `no` or end-of-input cancels before installation.
It never installs Python or executes legacy Python helpers.

- **Java/Maven:** fixed release archives with SHA-256 and detached PGP signatures.
  The public-key bytes and expected signer fingerprints are source-pinned under
  `containers/setup/`. GnuPG uses a private temporary home, no key retrieval and
  no user keyring. Signature failure or a mismatched signer/checksum stops before
  activation. See [Adoptium archive verification](https://adoptium.net/installation/archives)
  and [Apache Maven releases](https://maven.apache.org/download.cgi).
- **Docker/Compose:** the official signed Docker APT repository, using the pinned
  public key with `Signed-By`. This is allowed only on a fresh host: existing
  runtime packages/processes, Docker/containerd state/configuration, known service units,
  overrides, unmanaged binaries or selected Docker host/context cause refusal.
  Any existing client `config.json` also causes refusal, including a stored
  default context. Only file metadata is inspected; registry credentials and
  stored context contents are not read or printed.
  Package actions use `--no-remove --no-upgrade`. A new Docker service may be
  started by package installation; this is included in the recap. See
  [Docker's Ubuntu procedure](https://docs.docker.com/engine/install/ubuntu/).
- Missing download tools/CA certificates/Git can be installed through the host's
  existing trusted Ubuntu repositories after the recap. No remote shell installer
  is downloaded or executed. Existing Docker services are not repaired/restarted,
  removed or replaced automatically.

No production proxy/manager, firewall, certificates or state volumes are changed.
Daemon startup and Docker-group permission grants remain explicit manual operator
steps. The wizard does not run those commands.

## Scoped Java and Maven selection

Java and Maven go into the operator's private
`~/.local/share/stargate/toolchains/` directory. System alternatives and shell
startup files stay unchanged. The checkout stores only the selected absolute
paths in `.local-setup/java-home` and `maven-home`, mode 0600 inside 0700 storage.
Incomplete, aliased, shared or unsafe selections fail closed without falling back
to system binaries. Verified installations may contain upstream internal links.

Use the activation wrapper for build commands:

```sh
bash tools/with-toolchain.sh java --version
bash tools/with-toolchain.sh javac --version
bash tools/with-toolchain.sh jlink --version
bash tools/with-toolchain.sh mvn --version
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -pl image-preparer -am package
```

Image-input and extension-packaging launchers use this wrapper automatically.
The native/backup launchers use the same selection when their migrations are
integrated. An ordinary `mvn` or `java` outside this wrapper still uses your
existing shell environment. Missing Maven dependencies and native builds are
not solved by installing the JDK/Maven alone.

Systemd services need an explicit appropriate Java executable in their reviewed
unit. User-service installation can select this operator JDK; the root certificate
job requires a root-controlled JDK accessible under its sandbox and must not use
this operator-writable private toolchain. Follow the [root JDK provisioning and TLS selection
procedure](root-java-toolchain.md) before activating those jobs. The wizard
checks operator tools, not readiness of all root/user systemd services.

## Docker access or service not ready

Package installation is different from a usable daemon. A container/test host
without systemd or a daemon is reported as **not ready**. On the real operator
host, diagnose first:

```sh
docker context show
docker info
id -nG
sudo systemctl status docker --no-pager
```

Do not switch a selected remote Docker context silently. Starting Docker can
resume existing containers. Only after reviewing the intended host/workloads,
the operator may deliberately enable/start its service:

```sh
sudo systemctl enable --now docker
```

Docker-group membership gives the trusted operator root-level control through
Docker. If that is appropriate, grant access explicitly, then log out of SSH
and reconnect so the new group is active:

```sh
sudo usermod --append --groups docker -- "$(id -un)"
exit
```

After reconnecting, rerun `bash tools/setup-wizard.sh --check-prerequisites`.
For an existing daemon needing Compose only, follow Docker's official repository
procedure and review the proposed package transaction; this wizard deliberately
does not replace an existing runtime or install arbitrary unverified plugin bytes.

## Failed setup and retry

Setup is not one system-wide rollback transaction. A JDK installed before a later
Maven/package failure stays installed, and completed selection files stay selected.
The check reports the remaining problem. Downloads and temporary GPG homes are
removed on normal exit; existing toolchain destinations are never overwritten.
A hard interruption can leave private staging files. Inspect the exact reported
paths before cleanup; do not prune unrelated Docker resources or remove state.

If a partial installation leaves an existing destination, do not delete a toolchain
used by services. Inspect it and the log first. A previously unused destination
can be moved to a private backup before retrying the verified installation. Keep
that backup until the new selection and dependent tools have been checked.

To remove only this checkout's toolchain selections and return to the shell's
existing tools (this does not uninstall either JDK or Maven):

```sh
rm -- .local-setup/java-home .local-setup/maven-home
```

If Docker setup stopped after creating repository files, inspect exactly these
public files. Compare the key hash with `DOCKER_SETUP_KEY_SHA256` in the source
and compare the source stanza with the helper before treating them as this
attempt's files:

```sh
sudo sha256sum /etc/apt/keyrings/stargate-docker.asc
sudo cat /etc/apt/sources.list.d/stargate-docker.sources
```

Do not remove them after a successful install: the repository supplies updates.
If they are confirmed leftovers from this failed attempt and Docker was not
installed, remove only those confirmed files before retrying:

```sh
sudo rm -- /etc/apt/keyrings/stargate-docker.asc /etc/apt/sources.list.d/stargate-docker.sources
```

Existing runtime/Compose repair and other distributions require the corresponding
operator/vendor procedure. Unsupported or incomplete checks are not passed.
After setup, rerun the read-only prerequisite checks before continuing.
