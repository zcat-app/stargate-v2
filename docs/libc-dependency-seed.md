# Fixed-input libc dependency seed

Build the [Java 25 bootstrap module](libc-bootstrap-tools.md) and satisfy its
host prerequisites before using these commands.

`tools/prepare_libc_dependency_seed.sh` prepares and can execute a single fixed
Ubuntu dependency-seed plan. `prepare` only checks inputs and writes the plan;
`execute` starts one isolated Docker container and installs dependencies from
the fixed Ubuntu snapshot. Neither command creates the build chroot, compiles
libc, runs its tests or establishes that libc can be built successfully.

The fixed inputs are the official Ubuntu amd64 image manifest
`ubuntu@sha256:a2d43bffc46670d7108bb3c0468c67c5557c4c92e83e1e34cbff1322ad1b94dc`
with image ID `sha256:6277ab668b2ad3c3ab851d370faa1690d324b30db29d342527f61fed28f20f36`,
the four pinned glibc source files and patched source tree, and the CA bundle
SHA-256 `64e7c24b0536b525fb19b145768bd5e6e12ced0df3db837c34553ea789acd143`.
The source is checked against the content and symlink inventory from the
pinned fixed-input inventory. Directory
and file modes are also checked for the later tests that change UID. This is an
exact-input check, not a new publisher signature verification of the source.
The CA bundle must be prepared by `tools/prepare_libc_seed_ca.sh`; its signed
release and package checks and their limitations are described in the
[container runbook](../containers/README.md). Use
`tools/prepare_libc_source.sh` to create the separate source workspace.

## Prepare the reviewed plan

Supply explicit existing input paths and a **new** absolute output path with
real, non-symlink parents, outside both input workspaces:

```sh
bash tools/prepare_libc_dependency_seed.sh prepare \
  --source-workspace /absolute/path/to/prepared-source-workspace \
  --ca-bundle /absolute/path/to/ca-workspace/bootstrap-ca.pem \
  --output /absolute/path/to/new-private-plan
```

The command creates the output directory mode 0700 and `plan.json` mode 0600.
Failure retains the new directory and does not make it reusable; choose a new
output for a retry. It checks all archive hashes, the source-preparation status,
patched target and complete source-tree inventory. The hash binds file content,
names, directory entries and symlink text; ordinary files must be single-link,
mode 0644 or 0755, and directories mode 0755. The source and CA inputs remain
in their original locations and must remain unchanged and inaccessible to
concurrent writers during execution.

`plan.json` contains a random marker, unique container name, exact argument
arrays, timeouts, expected hashes and input paths. Record and review its SHA-256.
The executor regenerates the complete supported plan and rechecks inputs before
claiming it. Do **not** call the separate `claim` command before `execute`:
execution claims it internally. An earlier manual claim consumes the plan.

## Execute once

Execution requires exclusive control of the reviewed local Docker daemon at
`unix:///var/run/docker.sock`, the fixed image already present locally, and a
trusted root-owned Docker CLI at a canonical absolute path. The daemon ID and
Docker CLI hash are operator-supplied expectations, not discovered trust
anchors. After independently inspecting the daemon, image, host resources,
storage driver and plan, invoke:

```sh
bash tools/prepare_libc_dependency_seed.sh execute \
  --plan /absolute/path/to/new-private-plan/plan.json \
  --docker-cli /usr/bin/docker --docker-sha256 "$REVIEWED_DOCKER_SHA256" \
  --daemon-id "$REVIEWED_LOCAL_DAEMON_ID" --ack-exclusive-local-daemon
```

The acknowledgement is the operator's assertion of exclusive control; the
command checks the daemon ID but cannot prevent an external actor from using it.
The output directory must still contain only `plan.json`. The executor verifies
inputs and the exact plan, then exclusively creates and syncs `plan.once` before
any Docker call. A failure or interruption consumes that plan; never delete the
fence or reuse it. It creates a private durable `execution.jsonl`, an isolated
empty Docker configuration directory and private bounded per-command output.
Each command intent and result is synced; a journal failure prevents further
Docker operations. It checks the daemon and the exact captured container ID,
name, label, image, state and isolation before every seed stage. It never adopts
an existing builder or uses a shared name for cleanup.

The plan uses `--pull never`, a random name and label
`org.stargate.libc.dependency-seed=<marker>`, root only inside the container,
bridge egress, Docker's default private PID and UTS namespaces (explicit empty
mode values), explicitly private IPC and cgroup namespaces, no host/shared
mounts and no published ports. Inspection requires empty PID and UTS modes
and private IPC and cgroup modes. [Docker documents these PID and UTS modes](https://docs.docker.com/reference/cli/docker/container/run/).
It requests 4 GiB memory, 4 GiB combined memory/swap, 2 CPUs, 512 PIDs and
disabled Docker logging. These configured limits are not a capacity
recommendation for another host or workload.

The default requests **no hard writable-layer quota** and does not claim that
one is enforced. The executor records the daemon's Docker root path and available
and total space for that filesystem and the output filesystem before creation,
before source copy and after dependency installation. It also records Docker's
reported `SizeRw` for the owned seed before copy and after installation. An
inaccessible filesystem or unavailable size is recorded as unknown. These are
observations, not a reservation, hard cap, or proof of available space throughout
the run; the operator must ensure sufficient space and monitor it.

An operator whose Docker storage driver and backing filesystem support the
setting may explicitly add `--layer-quota 8G` to **prepare**. That plan requests
`--storage-opt size=8G`, and execution rejects a missing or mismatched setting;
it never retries without it. For overlay2, Docker documents that this option
requires XFS with project quotas. The plan and result record the requested mode;
a matching inspection shows configuration, not independently verified quota
enforcement. The default is portable to hosts without that option. See
[Docker storage-driver options](https://docs.docker.com/reference/cli/docker/container/run/#set-storage-driver-options-per-container---storage-opt).

The executor caps ordinary stdout and stderr at 16 MiB per stream, each source
readback tar at 512 MiB, and aggregate Docker stdout/stderr at 2 GiB. It also
uses per-command deadlines. These are limits for seed preparation, not
measured build requirements. Ensure enough bounded host storage for those files,
the small journal and metadata, and the container's own writable layer. A
client timeout or output limit kills only the local Docker CLI process group:
it does not establish that daemon-side work stopped.

The runner copies the verified inputs into the owned container and checks all
source and CA hashes, including the Ubuntu keyring. It copies the complete source
back and verifies the fixed content, symlink and mode inventory. It replaces the
seed's APT sources with the signed `20261027T000000Z` Ubuntu snapshot, seeds
HTTPS with the verified CA, installs normal CA certificates and
`build-essential`, and performs an unmodified TLS/signature-checked update. It
runs `apt-get build-dep` against the exact DSC with empty build options and
profiles, installs the existing helper `DEPS`, and runs `dpkg-checkbuilddeps`.
The recorded package inventory must match
`4812261212acdd9ccc4921137defbf96fc2f223c7a6853c36c03b2a995681670`.
It checks the source and CA hashes and source copyback again, and rechecks the
host input inventory before declaring the seed ready. No security test, package
test, profile or build flag is changed.

On success, `result.json` reports `dependency-ready`, the full owned container
ID, marker, quota status and disk observations; the running seed is retained for a separately reviewed next
step. It is not a build-ready chroot. A completed APT error or verified content
mismatch triggers cleanup only after the exact owned container is re-inspected;
the executor stops and removes that ID and verifies its absence. Ambiguous
create, identity, daemon, timeout, output-limit or cleanup outcomes retain the
resource and evidence for manual review. If journal durability fails, it makes
no further Docker calls. Never sweep by name or label, reuse the plan, or remove
an unverified resource. Preserve the private output and inspect the exact
recorded ID before any later action.

Offline tests:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml -Dtest=SeedContractTest,SeedExecutorTest test
```

These tests exercise fixed input and copy boundaries, full fake-Docker lifecycle,
identity and resource checks, bounded local output, one-shot fencing and failure
paths. Those tests alone do not prove Docker compatibility, dependency
installation or general resource-capacity bounds.

## Prepare a fresh builder

`tools/bootstrap_libc_builder.sh` executes a newly prepared, unclaimed plan and
continues only after the seed executor reports `dependency-ready`. It commits
the inspected seed to an untagged image with a unique seed-image label, checks
the image ID, parent, layers, labels and architecture, and creates a separately
labeled, inspected builder from that exact image ID. It does not adopt an old
container or execute the libc build. An exclusive local daemon is required
throughout; neither labels nor these checks prevent another daemon user from
changing resources. Keep both input workspaces and the plan private and free of
concurrent writers.

The builder requests bridge networking, explicit empty PID and UTS modes
(Docker's private defaults), and private IPC and cgroup namespaces. Inspection
requires those exact modes. It has no host mounts or published ports. Its 9 GiB `/work`
tmpfs is writable, executable, permits device nodes, and is nosuid. Unlike the
4 GiB dependency seed, the builder has no memory limit: tmpfs usage consumes
host memory or swap. Ensure sufficient memory and Docker storage. These
resource settings do not establish portability or a capacity recommendation.

On the reviewed Docker host, provide the prepared source and CA, a new plan
directory, and independently reviewed Docker CLI hash and daemon ID:

```sh
bash tools/prepare_libc_dependency_seed.sh prepare \
  --source-workspace /absolute/path/to/prepared-source-workspace \
  --ca-bundle /absolute/path/to/ca-workspace/bootstrap-ca.pem \
  --output /absolute/path/to/new-private-plan
bash tools/bootstrap_libc_builder.sh \
  --plan /absolute/path/to/new-private-plan/plan.json \
  --docker-cli /usr/bin/docker --docker-sha256 "$REVIEWED_DOCKER_SHA256" \
  --daemon-id "$REVIEWED_LOCAL_DAEMON_ID" --ack-exclusive-local-daemon
```

Record and review the plan and CLI hash before the second command. A plan is
consumed once; do not pre-claim it or reuse a failed plan. Prepare a new plan
in a new output directory for each retry. The executor creates a private
`bootstrap/` journal under the plan directory. It verifies root and package
inventories, snapshot sources and pinned hashes before and after the root copy,
checks numeric DNS, device nodes, mount/namespace and GNU tar prerequisites,
build dependencies, and the existing fresh preflight. Copying preserves
numeric ownership, xattrs and ACLs and excludes pseudo-filesystems and mutable
Docker host files. Successful `bootstrap/result.json` reports `bootstrap-ready`
and the full builder ID, image ID and marker. This is readiness only; it does
not run `dpkg-buildpackage`, glibc tests, or an OS/image rebuild.

Successful seed, image and builder are retained. A definite local readiness
failure can remove only the individually re-inspected builder, confirming its
absence; seed and image remain. Ambiguous creation, Docker or identity outcomes
are retained for manual investigation. A journal failure prohibits further
Docker operations. Inspect the exact recorded IDs and labels before any manual
cleanup; never sweep by a name or label. The seed's separate failure rules
continue to apply.

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml -Dtest=BuilderBootstrapTest test
```

Successful bootstrap establishes readiness of its selected inputs only. Keep
exclusive daemon access through the later build and run the native build and
regression checks separately. Do not treat readiness as a passing libc build.
