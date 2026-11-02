# Continuous integration

[CI](../.github/workflows/ci.yml) checks pushes and pull requests to `main`,
and supports manual workflow dispatch. It uses one disposable
Ubuntu 24.04 runner, a Temurin JDK matching `containers/java-runtime.json`,
Node 24 for the extension tests, and the runner's Maven. Tool versions appear in
the log.

The three official GitHub actions are pinned to full commit hashes. JDK download
signature verification is required. The job has read-only repository permission;
checkout does not retain its authentication token in Git configuration. There
are no signing-key inputs, dependency-cache writes, artifact-upload steps,
release steps or deployment commands. Generated JARs and unsigned extension
packages remain in the disposable runner. Project commands use Bash, Java and
the existing extension's JavaScript tests; no Python is invoked.

## Checks and local reproduction

From an initialized checkout with Java 25, Maven, Node 24, Git, Bash, `jq` and standard
Linux tools, run:

```sh
bash tools/check-source-policy.sh
while IFS= read -r -d '' path; do
  case "$path" in *.sh) bash -n "$path" ;; esac
done < <(git ls-files -z)
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress package
bash tools/with-toolchain.sh mvn --batch-mode --no-transfer-progress -f simplex-alert/pom.xml package
node --test extension/test/*.test.cjs
bash extension/test-package.sh
bash extension/package.sh
```

Stop on any failed command. Maven runs the existing tests without `skipTests`,
test exclusions or ignored failures. The standalone SimpleX module is checked
separately because it is not a module of the root reactor. Packaging tests cover
the real Java packager, ZIP payloads, reproducibility and failure boundaries.
Ordinary dependency/tool downloads use HTTPS; no product network route is started
or changed by this job. A green CI check is not permission to publish a release.

## Native and real-network qualification remain separate

Some retained tests are explicitly conditional in their existing source. Minimal
CI does not download private evidence or invent substitutes for it:

| Existing condition | Extra evidence it enables |
| --- | --- |
| `STARGATE_TEST_AGE` and `STARGATE_TEST_AGE_KEYGEN` | Pinned native age/age-keygen spawn, encrypted archive and recovery tests. |
| `STARGATE_TEST_RECOVERY_JAR` | The native backup test's real offline-recovery CLI bridge. |
| `native.build.fixture.root` | Retained I2P/Nym binary and build-record comparisons. |
| `libc.build.fixture.root` | Retained libc package, probe, Memcheck and regression-summary checks. |
| `bootstrap.fixture.plan` and `bootstrap.full.source.proof=true` | Retained bootstrap plan, source/CA archives and full cached-source preparation. |

Without those inputs, the existing annotations/assumptions omit or abort those
tests; they must not be reported as native passes. Maven's executed/skipped
counts describe that run. This job does not build native container images, scan deployed images, contact
Tor/I2P/Nym destinations, send SimpleX alerts or run Firefox/Brave. A green check
does not qualify those behaviors or authorize deployment.

## Updating action pins

Inspect the official release and its resolved commit before changing an action
hash; review the resulting diff and rerun relevant checks. Version comments are
labels, while the full hashes select the executable action code. Current pins
were checked against the official [checkout release](https://github.com/actions/checkout/releases/tag/v7.0.1),
[setup-java release](https://github.com/actions/setup-java/releases/tag/v6.1.0)
and [setup-node release](https://github.com/actions/setup-node/releases/tag/v7.1.0).
The [Ubuntu runner inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2404-Readme.md)
is mutable and is not a reproducible runner-image guarantee.
