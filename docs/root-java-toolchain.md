# Root certificate job: qualified Java 25

The wizard's `~/.local/share/stargate/toolchains/` JDK is operator-writable and
hidden by the TLS unit's `ProtectHome=true`. It cannot supply the root job.
The checked-in unit uses `/usr/bin/java`; that path is not evidence that Java 25
is installed or protected. This manual Linux amd64 procedure installs the same
fixed Temurin **25.0.5+8** archive authenticated by the wizard, then selects its
absolute path in the reviewed TLS unit. It changes no system alternatives.
Commands below are operator instructions, not an installer or a claim of rollout.

Use existing trusted `curl`, GnuPG, GNU tar/coreutils and systemd. Stop if any are
missing. Review `containers/setup/prerequisites.sh` and `temurin.asc` from the
intended revision; record that revision and their hashes. The literal archive/key
hashes and signer below must match those reviewed declarations. Do not source a
checkout or execute its scripts as root, copy an extracted operator JDK to root,
or substitute a latest-release URL.

## Stage public inputs

Run without sudo from the reviewed checkout. These are public release/key bytes;
no certificate or private key enters this staging directory. Reuse an existing
cached archive/signature with the same names instead of downloading again if
available; verification below is still mandatory.

```bash
jdk_stage=$(mktemp -d /tmp/stargate-root-jdk-inputs.XXXXXXXX)
chmod 0700 "$jdk_stage"
install -m 0600 containers/setup/temurin.asc "$jdk_stage/temurin.asc"
install -m 0600 containers/setup/prerequisites.sh "$jdk_stage/reviewed-prerequisites.txt"
jdk_url='https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5%2B8/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5_8.tar.gz'
curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --max-filesize 268435456 --output "$jdk_stage/temurin-jdk.tar.gz" "$jdk_url"
curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --max-filesize 268435456 --output "$jdk_stage/temurin-jdk.tar.gz.sig" "$jdk_url.sig"
sha256sum containers/setup/prerequisites.sh containers/setup/temurin.asc
```

Stop on any failed command. Transfer only these four public files to a **new**
protected review directory. Its exclusive creation refuses reuse; inspect an
existing directory rather than overwriting a prior review. `/root` must be the
normal root-owned, non-writable-to-others directory, without a symlink.

```bash
sudo mkdir -m 0700 /root/stargate-root-jdk-25.0.5-review
sudo install -o root -g root -m 0600 "$jdk_stage/temurin.asc" "$jdk_stage/reviewed-prerequisites.txt" "$jdk_stage/temurin-jdk.tar.gz" "$jdk_stage/temurin-jdk.tar.gz.sig" /root/stargate-root-jdk-25.0.5-review/
sudo sha256sum /root/stargate-root-jdk-25.0.5-review/reviewed-prerequisites.txt /root/stargate-root-jdk-25.0.5-review/temurin.asc
sudo namei -l /root/stargate-root-jdk-25.0.5-review/temurin.asc
```

Compare the copied declarations/key and hashes with the reviewed revision and
record them. Treat the copied declarations as text only. Root-owned staging,
literal pins and re-verification below bind extraction to those public bytes,
even if the checkout or operator staging later changes.

## Authenticate, extract and qualify

First inspect `sudo namei -l /opt`. `/opt` must be a real root-owned directory
without group/world write permission. Create `/opt/stargate` only if absent;
otherwise inspect its ownership/permissions instead of changing them blindly.
The block checks both parents, refuses an existing JDK destination, authenticates
before extraction, and never runs anything from the checkout.

```bash
sudo env -i PATH=/usr/bin:/bin /bin/bash -eu -o pipefail <<'SH'
umask 077
cd /root/stargate-root-jdk-25.0.5-review
sha256sum -c <<'HASHES'
a46d5d3ab75c3c86dddf1bfd2957a067a24b1c6b2d2ed2bc69294bf970c5160b  temurin.asc
68982529869257d0ee6b824ec5aa270ff8b118bb438670da0b97ebdab178d7fb  temurin-jdk.tar.gz
HASHES
mkdir -m 0700 gpg
# Private keyring only; no network key retrieval or user keyring.
gpg --homedir "$PWD/gpg" --no-autostart --batch --import temurin.asc
gpg --homedir "$PWD/gpg" --no-autostart --no-auto-key-retrieve --batch --status-fd 1 --verify temurin-jdk.tar.gz.sig temurin-jdk.tar.gz > gpg/status 2> gpg/verify-log
awk '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3=="3B04D753C9050D9A5D343F39843C48A565F8F04B" || $NF=="3B04D753C9050D9A5D343F39843C48A565F8F04B") {ok=1} END {exit !ok}' gpg/status
for parent in /opt /opt/stargate; do
  if [ "$parent" = /opt/stargate ] && [ ! -e "$parent" ] && [ ! -L "$parent" ]; then
    mkdir -m 0755 "$parent"
  fi
  test -d "$parent" && test ! -L "$parent"
  test "$(stat -c %u "$parent")" = 0
  test -z "$(find "$parent" -maxdepth 0 -perm /022 -print)"
done
jdk_home=/opt/stargate/jdk-25.0.5+8
test ! -e "$jdk_home" && test ! -L "$jdk_home"
tar -tzf temurin-jdk.tar.gz > archive.paths
while IFS= read -r entry; do
  [[ "$entry" == jdk-25.0.5+8/* && "$entry" != /* && "/$entry/" != */../* ]]
done < archive.paths
mkdir -m 0700 extracted
tar --extract --gzip --file temurin-jdk.tar.gz --directory extracted --no-same-owner --no-same-permissions
test -d extracted/jdk-25.0.5+8 && test ! -L extracted/jdk-25.0.5+8
find extracted -type d -exec chmod 0755 {} +
find extracted -type f -exec chmod a+rX,go-w,u-s,g-s {} +
mv -T extracted/jdk-25.0.5+8 "$jdk_home"
test -z "$(find "$jdk_home" ! -uid 0 -print -quit)"
test -z "$(find "$jdk_home" ! -type l -perm /022 -print -quit)"
# Upstream internal symlinks are allowed only inside this protected tree.
while IFS= read -r -d '' link; do
  resolved=$(realpath -e "$link")
  [[ "$resolved" == "$jdk_home/"* ]]
done < <(find "$jdk_home" -type l -print0)
"$jdk_home/bin/java" --version
"$jdk_home/bin/javac" --version
"$jdk_home/bin/jlink" --version
SH
```

Expect both hashes `OK`, an accepted pinned signer, Java `25.0.5` / Temurin
`25.0.5+8`, `javac 25.0.5` and linker `25.0.5`. All checks must pass. Authentication
failure means no extraction; any later failure means **do not select/activate**
the destination. Retain the error and protected review directory. Inspect exact
partial paths before cleanup; never remove a JDK used by an installed unit.
For a retry use a fresh protected review directory and adjust its literal `cd`
path; do not bypass a failed check or reuse a partial destination.

## Select the TLS unit's executable

Follow [the TLS review/install procedure](remote-access.md#persistent-certificate-renewal)
to stage its helper/service/timer as root-owned reviewed files first. In that
review snapshot change **only** the service's Java executable as follows, then
review the complete resulting unit and record its new hash. The fixed arguments,
`UnsetEnvironment`, key permissions and all sandbox settings must remain intact.

```bash
sudo sed -i 's|^ExecStart=/usr/bin/java |ExecStart=/opt/stargate/jdk-25.0.5+8/bin/java |' /root/stargate-tls-renewal-review/stargate-tls-renewal.service
sudo grep '^ExecStart=' /root/stargate-tls-renewal-review/stargate-tls-renewal.service
sudo sha256sum /root/stargate-tls-renewal-review/stargate-tls-renewal.service
sudo namei -l /opt/stargate/jdk-25.0.5+8/bin/java
```

Expect exactly one `ExecStart`, beginning with that protected executable. A path
under `/home`, a writable ancestor, unresolved unit override or unexpected
executable is a stop condition. Check actual sandbox access before activating
certificate staging; these transient probes run version checks only:

```bash
sudo systemd-run --wait --pipe --collect --property=User=root --property=ProtectHome=true --property=ProtectSystem=strict --property=PrivateTmp=true --property=PrivateNetwork=true --property=NoNewPrivileges=true /usr/bin/env -i PATH=/usr/bin:/bin /opt/stargate/jdk-25.0.5+8/bin/java --version
sudo systemd-run --wait --pipe --collect --property=User=root --property=ProtectHome=true --property=ProtectSystem=strict --property=PrivateTmp=true --property=PrivateNetwork=true --property=NoNewPrivileges=true /usr/bin/env -i PATH=/usr/bin:/bin /opt/stargate/jdk-25.0.5+8/bin/javac --version
sudo systemd-run --wait --pipe --collect --property=User=root --property=ProtectHome=true --property=ProtectSystem=strict --property=PrivateTmp=true --property=PrivateNetwork=true --property=NoNewPrivileges=true /usr/bin/env -i PATH=/usr/bin:/bin /opt/stargate/jdk-25.0.5+8/bin/jlink --version
```

Expect the same versions and exit status zero. Continue the TLS guide's reviewed
installation. For an existing installation, first record whether its timer was
enabled/active, pause it and wait for any in-flight staging to finish naturally:

```bash
sudo systemctl is-enabled stargate-tls-renewal.timer
sudo systemctl is-active stargate-tls-renewal.timer
sudo systemctl stop stargate-tls-renewal.timer
sudo systemctl show stargate-tls-renewal.service -p ActiveState -p SubState -p Result -p ExecMainStatus
sudo systemctl list-jobs --no-pager
sudo cp -p --no-clobber /etc/systemd/system/stargate-tls-renewal.service /root/stargate-tls-renewal-review/previous.service
```

Proceed only with no pending service job and an inactive/failed service; investigate
old failures and leave the timer stopped on failure. Save any effective drop-ins
and retain the previous JDK too. Then use the TLS guide's unit installation,
`systemd-analyze verify` and `daemon-reload`; before its first service start
inspect the effective unit including drop-ins:

```bash
sudo systemctl cat stargate-tls-renewal.service
sudo systemctl show stargate-tls-renewal.service -p ExecStart -p ProtectHome -p ProtectSystem -p ReadWritePaths
```

Expect the selected `/opt/stargate/.../bin/java`, `ProtectHome=yes`,
`ProtectSystem=strict` and only the intended TLS output in `ReadWritePaths`.
Use the TLS guide's initial run, no-op, metadata and both-listener reload checks
before restoring the recorded scheduling intent; do not enable a previously
disabled timer. Keep the previous unit
and its qualified protected JDK for rollback. Do not roll back certificate files
or loosen private-key permissions to make a check pass.

Actual root ownership, systemd sandbox access and both live TLS listeners must
be checked on the installation. A downloaded JDK version string alone does not
establish that the privileged job can safely use it.
