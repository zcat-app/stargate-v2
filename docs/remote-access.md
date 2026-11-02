# Encrypted remote access

Stargate can expose an authenticated HTTPS browser proxy plus an HTTPS device
pairing/status API. Tor, I2P and Nym routing stay unchanged. The existing local
HTTP endpoints remain available on host loopback, including private administration.
The public API allows only pairing-code redemption and authenticated device status;
it rejects the administrator UI, controls and framework routes.

The extension uses the browser's native TLS proxy support. The server certificate
and private key stay on the server; users do not import a CA or need a VPN. TLS
protects browser-to-server transport. The server still sees devices, destinations
and HTTP content; destination HTTPS remains a separate end-to-end TLS connection
through CONNECT. This does not remove trust in the VPS.

Before connecting to a named Stargate server, a browser may resolve that server's
hostname using a resolver selected by browser or device settings. That resolver
can therefore see which server is being contacted; if that lookup is unencrypted,
observers on its network path may see it too. TLS to Stargate does not itself encrypt this earlier
lookup. This concerns the server hostname and does not establish that website
destinations are resolved locally. Browser, operating-system and secure-DNS
settings can affect the lookup path.

Enabling secure DNS does not guarantee that the Stargate hostname is hidden.
Firefox can still make a plaintext server-hostname lookup around restart, even
with strict DoH selected. Browser-wide DNS containment is not guaranteed.

## Certificate and ports

Use a hostname under your control with a normally trusted certificate. Point its
DNS directly to the VPS. An ordinary website reverse proxy/CDN must not sit in
front of the browser-proxy port: it may reject or reinterpret forward-proxy
requests and CONNECT. Stargate terminates TLS itself using the existing Java stack.
A website on port 443 can coexist with separate Stargate ports.

The examples use `gate.example.org`: API port **9443**, proxy port **9444**.
Replace the hostname and issuer paths with your own before installing anything.
A Caddy website can keep ports 80/443 while Stargate uses these separate ports.

Provision a leaf-first certificate chain and a matching RSA/EC key. The staging
helper converts the key to unencrypted PKCS8 and restricts it to the app's UID
10001. Run it with permission to read the issuer's key and set ownership. Example
for a Caddy certificate (never print or share key contents):

```sh
sudo /opt/stargate/jdk-25.0.5+8/bin/java --source 25 /usr/local/libexec/SyncTlsCertificate.java \
  --certificate /var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gate.example.org/gate.example.org.crt \
  --key /var/lib/caddy/.local/share/caddy/certificates/acme-v02.api.letsencrypt.org-directory/gate.example.org/gate.example.org.key \
  --output /srv/stargate/tls
```

Install the reviewed root-owned Java helper using the procedure below before
running that command; never run a writable checkout as root. The helper requires
a qualified root-controlled Java 25 JDK and `/usr/bin/openssl`.
The wizard's private operator JDK does not qualify: follow
[root JDK provisioning and selection](root-java-toolchain.md), including signature
verification and the service sandbox checks, before running the command. The
example above uses that procedure's protected `/opt/stargate` installation.

The output directory is mounted read-only into the app. Mount the directory,
not individual certificate files, so atomic file replacement is visible. A bad
or mismatched renewal does not replace the proxy's working TLS context. Netty
checks for replacements every five seconds; Quarkus every thirty seconds.
Both listeners validate that the certificate matches its private key. The manager's
TLS registry supplier validates the exact PEM bytes before Quarkus may replace its
working context; a structurally readable keystore alone does not establish a match.
Existing connections retain their negotiated TLS session. The manager validates each certificate/key snapshot through the Quarkus TLS registry before publishing it; the proxy performs the same RSA/EC key-match check. A mismatched renewal is rejected before replacing either working TLS context. Failed reloads are
reported without request data. An expired retained certificate will be rejected
by clients; retaining it is not an expiry workaround.

### Persistent certificate renewal

Caddy renews its own files; a one-time copy does not track that renewal. The
uninstalled [service](../manager/tls-renewal/systemd/stargate-tls-renewal.service)
and [timer](../manager/tls-renewal/systemd/stargate-tls-renewal.timer) reuse the
existing staging helper and the exact Caddy paths above. They issue no certificate,
change no Caddy configuration and restart no app. These instructions require an
operator with host root access; they do not claim the units have been installed.
For an existing installation of the earlier helper, use the complete
[Java cutover sequence](#existing-installation-java-cutover) below. The staging
and installation blocks that follow also cover a first installation.

Review the helper and both unit files from the intended project revision. Confirm
that the Caddy source path still belongs to the issuer in use, that its directories
are owned by root/Caddy without group/world write permission, and that the source
key has mode 0600 or stricter. Inspect metadata only; never print the key. Do not
relax key permissions to let the ordinary checkout user read it. A different Caddy
storage root, issuer directory, hostname, app UID/GID or output directory requires
reviewing and updating the service's fixed arguments and `ReadWritePaths` together.
Do not guess another source when these paths are absent.

Prepare a root-owned review snapshot from the reviewed checkout, without executing
its helper. These commands copy source and units only:

```sh
sudo install -d -o root -g root -m 0700 /root/stargate-tls-renewal-review
sudo install -o root -g root -m 0600 tools/SyncTlsCertificate.java /root/stargate-tls-renewal-review/SyncTlsCertificate.java
sudo install -o root -g root -m 0600 manager/tls-renewal/systemd/stargate-tls-renewal.service /root/stargate-tls-renewal-review/stargate-tls-renewal.service
sudo install -o root -g root -m 0600 manager/tls-renewal/systemd/stargate-tls-renewal.timer /root/stargate-tls-renewal-review/stargate-tls-renewal.timer
sha256sum tools/SyncTlsCertificate.java manager/tls-renewal/systemd/stargate-tls-renewal.service manager/tls-renewal/systemd/stargate-tls-renewal.timer
sudo sha256sum /root/stargate-tls-renewal-review/SyncTlsCertificate.java /root/stargate-tls-renewal-review/stargate-tls-renewal.service /root/stargate-tls-renewal-review/stargate-tls-renewal.timer
```

Record the project revision and matching hashes, and review those root-owned copies
before installing them. If `/usr/bin/java` is not an already qualified protected
Java 25 JDK, select the authenticated `/opt/stargate/.../bin/java` executable in
this root-owned service snapshot using [the root JDK procedure](root-java-toolchain.md#select-the-tls-units-executable),
then record the changed unit hash. Never point it at the wizard's private JDK;
`ProtectHome=true` also makes that location inaccessible. The root-owned snapshot
binds the later privileged run to the reviewed bytes even if the checkout changes. Check ownership, permissions and
symlinks of the destination parent directories with `namei -l`; the helper/unit
parents must be root-owned and must not be writable by ordinary users. Likewise
`/srv` and `/srv/stargate` must be root-owned and not group/world writable. Create
missing directories with those properties, without changing an existing deployment
directory's ownership blindly. The TLS output directory must already exist for the
service's sandbox; its intended owner/group is 10001:10001 and mode 0750. Its two
staged files must have mode 0600 and that same owner/group.
The output's immediate parent must not be group/world writable, including sticky
directories such as `/tmp`. A root-owned sticky directory may be an ancestor of
a separate protected parent. Directory symlinks are refused. The Java program
uses secure directory operations and stages private files before replacing the
two final names; it does not follow deployment-file symlinks to repair metadata.

After that review, install the selected root-owned bytes:

```sh
sudo install -d -o root -g root -m 0755 /usr/local/libexec
sudo install -o root -g root -m 0644 /root/stargate-tls-renewal-review/SyncTlsCertificate.java /usr/local/libexec/SyncTlsCertificate.java
sudo install -o root -g root -m 0644 /root/stargate-tls-renewal-review/stargate-tls-renewal.service /etc/systemd/system/stargate-tls-renewal.service
sudo install -o root -g root -m 0644 /root/stargate-tls-renewal-review/stargate-tls-renewal.timer /etc/systemd/system/stargate-tls-renewal.timer
sudo systemd-analyze verify /etc/systemd/system/stargate-tls-renewal.service /etc/systemd/system/stargate-tls-renewal.timer
sudo systemctl daemon-reload
sudo systemctl cat stargate-tls-renewal.service
sudo systemctl show stargate-tls-renewal.service -p ExecStart -p ProtectHome -p ProtectSystem -p ReadWritePaths
# Stop if the effective Java path or sandbox differs from the reviewed unit.
sudo systemctl start stargate-tls-renewal.service
sudo systemctl show stargate-tls-renewal.service -p Result -p ExecMainStatus
sudo journalctl -u stargate-tls-renewal.service -n 10 --no-pager
```

Run commands separately and retain each exit status. Verify the installed helper
and unit hashes against the reviewed snapshot. An initial successful run reports
JSON with `changed` and a certificate SHA-256; it does not disclose key bytes. A
successful no-op reports `changed: false`. Check that the app's existing read-only
**directory** mount resolves to `/srv/stargate/tls`, then observe the new certificate
on both configured TLS ports after allowing their reload intervals. A successful
staging job alone does not prove an app reload. Only after a successful initial
stage and reload check enable the schedule:

```sh
sudo systemctl enable --now stargate-tls-renewal.timer
sudo systemctl list-timers stargate-tls-renewal.timer --all
```

The timer checks hourly with up to five minutes of randomized delay and one minute
of timer accuracy. `Persistent=true` catches a missed calendar activation after
downtime; it cannot renew while the host is down. Each activation runs the helper
once, with no retry loop or automatic restart. The service allows 30 seconds before
termination, followed by at most five seconds of stop grace, and kills remaining
processes in its cgroup. The root job uses a protected Java 25 source program,
clears Java option/classpath environment overrides, reads only the existing
issuer files, has no network access and can write only the TLS output directory
(plus its private temporary directory). The next scheduled activation rechecks the
source. Repeated errors or imminent certificate expiry require operator attention;
inspect the service result and journal, and the timer's next activation.

An existing privileged issuer deployment hook may instead run
`/usr/bin/systemctl start stargate-tls-renewal.service` after a completed renewal.
Use the same installed service; do not grant Caddy general root access or configure
a new hook mechanism merely for this copy. The hourly timer is sufficient without
changing Caddy. Systemd serializes activations of this named service. Do not run
the helper separately at the same time.

#### Existing installation: Java cutover

Use this sequence when replacing an installed certificate-staging service. First
stage and review the helper, service and timer using the root-owned snapshot
above, including the protected Java executable and your actual issuer paths.
Record the existing timer's enabled/active state. Do not replace the previous
snapshot or backup to rerun an uncertain cutover.

```sh
sudo systemctl is-enabled stargate-tls-renewal.timer
sudo systemctl is-active stargate-tls-renewal.timer
sudo sha256sum /root/stargate-tls-renewal-review/SyncTlsCertificate.java /root/stargate-tls-renewal-review/stargate-tls-renewal.service /root/stargate-tls-renewal-review/stargate-tls-renewal.timer
sudo systemctl stop stargate-tls-renewal.timer
sudo systemctl show stargate-tls-renewal.service -p ActiveState -p SubState -p Result -p ExecMainStatus
sudo systemctl list-jobs --no-pager
```

Wait for any active staging job to finish naturally. Proceed only when there is
no pending job and the service is inactive; investigate a failed service first.
The printed hashes must match the reviewed root-owned snapshot. Save effective
unit drop-ins separately if present. Back up the previous service without
overwriting an earlier backup:

```sh
sudo test ! -e /root/stargate-tls-renewal-review/previous.service
sudo cp -p --no-clobber /etc/systemd/system/stargate-tls-renewal.service /root/stargate-tls-renewal-review/previous.service
```

Run the helper/unit installation block above, then run the service again for a
no-op check and compare installed files with the reviewed snapshot:

```sh
sudo cmp /root/stargate-tls-renewal-review/SyncTlsCertificate.java /usr/local/libexec/SyncTlsCertificate.java
sudo cmp /root/stargate-tls-renewal-review/stargate-tls-renewal.service /etc/systemd/system/stargate-tls-renewal.service
sudo cmp /root/stargate-tls-renewal-review/stargate-tls-renewal.timer /etc/systemd/system/stargate-tls-renewal.timer
sudo systemctl start stargate-tls-renewal.service
sudo systemctl show stargate-tls-renewal.service -p Result -p ExecMainStatus
sudo stat -c '%u:%g %a %n' /srv/stargate/tls /srv/stargate/tls/server.crt /srv/stargate/tls/server.key
sudo journalctl -u stargate-tls-renewal.service -n 8 --no-pager
```

Expect silent successful comparisons, `Result=success`, `ExecMainStatus=0`,
owner/group `10001:10001`, directory mode `750` and both files mode `600`.
A repeat with unchanged issuer files should report `changed:false`. Verify both
TLS listeners with normal hostname/certificate validation after their reload
intervals. Restore scheduling only after success and only if it was previously
active:

```sh
sudo systemctl start stargate-tls-renewal.timer
sudo systemctl list-timers stargate-tls-renewal.timer --all
```

Do not enable a previously disabled timer. On failure, leave scheduling paused,
retain the previous unit and inspect the result before recovery. Do not roll back
certificate files or loosen permissions. This changes only the host staging job;
no app restart or image rebuild is required.

Invalid, expired, oversized or mismatched source files and loose source-key
permissions are rejected before either deployment file is replaced. A source pair
changing during the read may fail validation; the helper reads each input once,
bounds each snapshot to 64 KiB and validates those exact bytes through OpenSSL
stdin. A later path replacement cannot substitute a different pair for validation.
The next activation retries the current pair. Publication uses two atomic file
replacements. If a reader catches
the brief mismatch, or the job is interrupted between replacements, the app keeps
its previous working TLS context and a later successful stage repairs the pair.
This is not an expiry workaround. Disabling the timer with
`sudo systemctl disable --now stargate-tls-renewal.timer` stops future scheduled
copies without deleting the staged certificate or changing the running app.

## Generate deployment configuration

Use compatible prepared images from [the existing container procedure](../containers/README.md).
Keep the existing Compose project name and environment file when adding remote
access; they identify the current state volumes, credentials and router identities.
Include every original pre-remote Compose input and override, including
`compose.nym.yaml`, image/volume overrides and all selected environment files.
Do not feed an already generated remote configuration back into the wizard.
Run as the operator from the checkout, **without sudo**:

```sh
bash tools/setup-wizard.sh --preview
# Check the recap, then repeat the same choices to prepare the file:
bash tools/setup-wizard.sh
```

Choose **Existing installation**, enter its exact project name, ordered sources
and environment-file paths. Blank ends each file list. Enter the existing HTTPS
device API origin, public TLS proxy port, loopback manager host port, loopback
plaintext proxy host port, staged certificate directory and a **new** output path.
All four ports must differ. The default output is
`.local-setup/compose.remote.yaml`; its directory is private (0700) and the file
is operator-owned (0600). The [wizard guide](operator-setup-wizard.md) describes
each choice and the new-installation defaults.

Preview writes nothing and runs no Docker or sudo. Generation first tries an
unprivileged metadata check. If traversal of the UID-10001 TLS directory is
denied, it explains and invokes only `sudo -- /usr/bin/stat -c '%f %u %a' --`
with the selected directory, `server.crt` and `server.key` as three arguments.
Your normal VPS sudo password may be requested in the terminal; do not share it.
This checks metadata without opening the key or changing permissions. Never run
the entire wizard with sudo and never loosen the directory/key permissions.
The directory and both files must belong to UID 10001, with directory mode
0750 or 0700 and regular files mode 0600 or read-only 0400 (no symlinks).
Use the reviewed staging procedure above if a check fails.
Cancellation, failed metadata/Compose checks and existing outputs do not
replace an earlier configuration. No new final file is published on failure;
an empty private output directory may remain. Correct the input and rerun with
a fresh output name. Do not deploy a leftover `.stargate-setup.*` staging file.

Generation starts nothing. It retains images, resolved state-volume mappings,
Nym requester/settings and capacity from the selected sources. It replaces app
publications with the four reviewed endpoints and clears native port publications.
Review the full output privately, especially exact volume names, Nym state **and**
secret mounts, images, networks and custom overrides. A changed Nym requester
environment value does not rewrite an already initialized client's provider.

Use the exact validation command printed by the wizard. For its default output
and **after replacing the project placeholder**, that is:

```sh
stargate_project='REPLACE_WITH_EXISTING_PROJECT_NAME'
stargate_config="$PWD/.local-setup/compose.remote.yaml"
docker compose --project-name "$stargate_project" --file "$stargate_config" config --quiet
```

Success exits zero without output. An error means stop and correct the inputs;
do not apply it. A resolved YAML or older JSON file contains resolved settings:
editing `.env` later does not update it. Regenerate from original sources instead.
Starting/replacing a persistent deployment is a separate deliberate operation
that can interrupt users. Only after reviewing the selected images and all seven
volume roles, use the same file/project:

```sh
docker compose --project-name "$stargate_project" --file "$stargate_config" up -d --no-build --pull never
```

Permit the chosen TLS ports in the VPS/provider firewall. Never publish the
plaintext manager, plaintext proxy, router SOCKS/control ports or Docker socket.
Administration remains at its existing loopback URL; the operator can use an SSH
tunnel for administration. Ordinary users do not need SSH. If the `STARGATE_PUBLIC_ORIGIN`
setting is accidentally removed from an already configured remote volume, startup
fails rather than silently downgrading access.

## Pair a device

Follow [the browser quick-start](getting-started.md) for installation, Firefox
permissions and Brave Tor settings before issuing a short-lived code.

The operator creates a one-time device code through the existing private manager.
The user opens Stargate's extension and enters `https://gate.example.org:9443` and that
code. The HTTPS response supplies the TLS proxy endpoint and independent device
credentials. Codes default to five minutes; the operator can choose 24 hours for
an invitation. Anyone holding a code can pair a device, so deliver it privately;
the longer option increases the exposure window. The private manager lists pending
invitations without redisplaying their codes and can cancel them. A manager restart
invalidates all pending codes. Issue a separate code per device; revoke a paired
device separately.

Only the configured proxy receives proxy credentials. The extension rejects
remote HTTP and status-response downgrades, verifies effective settings, and checks
setting ownership before releasing remote credentials. Firefox additionally rejects
an explicitly mismatched proxy transport reported with an authentication challenge.
The enrollment/status origin has an exact bypass so recovery works while the proxy
is stopped. Other destinations on the same hostname/other ports still use the
selected Stargate route. Local-loopback bypass behavior is retained.

Firefox uses a deterministic embedded PAC with a single HTTPS proxy and no direct
fallback for routed destinations. It has no remote PAC download or DNS helper.
Browser PAC load failures and an absent/disabled extension are outside a universal
kill-switch guarantee. Brave uses a fixed HTTPS proxy. Firefox currently requires
temporary installation and Brave unpacked installation; see [extension setup](../extension/README.md).
