# Shell operator setup wizard

Run from the checkout:

```sh
bash tools/setup-wizard.sh --preview
```

Preview asks the questions and shows a recap. It writes nothing and does not run
Docker. To prepare a private configuration file, run without the flag:

```sh
bash tools/setup-wizard.sh
```

Configuration preparation is **Bash only**, using Compose's renderer and standard
Linux utilities. Before generation it checks Docker,
Compose and daemon access. Missing prerequisites offer the separate guided setup
with its own confirmation; the configuration must then be rerun.

Use `bash tools/setup-wizard.sh --prerequisites` for
[guided checks and verified host-tool installation](setup-prerequisites.md), or
`--check-prerequisites` for read-only Docker checks. Java/Maven are needed only
for selected operator/build profiles, not to configure already prepared images.
Preview remains write-free and does not run Docker or installers.

## What must already be ready

- Linux with Bash 4 or later and standard GNU utilities (`stat`, `realpath`,
  `mktemp`, `grep`, `mkdir`, `ln`, `rm`).
- For generation, Docker Compose supporting `!override`/`!reset` (Compose 2.24.4
  or later; actual proof used 5.1.4), and your reviewed source Compose files.
- Compatible prepared app/Tor/I2P/Nym images for later deployment. The wizard
  does not build, pull or validate image bytes.
- Your selected Nym public-requester setting in the intended environment inputs.
  No provider is selected or contacted by the wizard.
- A staged certificate directory containing regular `server.crt` and `server.key`
  files (not symlinks). Directory and files must belong to app UID 10001, directory
  mode 0750 or 0700 and file mode 0600 or read-only 0400. Preserve the staging
  procedure's UID/GID 10001:10001, directory 0750 and file 0600 permissions.
- If the operator cannot traverse that private directory, `sudo` permission to
  run `/usr/bin/stat` for its metadata. No extra language runtime is needed.

TLS checks here are metadata checks only. The script never opens key contents,
issues a certificate, validates the certificate/key pair or proves live TLS.
Certificate staging and native initialization remain separate procedures. The
wizard never asks for administrator tokens or passphrases. Run it as the operator,
not with sudo (root execution is refused). If an unprivileged metadata check fails,
it explains and runs only `sudo -- /usr/bin/stat -c '%f %u %a' --` with the selected
directory and two file paths. Sudo may request your normal VPS password in the
terminal. It never runs the checkout, Compose or a shell as root, and it never
changes ownership or permissions. Denied/cancelled sudo or bad metadata stops
generation without publishing. Do not share the password or relax permissions.
It is not a clean-host installer.

Nym generates its local key passphrase during first initialization; keep
`nym-data` and `nym-secrets` together. This passphrase is not a payment credential
or NymVPN login. The wizard does not initialize or rotate it.

## The journey

1. **Existing or new installation.** Existing is the default. Supply the exact
   project and every original pre-remote Compose source/override in order. Use
   source files, not an already generated remote configuration. Enter file paths
   one per line; blank ends each list. Include all selected environment files,
   including `.env` when used; do not paste their contents.
2. **New defaults.** New installations suggest project `stargate-v2`, the existing
   `compose.yaml` plus `compose.nym.yaml`, API port 9443, TLS proxy port 9444,
   loopback manager port 9080, loopback proxy port 8881 and `/srv/stargate/tls`.
   Supply a hostname you control. All three network routes remain selected.
3. **Existing endpoints.** Enter the current public HTTPS API address, TLS proxy
   port, both loopback host ports and staged certificate directory. These are
   not guessed. The four host ports must differ; conflicting values can be
   corrected without restarting the whole questionnaire.
4. **Output.** The default is `.local-setup/compose.remote.yaml` in the checkout,
   ignored by Git. Existing outputs prompt for another filename. A custom parent
   directory must be yours, mode 0700 and not itself a symlink. The script can
   create that immediate directory, but not missing ancestors. Protect custom
   outputs and keep them out of Git yourself.
5. **Recap and confirmation.** Check the ordered inputs, project, endpoints,
   certificate path and output. Preview ends here. Declining confirmation also
   creates no files and runs no command. Confirming performs configuration
   preparation only.

No new connection/memory defaults are chosen. Capacity, images, state-volume
mappings and other inherited settings come from the chosen source inputs. If no
environment files are selected, Compose's default `.env` handling and shell
settings can still apply. Use the same intended environment when preparing the
configuration, then review the resolved result privately.

## What generation changes in the new file

The script creates a private temporary override and lets Compose merge/render it.
It does not modify your source files. The temporary override:

- Sets the HTTPS API/proxy settings and keeps ordinary web on Nym.
- Replaces the app's port publications with exactly the four reviewed endpoints:
  plaintext manager/proxy on `127.0.0.1`, plus the two public TLS ports.
- Clears explicit native Tor/I2P/Nym port publications.
- Adds the read-only certificate **directory** mount with automatic host-directory
  creation disabled.

It then validates the resolved file and requires all four services before
publishing. File publication refuses overwrites, including a collision after
the recap. The final file is mode 0600 in a mode-0700 directory. Generation failure
leaves no new final file; an empty private parent may remain. A hard interruption
can leave private staging files, which must not be treated as successful output.

The script does not certify arbitrary custom overrides. Review networks,
`network_mode`, privileges, mounts, actual images, volume names and all resolved
settings before using the output. Clearing explicit port entries alone does not
establish isolation for a custom host-network deployment. A successful render
also does not prove free host ports, usable images, matching restored state or
network/destination availability.

## After preparation

The wizard prints the exact read-only validation command for the resolved file
and project. Review its full contents privately; resolved environment values can
be sensitive. Use that same file/project with the [operator guide](operator-guide.md)
for a deliberately chosen startup, private SSH administration and invitations.
The wizard does not start/stop containers, change firewalls, stage keys, create
pairings, install timers, send SimpleX messages or publish to a store.
