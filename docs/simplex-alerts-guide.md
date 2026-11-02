# Understand Stargate's SimpleX alerts

These are messages from the scheduled **update checker**. They describe changes
to release information, security notices and selected server-software reports.
They do not measure whether websites are reachable. The checker never installs
updates, restarts Stargate or accepts chat commands.

## What each message means

| Message | Meaning | Your next action |
| --- | --- | --- |
| **Update check needs attention** | One or more checks could not obtain a usable result. This can involve a release source, advisory source or the selected running-image evidence. The message identifies the incomplete check. | Inspect the update-check service and logs below. Establish the cause before changing configuration. |
| **Software update information changed** | Published release information or the selected proxy package differs from the previous observation. A displayed version is upstream information, not a verified installed version. | Compare the release with the installed software, then review compatibility, signatures and retained patches before preparing an upgrade. |
| **Security information changed** | The selected server-software/security report changed, or the checker saw new/changed security notices. This can follow an operator upgrade or a change in advisory data. A security incident or affected deployment has not been established. | Review the selected report and relevant notices. Determine which component/version is involved and whether it applies before changing software. |
| **Update checks working again** | A previously incomplete check obtained a usable result again. This refers to the checker, not a website or network route recovering. | No action is needed for that recovery alone. If the same message also reports changed software/security information, review those changes. |

“Newly seen” means first seen by this checker's retained history; a notice may
have been published earlier. “Changed” means the observed notice changed.
Neither count establishes that your server has that many vulnerabilities.

The server report includes selected running-image IDs, supplied scans/extracted
files and advisory queries. It is partial evidence with explicit limitations.
An image replacement, inventory change or advisory-data change can produce a
report-change message. The alert alone does not identify which of those caused
it. See [runtime evidence and limits](java-monitor.md#runtime-security-evidence).

## Examples

These are formatter examples; they are not messages sent as test notifications.

```text
Stargate: update check needs attention
Could not check: server software report.
Action: check the update-check logs on the server.
Browsing availability was not checked.
```

This means the checker could not validate the selected server report. It does
not tell you to restart the proxy.

```text
Stargate: software update information changed
Release information changed: Tor 0.4.9.15-1~noble+1.
Action: compare with installed versions before upgrading.
Security impact on your server needs review.
Updates are not installed automatically.
```

Release information can change without the version changing, for example when
published package metadata changes. This is not a signature-verification result.
The optional [verified-upgrade action](verified-upgrades.md) needs a separately
configured host updater, pinned signer and compatible signed release. An alert
does not mean an upgrade is ready to install with one click.
```text
Stargate: security information changed
The server software/security report changed.
Newly seen security notices: Netty 2.
Changed security notices: Netty 1.
Action: review all listed changes.
Security impact on your server needs review.
Updates are not installed automatically.
```

```text
Stargate: update checks working again
Checking works again: server software report.
No action needed for these recovered checks.
This reports check recovery, not browsing availability.
```

## Which component is named?

| Alert name | What it refers to |
| --- | --- |
| Nym | Mixnet-client release information; ordinary web uses Nym. |
| I2P | i2pd router release information. |
| Tor | Tor/GeoIP package information from the selected repository. |
| Java | The selected Temurin Java 25 release information. |
| Quarkus | The manager's selected Quarkus platform release line. |
| Proxy package | The explicitly selected JAR file and its embedded Netty metadata. Its association with a deployed image must be checked separately. |
| Backup tool | The selected age encryption-tool release information. |
| Netty / Quarkus security notices | Published repository security notices; applicability needs review. |
| Server software report | Selected running-image, inventory and security-query evidence. |

## Check the service

Log into the VPS as the same operator account that owns the daily monitor. These
commands inspect it without starting an update, resending a message or changing
the proxy:

```sh
systemctl --user show stargate-daily-alert-consumer.service \
  -p ActiveState -p Result -p ExecMainStatus
systemctl --user list-timers stargate-daily-alert-consumer.timer --all
journalctl --user -u stargate-daily-alert-consumer.service -n 20 --no-pager
```

Use that installation's protected monitor configuration and selected recorder
directory when inspecting reports. The [Java monitor guide](java-monitor.md)
describes those paths, inputs and outcomes. Source HTTP/rate-limit failures and
image/evidence mismatches require different corrections; establish which happened.
Keep profiles, credentials and complete private configuration out of chat/Git.

An enabled timer does not prove the last collection succeeded. Exit 2 means the
selected observations were incomplete; exit 4 means attention is required, such
as an uncertain pending send or refused operation. Local SimpleX acceptance is
not phone-delivery confirmation. Preserve pending events, attempt markers and
receipts. Do not delete them, reset the ledger or repeatedly start the service
to force a notification. Follow the monitor's recovery instructions.

The existing manager can display sanitized collection/consumer outcomes when
its snapshot mounts are configured. It does not currently display detailed
security notices. Optional upgrade controls require their own configured host
updater and manager mounts; installing the extension alone enables neither.

## Quiet periods and phone size

Initial successful baselines and unchanged checks stay quiet. Failures and
recoveries notify on state transitions, not every daily repetition. No message
does not establish successful monitoring: the checker cannot send when it or
the sender is unavailable.

Messages retain the existing 768-byte phone-digest budget. Long version details
may be omitted to fit, while every affected component and notice count remains.
Full current observations remain in the private reports; retain a copy when
investigating an alert. Only fixed labels, bounded public version
fields and counts enter these messages; browsing destinations, credentials,
headers and payloads do not. Already pending messages retain their original text
and event identity, so one old-format message may still complete after an upgrade.
