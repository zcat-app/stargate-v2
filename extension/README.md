# Stargate browser extension

## Distribution status

A Mozilla-signed permanent-install package is not available yet. Released Firefox and Brave packages
are 0.8.8. Firefox uses temporary loading until Mozilla-signed distribution is
available; Brave uses unpacked installation and manual updates from GitHub.
See [downloads](../docs/release-readiness.md) and
[privacy policy](../docs/privacy-policy.md).

For everyday use, start with the [user guide](../docs/user-guide.md). Server
operators have a separate [operator guide](../docs/operator-guide.md). The
technical details below explain settings, routing and their limits.

Start with the bundled [Firefox / Brave quick-start](src/quick-start.html). It is
also available from the extension’s setup page and Help, without an internet
request. It covers the unsigned GitHub RC packages: Firefox uses temporary loading, and
Brave uses unpacked installation.

The current [container setup](../containers/README.md) pairs through the
server-rendered manager UI and advertises the published host proxy port.

Pair a stable Firefox or Brave profile using your operator's HTTPS server address
or a local manager. Browse through the normal address bar: ordinary web uses Nym,
`.onion` uses Tor and `.i2p` uses I2P when enabled in the server deployment.

## Build and load

Building uses the project's Java 25 **JDK**, with no Python, npm installation,
bundler or downloaded packaging dependencies. End users installing the prepared
extension do not need Java:

```sh
bash extension/package.sh
```

This writes the same Firefox XPI, Brave ZIP and unpacked folders under
`extension/target`. Manifests are explicit source files in `extension/manifests`;
both browser versions must agree. Packages remain unsigned. See the
[packaging migration and checks](../docs/extension-packaging.md).

For Firefox, open `about:debugging`, select **This Firefox → Load Temporary
Add-on** and select `extension/target/stargate-firefox.xpi`. In `about:addons`,
allow Stargate to **Run in Private Windows**: Firefox's proxy-settings API
requires this permission even when configuring regular windows. Regular windows
are the verified use case. Temporary unsigned add-ons disappear when Firefox
exits; permanent installation in stable Firefox requires Mozilla signing. The
RC package is not Mozilla-signed. Source manifests declare 0.8.9; the released package remains 0.8.8.

For Brave, open `brave://extensions`, enable **Developer mode → Load unpacked**
and select `extension/target/brave`. In privacy settings switch off both
**Private window with Tor** and **Only resolve .onion addresses in Tor windows**
for this dedicated profile. Brave's built-in Tor is separate from the external
Tor client used by Stargate. The full Brave process restart and actual worker
suspension/recovery were verified with the unpacked extension.

**Do not use Brave private windows with Stargate.** With Stargate's incognito
access disabled, a controlled private page connected directly over a TCP socket
owned by Brave, while the regular-window control correlated to Nym. Private
traffic can bypass Stargate even when its regular-window proxy status is
**Applied by Stargate · regular windows**. Allowing the extension in private
windows has not been verified as protection. Use regular windows. The extension
shows this warning in its Brave popup and options regardless of pairing, proxy
status or incognito permission; the warning itself does not block traffic.

## Pair and use

1. Ask the person who runs your server for its Stargate address and a one-time
   access code. For a local installation, the operator creates the code in the
   [manager](../manager/README.md). Ordinary users need no manager login or account.
2. Select **I have an access code**. Setup opens in a tab so switching to your
   messaging application does not close it. Complete **1. Prepare your browser**:
   Firefox reports its observed permission; Brave’s Tor options are a manual
   check. Ask for a fresh code when ready, then use **2. Connect this browser**.
   The proxy port is supplied automatically. **3. Browser settings applied**
   reviews the actual server and preparation status; it does not test destination
   access. IPFS handler setup is optional and available from that recap.
3. If access was saved but Firefox needs its permission or a required setting is
   controlled elsewhere, finish setup and apply settings again. A new code is
   unnecessary for an apply failure. Codes are single-use and expire after the
   operator-selected five minutes or 24 hours; saved access does not expire with
   the code. Pending codes are invalidated by a manager restart.
4. Use your normal browser address bar. Fully quit and reopen the browser before
   sensitive browsing: existing connections may keep their previous route.

Remote addresses require HTTPS with a normally trusted certificate. The local
exception is a numeric `http://127.0.0.1` origin. Paths, credentials, query strings
and fragments are rejected. See [remote access](../docs/remote-access.md). The
server API and loopback retain their existing routing exceptions. Ordinary web
is refused if the deployment has no Nym route; an unavailable route does not fall
back to a different network or direct connection.

## Popup, settings and appearance

The small toolbar popup has one main action and **Settings**, **Connection details**
and help. Its header and the full settings page show the installed version,
read directly from the extension manifest. Settings opens a normal tab. Clear (deep blue), Stargate (seven red
chevrons and a water-like center) and Observatory are bundled locally, with no
remote fonts or theme downloads. From version 0.8.8, Stargate is the default for
new profiles and invalid/missing appearance settings; saved Clear, Stargate or
Observatory choices are preserved. Appearance, reduced-motion preference and
**Advanced mode** are stored independently from pairing in this browser profile.
Advanced mode reveals the existing local-network, IPFS gateway and device-access
controls. IPFS opening remains a separate tool.

The toolbar's shape, badge and tooltip distinguish setup, off, working, settings
on, attention and unknown. An active icon means confirmed browser settings for
regular windows; it is not a current website-access or all-network health check.
Server observations are independent and show their observation time. Cached
observations are labeled; changing a theme does not test or change a network.

**Disconnect** asks before restoring previous browser settings, which may connect
directly. In version 0.8.1 the dialog offers **Stay connected** (cancel) and
**Disconnect**, and explicitly says saved access is kept. Connect can reuse that
access without a new code. From version 0.8.4, **Disconnect** also remains
available beside recovery actions when Stargate still owns proxy or privacy
settings, including unavailable server status and rejected access. Cancelling
keeps settings on; confirming restores previous settings and keeps saved access.
Completion messages describe the specific result and do not claim release when
ownership could not be confirmed. **Disconnect and forget saved access** first
releases settings and checks ownership; it keeps credentials if release fails or
cannot be confirmed. It does not revoke server-side access. The legacy Forget
action still leaves settings in place, and the UI now exposes a reset path when
access is missing but Stargate settings remain. No automatic access-request
backend is included: **Need access?** explains the private-code exchange.

The design targets accessible controls, keyboard interaction, visible focus,
reduced motion and responsive layouts. It does not claim complete WCAG AAA
conformance. Fixed invitation expiry and complete assistive-technology assessment
remain explicit limitations. Version 0.8.5 adds field-linked IPFS validation errors,
clean accessible theme names and predictable confirmation keyboard navigation.
Code expiry is unchanged. See [appearance and motion settings](../docs/customization.md).

## Direct local-network access

**Direct local-network access**, under Settings → Advanced mode, is off by default. After applying Stargate, use
**Enable direct private addresses** to bypass Stargate profile-wide for literal
private IPv4 destinations in `10.0.0.0/8`, `172.16.0.0/12` and `192.168.0.0/16`.
The browsers also match equivalent IPv4-mapped IPv6 literals such as
`[::ffff:192.168.1.1]`. Other IPv6 destinations and hostnames, including local
names, keep their existing routing. This feature performs no name resolution or
network discovery. Ordinary public web, onion and I2P routing stays unchanged.

These requests connect directly from the browser to the destination, outside
Stargate. The UI shows the saved choice and the confirmed browser bypass
separately. Unknown, conflicting or differing settings do not establish an
applied configuration. A failed enable is not saved and attempts to remove any
partial bypass while Stargate owns the setting. Disabling saves the off choice
before changing the browser so recovery will not restore the bypass; if that
change fails, check the browser bypass display and use Apply proxy to retry.

The choice persists with the pairing through restart and re-pairing. Forgetting
pairing removes that choice but keeps current browser settings. Release restores
the browser's previous routing. Changes affect new connections; close existing
connections or fully restart the browser to end their previous route.

Enabling direct access is not a browser-wide firewall guarantee. Hostname
resolution, existing connections and browser contexts have separate boundaries;
use the displayed effective bypass state rather than assuming every address
form behaves identically.

## Native IPv6 address URLs

Native IPv6 literals are not supported proxy targets. Requests receive
`400 INVALID_TARGET`. This rejection is not browser-wide IPv6 containment:
private windows, configured bypasses and failed connection attempts remain
outside that claim. The IPv4 and IPv4-mapped private-address opt-in above is a
separate direct-access bypass.

## Device isolation and revocation

The extension displays its device identifier. Match it in the authenticated
manager's **Paired devices** list to revoke it. New proxy requests and the status
grant are then rejected; existing connections close after the proxy's credential
refresh (normally within one second). Other devices keep their existing streams.
The manager and proxy must reference the same private configuration file.

Older configured credentials remain valid on upgrade and may be shared. Pair
each device again, then explicitly revoke the old credential. Copying a saved
pairing copies its identity; this is a bearer credential, not hardware binding.
Firefox may show its native proxy-authentication prompt after revocation. Cancel
it and use a new pairing code in the extension; do not enter the administrator key
into a proxy prompt.

Tor partitioning is per device credential, not per website. Nym uses a shared
client identity. With per-device I2P isolation configured, each credential uses
its assigned SOCKS port and destination keys; the I2P router and host remain
shared. The proxy does not hide destinations
from its administrator, scrub website cookies or prevent browser fingerprinting.
DNS/bootstrap and direct-connection exceptions mean this is not browser-wide
leak containment. See [privacy limits](../docs/user-guide.md#what-privacy-this-provides).

## Read IPFS through Nym

With Nym enabled and Stargate applied, you can enter `ipfs://CID/path` directly
in the address bar in a regular window. In Firefox, accept its **Open Link**
prompt for **Stargate IPFS through Nym**. If Firefox offers **System Handler**
instead, cancel it and open `about:preferences#downloads`. Under **Files and
applications**, search for **ipfs** and set its **Action** to **Use Stargate IPFS
through Nym**, then retry. The choice keeps saved pairing. If Stargate is absent, investigate handler
registration rather than choosing an external executable or resetting the profile.

These Firefox steps are also inside **Settings → IPFS address-bar links**.
**Help → Set up IPFS address-bar links → Open IPFS setup instructions** opens
the relevant browser instructions.

In Brave, first open **Stargate →
Settings → IPFS address-bar links → Enable IPFS links**, then choose **Allow**
in the browser prompt. Keep that tab open until you have chosen. Browser approval
is separate from pairing, and the button cannot confirm whether it was granted;
if necessary, inspect `brave://settings/handlers`.

Approve the handler before typing IPFS addresses: an unhandled address may be
sent to your search provider. Registration does not apply proxy settings or
override browser conflicts. With Stargate released, access missing or required
observations unavailable, the handler stays local and explains recovery. It does
not select another network, gateway or direct access. Private windows remain
unsupported. No local IPFS node or helper application is installed.

Address-bar handling replaces the current tab with the configured HTTPS gateway.
Alternatively, paste a CID or `ipfs://CID/path` into the extension's **IPFS tool**;
that existing opener still uses a new tab. Both use the same validator and fresh
proxy/privacy/manager/Nym checks. The local protocol handoff fragment is cleared
before resolution; input is not saved or logged. Browser history/cache may still
retain addresses. See [the address-bar verification](../docs/ipfs-address-bar.md).

The default gateway is `https://ipfs.dget.top`; **IPFS gateway → Save gateway**
changes it locally for this browser. An alternative verified during development
is `https://ipfs.storry.tv`. Public services are best effort and can change.

The setting is the full subdomain base: for `https://ipfs.example.org`, the
result is `https://CID.ipfs.example.org/path`. Your own gateway needs compatible
subdomain resolution, wildcard DNS and TLS. A path gateway URL such as
`https://example.org/ipfs/` is not accepted. Switching gateways affects new opens;
existing tabs retain their original gateway URLs.

Supported inputs are CIDv0 dag-pb and lowercase base32 CIDv1 raw/dag-pb with
SHA-256. Other encodings, IPNS and publishing are outside this reader. Invalid
input, released/changed proxy settings, disabled Nym or an unavailable manager
prevent the opener from navigating. An unavailable Nym transport fails at the
proxy; there is no direct or other-network fallback. External browser-setting
changes after opening remain outside this feature's protection.

Stargate stores the gateway address, not entered CIDs or paths. Forgetting pairing
keeps this gateway preference. Browser history/cache can retain opened URLs.
The gateway and Nym exit see the CID; the gateway is trusted to serve content,
which Stargate does not independently hash-verify. Different CIDs use different
origins, but sibling-domain cookies and legacy domain relaxation depend on the
gateway's public-suffix registration and response policies. No local IPFS node
is installed by the reader.

**Release settings** clears Stargate's setting and restores the browser's prior
routing. That routing may connect directly. **Apply proxy** explicitly reapplies
and checks the current setting. Changed bypass lists stop displaying “Applied”,
and another extension or browser policy is not overwritten. Manager loss leaves
the configured proxy in place; the manager/process/router observations become
unknown instead of retaining an old ready state.

The legacy **Forget saved pairing** action removes local credentials while leaving
proxy settings in place. The new UI offers the checked **Disconnect and forget**
sequence instead, and exposes retained-setting recovery. Neither action revokes
the server-side device or clears browser authentication caches. The operator can
revoke the device in the authenticated manager. Private windows are unsupported;
Brave private traffic can connect directly as described above.

## Credentials, permissions and status

The extension receives the selected profile's proxy credential and a separate,
purpose-bound read-only manager grant. It never receives the manager's admin
token. The grant is bound to the real extension origin and configured profile;
changing the manager or profile token invalidates it. Single-use codes are kept
only in manager memory. Existing grants survive a manager restart with unchanged
configuration. Proxy/profile configuration is loaded when the manager starts.

Credentials are kept in `storage.local`, not synced or embedded in packages.
Local browser storage is not an encrypted vault. Authentication is provided only
for the exact configured proxy host/port with the Stargate Basic realm; server-origin
401s receive no proxy credential. The handler registers synchronously and reads
storage on demand after the background worker wakes. Repeated challenges cancel
instead of looping. The extension has no content scripts or externally callable
message interface.

`proxy`, `privacy`, `storage`, `webRequest`, all-URL host access and the platform's
proxy-auth permission are used for proxy configuration, WebRTC policy and proxy challenges.
Firefox and Chromium declare different MV3 background/auth APIs. All-URL access
allows handling the browser's local proxy challenges; the extension does not
store destination URLs. No `publicSuffix` API or future Gecko version is needed.

WebRTC policy is checked separately: Firefox uses `proxy_only`, and Brave uses
`disable_non_proxied_udp`. Apply verifies ownership and the effective value before
confirming the combined settings; a competing controller is reported rather than
overwritten. Release removes this extension's override and restores the previous
setting. Startup/update restores policy independently of matching proxy settings.

These restrictions affect **new peer connections**. Fully quit and reopen the
browser after applying Stargate before sensitive browsing: existing web and
calling connections can continue on their previous route until closed. Applying
settings does not terminate them. A controlled HTTP/3 stream also continued
across Apply; this boundary is broader than WebRTC. Calls can fail, and successful WebRTC media
through Nym is not promised. Loopback and the configured public API retain their
routing exceptions. Private windows and an absent/disabled extension are outside
this scope.

## Connection status and recovery

The extension reports proxy settings for regular windows and separates those
settings from manager observations, listener availability and network readiness.
A responding Nym listener still leaves
network readiness unknown. Earlier received traffic belongs to the proxy process
and may include other browser profiles; it is not a current destination check.
Observation age is shown. Manager/background loss clears current network states.

The guidance panel offers **Apply browser settings**, local **Open manager**, remote
operator help or pairing controls when current observations justify them. It does not restart services or
change routes automatically. Repairing rejected pairing retains the saved manager
address, including nondefault ports, while you enter a fresh manager-issued code.

**Recent browser observations** keeps separate onion, I2P and ordinary-web
summaries, each with the latest uncached response, failure and cached response.
These request classes include regular-tab traffic while settings are released;
they do not prove the route used. HTTP errors, transport failures and cached
responses are distinct. Past responses remain history after failures. A cached
page does not demonstrate a fresh connection; success in another request class
does not erase a failure. Browser cancellations are excluded.

Only fixed categories, timestamps and status numbers are retained in bounded
session storage, with no addresses, headers or payloads. History survives worker
suspension and clears with the browser session. Session-storage failure can lose
history after worker exit. Chromium privacy lookups are capped at 32 in flight,
so these are best-effort observations, not a complete traffic ledger.

Private/unknown contexts are excluded. Chromium events without Firefox's privacy
field are checked against their tab's privacy flag, using existing permissions.
Unknown/non-tab contexts also receive no proxy credentials from the handler;
browser/extension/service-worker requests without a resolvable regular tab are
not promised support. Existing browser authentication caches are outside that
handler's control; private-window containment is not claimed.

The neutral badge identifies pairing rather than whole-tab protection. None of
these observations establishes browser-wide DNS/DoH/QUIC containment. HTTPS
remains end-to-end through CONNECT.

## Checks and reuse

Run the pure boundary checks with a patched Node LTS runtime:

```sh
node --test extension/test/*.test.cjs
```

These tests cover pairing, session concurrency, gateway validation, proxy
ownership/bypasses, Firefox permissions, authentication scope, retries and
private/unknown contexts. Run [packaging checks](../docs/extension-packaging.md)
separately. Unit and archive checks do not establish real browser/network behavior.

V1 reuse is limited to its small storage helper, stale-refresh generation guard,
and useful failure scenarios; see [NOTICE](NOTICE). Its spec-kit, tickets,
suffix/identity requirements, generated flow and deployment harness are absent.

I2P completion and error observations include a fixed network label without
storing URLs. The auth listener already covers all URLs; credentials remain
restricted to the exact configured Stargate proxy, including for I2P requests.
Tor profiles retain separate isolation partitions. The extension reports the
configured server's per-device I2P lifecycle; i2pd SOCKS credentials are not treated
as Tor-style isolation. Identity and lifecycle management remain server-side.

## Optional Nym route

With `compose.nym.yaml` enabled, ordinary DNS web destinations use Nym through
the same authenticated proxy. Onion and I2P routes keep their existing selection.
Authentication already listens to all URLs and still checks `isProxy`, Basic
realm and the exact paired proxy host/port; destination authentication gets no
Stargate credentials. No additional browser permissions were added.

The Nym row distinguishes listener observations from historical destination
traffic. `UNKNOWN` network readiness is intentional. Browser events use `WEB`
for ordinary web traffic: this describes the request class, not proof of the
route. Loopback manager traffic is excluded; no URLs are retained. Pairing,
effective setting checks and recovery remain unchanged. Nym profiles share one
native client, without Tor-style isolation.

## DNS speculation

Firefox Apply disables network prediction before applying the proxy and checks
both the effective value and Stargate ownership. This closes a reproduced cold
HTTPS/PAC gap in which page DNS hints resolved destinations before the first
proxied request. Startup and updates restore the restriction even when proxy
settings already match. Conflicts are reported; Forget keeps settings and
Release clears only Stargate's overrides. A busy settings operation must finish
before Release can succeed. Disabling speculation may reduce page preloading.

Brave keeps its own prediction setting. The tested release disables its HTML
DNS-prefetch/preconnect service; that is browser behavior, not an extension DNS
firewall.
The restriction concerns future speculative activity. Existing requests, proxy
hostname bootstrap, configured bypasses and other browser/system DNS remain
separate boundaries; it does not establish browser-wide DNS/DoH containment.

## Encrypted remote servers

Use the HTTPS server address and device code supplied by your operator. Remote
access requires a normally trusted server certificate; no certificate import or
VPN is required. Administration remains separate from the public device API. See
[remote access setup and limitations](../docs/remote-access.md). Local pairing
continues to use the existing loopback manager.
