# Open IPFS addresses from the address bar

Firefox registers `ipfs` through its extension manifest. Brave uses a
user-activated **Enable IPFS links** button and its native **Allow** prompt.
The browser hands the escaped URI to a bundled local extension page; there is no
keyword, content script, native helper or local IPFS node. Permissions are unchanged.

Firefox setup must also check the selected application: if it offers **System
Handler**, cancel and open `about:preferences#downloads` → **Files and
applications** → search **ipfs** → **Action: Use Stargate IPFS through Nym**.
This changes only the browser's protocol-handler choice and keeps pairing.
If Stargate is not listed, check the extension is loaded and the handler is enabled.

The receiver decodes once, preserves case-sensitive CIDs and existing path/query
escaping, and calls the same guarded IPFS resolution used by the existing tool.
Only after that succeeds does it replace its own tab with the configured HTTPS
subdomain gateway. Ordinary-web routing remains Nym. Released, unpaired,
conflicting or unconfirmed settings do not trigger a gateway navigation. The
manager and enabled-Nym checks remain mandatory. No settings are applied
automatically, no alternate gateway/network is selected, and no direct fallback
is added. Private receiver contexts are rejected.

The handoff fragment is cleared before asynchronous work. Input is not logged or
written to extension storage. A deliberate Try again reruns the checks; newer
handoffs invalidate an older pending navigation. Browser history/cache can still
retain addresses. Before the browser has approved a handler, raw input can be
treated as a search query; Stargate cannot intercept input when absent or disabled.


## Gateway failures

A gateway can be slow or return an error through Nym. A SOCKS preflight is not
proof that the same request will work in a browser. The configured default
https://ipfs.dget.top has returned HTTP 504 in browser checks; another public
gateway, https://ipfs.storry.tv, has returned the checker successfully. Those
observations do not guarantee current availability or every path/query behavior.
Choose a gateway you trust in Settings; Stargate does not switch it automatically.

For setup, see [the user guide](user-guide.md#optional-open-ipfs-addresses).
Developers can package and run the protocol tests with:

```sh
bash extension/package.sh
node --test extension/test/*.test.cjs
```
