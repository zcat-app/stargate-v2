# Stargate extension privacy policy

Effective date: 1 November 2026. Applies to extension version 0.8.9.

## Who receives your data

Stargate connects your browser to a server you choose. Use a server operator you trust. The extension does not send analytics, advertising identifiers, crash reports or browsing reports to the Stargate developers, and does not contain advertising or tracking services. The developers do not automatically receive your traffic because you installed the extension. A developer who also operates your chosen server has the operator's access described below.

## Pairing and server status

When you connect, the extension sends your one-time access code and its browser-assigned extension origin to the server address you enter. The server returns a device identifier, proxy credentials and a separate grant for reading that device's status. Later status requests send that grant and extension origin to the same server. Ordinary connection metadata, including your connecting IP address, is also visible to that server. Status requests can occur when you open or use the extension even while its proxy settings are disconnected. Disconnecting is not a promise to stop every server request.

Remote server addresses must use HTTPS. Plain HTTP is accepted only for a server on 127.0.0.1 on your own computer. Manager requests do not follow redirects or use browser cookies. Proxy credentials are supplied only for the configured Stargate proxy's authentication challenge, not a destination website's login prompt.

## Browsing through Stargate

When Stargate's settings are applied, your browser sends its proxied web requests through the selected server. This includes destination information and request/response traffic. The server routes .onion addresses through Tor, .i2p addresses through I2P, and ordinary websites through Nym. A failed server route does not switch to another network or connect directly.

For destination HTTPS connections, the website's TLS connection remains encrypted through the server; Stargate does not install a certificate authority or decrypt that website connection. Destination hostnames, ports and connection timing or volume can still be visible to the operator. With destination HTTP, the operator can read requests and responses, including paths, query strings, cookies, messages or submitted information. Encrypted transport to the Stargate server does not turn an HTTP destination into HTTPS.

Destination sites receive the traffic and data you send them, through the selected network. Network operators and service providers have their own privacy practices. Tor uses separate isolation credentials per paired device; isolated I2P deployments use separate persistent device destinations. Nym uses a shared client with separate streams, not an independent Nym identity for each user. Cookies, website logins and browser fingerprints can still identify you.

## Optional IPFS gateway

Opening an IPFS address converts it to an HTTPS URL on your configured gateway and sends it through Nym. The initial default gateway is https://ipfs.dget.top; you can change it in Settings. The gateway receives the requested content identifier and path. Stargate does not run a local IPFS node or verify downloaded content against its identifier. The gateway has its own privacy practices and availability limits.

## What stays in your browser

The extension keeps your server address, device credentials, status grant, connection preference, local-network choice, theme preferences and optional gateway setting in local extension storage. It does not use browser account sync for these records. Local storage is not a separate encrypted vault: someone with access to your browser profile or an infected device may obtain saved access. The code typed during setup is not saved as a reusable credential by the extension.

To explain connection problems, the extension keeps a bounded summary of browser events: route category, time, HTTP status or a general failure category, and proxy authentication counters. These observations use browser-session storage or memory. They do not store destination URLs, hostnames, headers, payloads or credentials. They are not sent as telemetry. Website data and history that the browser itself keeps are separate from these extension records.

## Server records and retention

The Stargate manager keeps pending invitation codes in memory until used, cancelled, expired or the manager restarts. Codes expire after five minutes by default; the operator can choose the existing 24-hour option. Redeemed device identifiers, credentials and routing configuration persist on the server until the operator removes them. Server aggregate counters and route status are operational observations, not a browsing-history service. Stargate's product logging excludes browsing destinations, request headers, credentials and payloads. An operator's host, reverse proxy, backups or modifications may retain additional records; ask that operator about retention and deletion. This policy cannot guarantee an independently operated server's behavior.

## Your choices and deletion

Disconnect releases Stargate's browser proxy and privacy settings and keeps saved access for later use. Your browser can then use its normal connection settings. Disconnect and forget saved access additionally removes the extension's saved pairing. Removing the extension is the way to remove its remaining local preferences and observations; it does not erase browser history or data held by a server, gateway or website. Ask the server operator to revoke a lost or exposed device credential. Revocation does not automatically erase retired network identity files or backups: discuss those separately with the operator. Expiry of an invitation does not expire access already redeemed.

Private windows are unsupported. The extension excludes private-window events from its observations and does not supply Stargate credentials for private-window requests. Firefox still requires Allow in Private Windows to change its browser proxy settings. This permission is not a promise that private browsing is protected.

Loopback and the configured server API are routing exceptions. The optional local-network setting permits direct access to private IP ranges. The browser can resolve the Stargate server's own hostname outside the proxy. Stargate does not protect other applications or provide a universal kill switch when it is disabled, absent or its settings are changed. WebRTC restrictions can prevent calls from working.

## Questions and policy updates

For data handled by your chosen server, contact its operator directly. For extension-code questions or this policy, use https://github.com/zcat-app/stargate-v2/issues. GitHub issues are public: do not post access codes, tokens, private addresses, browsing records or other personal information there. Mozilla, GitHub, your browser vendor, websites and network or gateway providers have separate privacy policies for their services. Future extension releases may update this policy and their permission declarations; review those changes before accepting an update.
