# Public release downloads

The Java host updater accepts public HTTPS assets. It does not accept GitHub
credentials and cannot download private or draft releases. Assets must be public and published before the updater can retrieve them.

For a published GitHub release, configure the complete, versioned manifest URL:

```text
https://github.com/OWNER/REPO/releases/download/TAG/release.json
```

Upload `release.json.sig` alongside `release.json`; the updater appends `.sig`
to the configured manifest URL. Each signed `archive` value selects the complete
versioned URL of its image archive. Do not use GitHub API asset endpoints, a
release HTML page or a mutable `latest` link. A missing/private asset fails rather
than asking for a token or using a different source.

## Redirect and verification boundaries

- HTTPS uses Java's normal certificate and hostname verification. No custom
  trust store, insecure TLS option, cookie jar or authorization header is added.
- The updater follows only 301, 302, 303, 307 and 308 responses, with at most five
  redirects. Loops, missing/ambiguous locations, user information, fragments and
  HTTP downgrades are rejected.
- Same-origin HTTPS redirects are supported. The only cross-origin exception is
  a versioned `github.com/OWNER/REPO/releases/download/TAG/ASSET` URL on port 443
  to `release-assets.githubusercontent.com` on port 443 under its validated
  `/github-production-release-asset/` path. Other hosts or ports are rejected
  before contacting the redirect destination. If GitHub changes delivery hosts,
  this policy must be reviewed; it does not silently widen trust.
- One ten-minute deadline covers request headers, all redirect hops and the final
  body. The existing 20-second connection timeout remains. Partial output is
  deleted on failure; an existing output file is preserved.
- The manifest remains limited to 64 KiB, its Ed25519 signature to 64 bytes, and
  archive transfers to the signed exact size and operator ceiling. A redirect
  does not bypass the independently pinned signing key, signature, manifest
  expiry, patch inventory or archive SHA-256 verification. An archive is hashed
  before Docker loads it. Installation and rollback retain their existing gates.

GitHub documents public assets as available without authentication and advises
clients to handle redirects as well as direct responses in its official
[release asset reference](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).
TLS and a matching upstream checksum alone do not authorize a Stargate upgrade;
the separately pinned Stargate release signature is still required.

## Focused verification

The verification command is:

```sh
bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f updater/pom.xml package
```

The local HTTPS fixtures use an ephemeral certificate trusted only by their test
client. They exercise actual TLS and response bodies; production continues to
use the system trust store. The tests cover redirect success and refusal,
certificate rejection, transfer bounds, deadlines and cleanup, alongside the
existing signed preview/install/rollback tests. They do not require Docker.
