# Downloads and signature verification

Use the [v0.1.0 downloads](https://github.com/zcat-app/stargate-v2/releases/tag/v0.1.0).
This is the stable server release for Linux amd64. Automatic prerequisite installation
supports Ubuntu 24.04 amd64; other Linux hosts need [manual setup](setup-prerequisites.md).

| Payload | Purpose |
| --- | --- |
| stargate-operator-v0.1.0.tar.gz | Operator tools, guides and nine prebuilt helper JARs |
| stargate-source-v0.1.0.zip | Project source without Git history |
| app-image.tar, tor-image.tar, i2p-image.tar, nym-image.tar | Four core container images |
| simplex-alert-image.tar | Optional SimpleX 7.1.4 alert runtime |
| release.json | Signed core updater manifest |
| image-ids.json | Exact image IDs and Compose tags |
| runtime-transition.json | Core image and file hash pins for operator review |
| stargate-firefox.xpi, stargate-brave.zip | Extension 0.8.9 for temporary/unpacked loading |
| stargate-release-public.der | Public Ed25519 verification key |

The checksum signature covers the release payloads. The operator bundle includes
the prebuilt helper JARs. Unpacking it does not update a running helper.
Follow the [updater setup](verified-upgrades.md#configure-the-operators-updater).

## Extension distribution

Firefox is published on Mozilla Add-ons as
[Stargate](https://addons.mozilla.org/en-US/firefox/addon/stargate-browser-proxy/):
version **0.8.9**, Mozilla-signed for permanent installation, with automatic
updates (listed 1 November 2026, approved 4 November 2026). Do not disable
signature verification. The GitHub release supplies the unsigned
`stargate-firefox.xpi` for temporary loading and the Brave package for manual
installation. See [packaging instructions](extension-packaging.md). The Stargate
release signature and Mozilla add-on signing serve different purposes.

## Verify the downloads

1. Download the payloads listed above, `SHA256SUMS` and `SHA256SUMS.sig` from
   [v0.1.0](https://github.com/zcat-app/stargate-v2/releases/tag/v0.1.0).
   Keep them together in a new folder; do not mix checksum files between releases.
2. Obtain the public-key fingerprint through an independently trusted channel.
   A key or fingerprint supplied only with the same download does not establish
   trust. The publisher's approved public DER SHA-256 is
   `affae46c79d99fb6415fa914d752fd712865ccd073ddddfb8d01faddda6e7659`.
3. From that directory, with GNU coreutils and OpenSSL 3, run this complete block:

```sh
printf '%s  stargate-release-public.der\n' \
  affae46c79d99fb6415fa914d752fd712865ccd073ddddfb8d01faddda6e7659 |
  sha256sum --check --strict - &&
openssl pkeyutl -verify -pubin -keyform DER \
  -inkey stargate-release-public.der -rawin \
  -in SHA256SUMS -sigfile SHA256SUMS.sig &&
sha256sum --check --strict SHA256SUMS
```

Continue only if the key check, `Signature Verified Successfully`, and every
payload checks pass. Stop on any error. Do not edit or reformat the signed
checksum file. The publisher's private key stays on their laptop; verification
needs only the public DER. These commands do not install or restart anything.


## Verified image upgrade

The stable release manifest is bound to the four core image IDs published in
the v0.1.0 prereleases. The current host updater and an operator-reviewed
[runtime transition](verified-upgrades.md#configure-the-operators-updater)
are required. Retain the previous images and a verified backup.

Get `release.json` and its detached `release.json.sig` from the stable release. After independently verifying the
public-key fingerprint as above, run:

```sh
openssl pkeyutl -verify -pubin -keyform DER \
  -inkey stargate-release-public.der -rawin \
  -in release.json -sigfile release.json.sig
```

This verifies those exact manifest bytes. The updater separately checks schema,
expiry, patch/configuration policy, artifacts and the actual deployment-bound
preview. Check the expiry embedded in the manifest before preparing an upgrade.

The updater requires a genuine old-to-new image transition and does not accept
private GitHub release authentication. See [verified upgrades](verified-upgrades.md)
and [public download support](public-release-downloads.md).



## Before installing

- Read [the privacy limits](user-guide.md#what-privacy-this-provides).
- Keep existing state, native identities and the previous images before upgrading.
  Follow [signed upgrades and rollback](verified-upgrades.md).
- A valid signature establishes approved bytes, not freedom from vulnerabilities.
  Read [security findings and coverage](simplex-alert-security-review.md).
- CI does not exercise real Tor/I2P/Nym routes or prove clean-host deployment.
  See [CI scope](continuous-integration.md).
