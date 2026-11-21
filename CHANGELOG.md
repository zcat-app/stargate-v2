# Stargate v0.1.0

Stargate v0.1.0 is the first stable server release for Linux amd64. Stargate routes onion sites through Tor, I2P sites through I2P, and ordinary web traffic through Nym when that route is enabled.

## Updated components

| Component | Version |
| --- | --- |
| Eclipse Temurin | 25.0.5.1+2 |
| Quarkus platform | 3.40.1.2 |
| Netty | 4.1.141.Final |
| Tor | 0.4.9.17 |
| Ubuntu glibc | 2.39-0ubuntu8.12 |
| i2pd | 3.0.0, rebuilt with the retained Stargate patches |
| Nym SOCKS5 client | 1.1.89, with the retained Stargate patches |
| Optional SimpleX alert runtime | 7.1.4 |

## Upgrading

- Back up Stargate before replacing images. The updated host updater supports an operator-reviewed transition for protected runtime files. The transition pins the exact previous and candidate image IDs and the expected file hashes.
- If you use SimpleX alerts, back up the stopped alert profile and approve its database migration separately. To downgrade after migration, restore the pre-upgrade profile backup before starting the previous SimpleX version.
- Firefox users can install the signed extension from [Mozilla Add-ons](https://addons.mozilla.org/en-US/firefox/addon/stargate-browser-proxy/). Brave uses the unpacked extension. Firefox users on the store build need Firefox 140 or later.
