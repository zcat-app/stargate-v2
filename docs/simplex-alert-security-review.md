# Runtime security scope and limitations

Stargate and its dependencies process untrusted network input. A valid release
signature authenticates the selected bytes and signer; it does not establish that
the software is free of vulnerabilities. Review current upstream advisories for
the exact versions and images you intend to deploy.

## Runtime inventory

The container build selects specific runtime libraries rather than installing a
complete set of operating-system packages. Use the source pins and file hashes in
`containers/native/glibc-inputs.json`, `containers/java-runtime.json` and
`containers/simplex-alert/libraries.json` alongside the selected image contents.
A package database alone may not inventory every copied library. Package versions
alone do not establish whether a retained backport is present or effective.

## Coverage limits

- The sender's statically linked Haskell, SQLCipher and other bundled components
  do not have a complete compiled inventory matched against advisory feeds.
- The Nym source dependency graph does not establish the exact dependencies
  compiled into a particular released binary.
- Java archive metadata does not cover every JDK module, shaded dependency or
  native library.
- Container inventories do not assess the host kernel, host services, crash
  collection, additional mounts or later operator modifications.
- The SimpleX runtime can receive remote protocol traffic even though the alert
  transport ignores inbound events. Ignoring an event does not remove the
  runtime's responsibility to parse it safely.

These limits require deployment-specific assessment. They are not a current
vulnerability scan or a statement that every retained version is affected.

## What monitoring does not establish

- A release notification is not an installed upgrade or security clearance.
- An advisory match requires assessment against the exact deployed bytes and
  reachable component. An empty result does not establish complete coverage.
- Refreshing advisory metadata does not perform a fresh full-image scan.
- An assessment of a particular image does not automatically apply to another
  image, added host service, changed mount or modified dependency.

Keep raw scans, operational records and assessment evidence private. See the
[Java monitor](java-monitor.md) for configuration and
[maintenance instructions](maintenance-upgrades.md) for reviewing and applying
updates. Consult the selected release's advisories for affected versions, fixed
versions, impact and required action when a security issue affects a public
release.
