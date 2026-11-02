# Build extension packages

Prepared-package users need only a browser. Current source manifests declare
0.8.9; the rc.3 Firefox and Brave packages are 0.8.8. Build the matching
source revision when reproducing a released package.

Both packages include [the privacy policy](privacy-policy.md) as PRIVACY.md and
a local, script-free privacy.html. The Java builder HTML-escapes policy text.
Firefox declares desktop minimum 140 and its required data-consent categories;
Android is not supported. Brave uses its own manifest and background worker.

A Stargate checksum signature does not supply Mozilla signing. The public Firefox
XPI uses temporary loading; Brave uses unpacked loading and manual updates.
Never disable browser signature verification. See [downloads](release-readiness.md).

## Build from source

Prepared-package users need only their browser; they do not run this builder.
Developers/operators can package a selected source checkout with:

```sh
bash extension/package.sh
```

The wrapper invokes `java --source 25` on `extension/PackageExtension.java`.
Packaging needs the project's Java 25 **JDK**, not the stripped app-image runtime.
There is no Python, Node/npm, bundler, additional Java library or network request.
It does not sign, upload or publish anything.

Outputs retain their existing paths:

- `extension/target/stargate-firefox.xpi` and unpacked `extension/target/firefox/`.
- `extension/target/stargate-brave.zip` and unpacked `extension/target/brave/`.

Browser versions are declared in explicit source manifests in
`extension/manifests/`; update both versions together when an actual version bump
is selected. The builder refuses mismatched versions. The builder copies the allowlisted source files, browser adapter, worker, icons,
license and notice. Stargate is the default theme; saved theme choices are retained.

Source links and unexpected output types are rejected. A lock prevents concurrent
packagers. Both browsers are built in staging before publication. Each output is
renamed atomically; the four-output set is not one filesystem transaction.
Handled publication failures restore moved old outputs. If restoration itself
fails, an explicit error names the retained staging directory containing prior
outputs for inspection. A hard interruption can leave a partial set or private
staging/backup directory: inspect before distribution and rerun from the selected
source. Do not treat that state as a successful build. Only generated package
outputs are replaced; other target files remain.

## Packaging checks

```sh
bash -n extension/package.sh extension/test-package.sh
shellcheck extension/package.sh extension/test-package.sh
bash extension/test-package.sh
```

The Java test inspects every ZIP member against the unpacked files, including
manifest, license, notice and browser worker differences. Repeat builds with
changed source timestamps produce identical archives. Fixed ZIP-local timestamps (2000-01-01) and sorted entries make package bytes
reproducible across UTC and Europe/Prague. Source revisions and payload contents
must still match when comparing hashes.

Failure checks cover missing inputs, mismatched versions, input/output symlinks,
an existing package lock, publication failure with successful rollback and
restoration failure retaining a usable backup. They use a private synthetic
checkout and no browser, Docker or real credentials.
