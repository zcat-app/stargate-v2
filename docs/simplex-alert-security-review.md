# Runtime security findings and coverage

Assessment date: 2026-10-27. This is a scoped dependency/advisory review, not a
complete image scan, penetration test, compiled SBOM, or security certification.
Hashes and signatures establish the selected bytes and provenance; they do not
establish that those bytes are free of vulnerabilities.

The runtime retains the existing prepared patched application libc subset and
Java 25.0.5. It adds only `libcrypto.so.3` from Ubuntu `libssl3t64`
`3.0.13-0ubuntu3.16`, and `libgmp.so.10` from Ubuntu `libgmp10`
`2:6.3.0+dfsg-2ubuntu6.1`. Their immutable source image digest, file hashes, and
copyright notices are recorded in `containers/simplex-alert/libraries.json` and
the resulting image. No libc from that library source image replaces the patched
application libc. The source image is the same Ubuntu digest already selected by
the base repository container build.

Selected exact-coordinate queries to the public OSV API returned no matching
records for source packages `openssl` `3.0.13-0ubuntu3.16` and `gmp`
`2:6.3.0+dfsg-2ubuntu6.1` under ecosystem `Ubuntu:24.04:LTS`. Ubuntu documents this
[OSV publication/query route](https://documentation.ubuntu.com/security/security-updates/osv/).
These results are limited by package naming, ecosystem/version coverage, and the
advisory feed at query time. They are not a claim that every current Ubuntu CVE
has been independently reconciled. In particular, the sparse package database of
the copied application root does not list these newly added complete packages;
the supplemental `libraries.json` is the file-subset inventory for them. A future
scanner must consume this supplemental inventory rather than treating absence
from `dpkg` status as absence of those libraries.

The original independent sender selected Jackson databind/core 2.21.2. The OSV
query returned 16 databind records and 3 core records whose affected package
ranges include 2.21.2. The primary FasterXML advisories confirm the upper affected
2.21 bound of 2.21.6 and fixed release 2.21.7 for the newest relevant records:
[core token error handling](https://github.com/FasterXML/jackson-core/security/advisories/GHSA-7hhh-6rmp-j9qf),
[core number parsing](https://github.com/FasterXML/jackson-core/security/advisories/GHSA-p6pp-m3f8-5c89),
[databind reference completion](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-cxp5-3px4-pw24),
and [databind type-ID retention](https://github.com/FasterXML/jackson-databind/security/advisories/GHSA-wv8q-qhhj-9h54).
The selected sender uses databind and its transitive core 2.21.7, with
annotations 2.21. Exact-version follow-up OSV queries returned no matching records
for these three coordinates.

Those package matches did not demonstrate an exploitable path in this sender.
The sender uses bounded String frames and JsonNode tree parsing, without
POJO annotations/views, polymorphic/default typing, object identity, InetAddress,
XML, DataInput, or asynchronous Jackson parsers named by the retrieved records.
We upgraded for dependency hygiene without asserting those vulnerable APIs were
reachable. The assessment records package ranges and selected primary references above.
It does not reproduce exploits.

The pinned SimpleX v7.0.0 binary reports `v7.0.0.11`; the verified signed release
manifest and key are preserved with image provenance. The current upstream
[security page](https://github.com/simplex-chat/simplex-chat/security) had no
published GitHub advisories when checked, while its policy explicitly allows
some security fix details to be delayed. Absence there provides no clearance.
[Later v7.0.4 artifacts](https://github.com/simplex-chat/simplex-chat/releases/tag/v7.0.4)
exist; their CLI compatibility and security differences were not assessed for this runtime. The pinned v7.0.0 baseline is not a claim that it is the latest or safest version.

The released executable's dynamically linked dependencies were observed as
libc, libm, zlib, libcrypto, libgmp and the ELF loader. Its statically linked
Haskell/SQLCipher/other bundled component versions have **not** been recovered
into a complete compiled SBOM or matched against advisory feeds. The existing
Java and application runtime subsets were reused; their full fresh advisory
review was not repeated here. No Trivy, Grype or Syft executable was available.
These are material unassessed gaps before production deployment. Host-level crash collection, kernel/supervisor persistence paths, and every
possible upstream internal file write were not audited. The service
still processes remote protocol traffic and can receive messages even though
this transport ignores inbound events.

## App, Tor, I2P and Nym findings

Saved Trivy 0.76.1 scans using the 28 October 2026 vulnerability and Java
databases retain these findings. They are historical evidence, not a current
scan or a claim that every image with a similar version has the same content.

| Finding | Scanner severity | Retained assessment |
| --- | --- | --- |
| CVE-2026-18374, libc6 | MEDIUM | Selected local backport plus patched-ELF comparison evidence; the scanner finding remains visible. |
| CVE-2026-89092, libc6 | MEDIUM | Scoped absence of nscd from inspected image paths and mounted sockets; host exposure is unassessed. |
| CVE-2026-40228, libsystemd0 in Tor | LOW | Scoped absence of journald from inspected image paths; host exposure is unassessed. |

The first two findings appeared in app, Tor, I2P, Nym and sender scans; the
third also appeared in Tor. These assessments must be bound to each exact
image ID, scan hash and finding before reuse. They do not suppress findings
or establish that the whole deployment is unaffected.

The libc backport is pinned in containers/native/glibc-inputs.json. Package
version matching cannot establish whether the patch is present or effective.
Absence checks do not cover host services, later mounts or modified images.
See Ubuntu's [18374](https://ubuntu.com/security/CVE-2026-18374),
[89092](https://ubuntu.com/security/CVE-2026-89092) and
[40228](https://ubuntu.com/security/CVE-2026-40228) descriptions.

Saved OSV source-coordinate queries returned review candidates for glibc,
libevent, lz4, miniupnpc, systemd and Tor, and for 19 Nym source-graph
coordinates. No candidate was returned for the selected Maven coordinates.
Neither presence nor absence of a source-version match establishes actual
affected code in a runtime subset. These dated results must not be presented
as a current advisory lookup.

## What monitoring does not establish

- A release notification is not an image upgrade or security clearance.
- Saved image scans do not become fresh full-image scans when the daily
  monitor queries advisory feeds.
- Java archive inventory does not cover every JDK module, shaded dependency or
  native library. No reported Java findings is not complete Java/JDK coverage.
- The Nym source lock graph is not a compiled binary SBOM. Missing Cargo
  results do not mean the binary has no Rust dependencies.
- Sender static Haskell/SQLCipher dependencies and host dependencies remain
  incompletely assessed.
- A valid signature proves selected bytes and signer approval, not safety.

Keep raw scans, scanner/database versions, exact image IDs, copied-file hashes
and assessment evidence privately. Do not rewrite scans to force a match. The
[Java monitor](java-monitor.md) describes current configuration;
[maintenance instructions](maintenance-upgrades.md) explain what to do with alerts.
