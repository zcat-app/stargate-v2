#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
jar="$root/backup-tools/target/stargate-backup-tools-0.1.0-SNAPSHOT.jar"
[[ -f "$jar" ]] || { printf '%s\n' 'Build backup tools first: bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f backup-tools/pom.xml package' >&2; exit 1; }
exec bash "$root/tools/with-toolchain.sh" java --enable-native-access=ALL-UNNAMED -cp "$jar" app.zcat.stargate.backup.VolumeImport "$@"
