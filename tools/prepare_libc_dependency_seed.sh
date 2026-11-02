#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
jar="$root/bootstrap-tools/target/stargate-bootstrap-tools-0.1.0-SNAPSHOT.jar"
[[ -f "$jar" ]] || { printf '%s\n' 'Build bootstrap tools first: bash tools/with-toolchain.sh mvn --offline --batch-mode --no-transfer-progress -f bootstrap-tools/pom.xml package' >&2; exit 1; }
exec bash "$root/tools/with-toolchain.sh" java --enable-native-access=ALL-UNNAMED -jar "$jar" --project "$root" seed "$@"
