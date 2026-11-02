#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
core="$root/backup-tools/target/stargate-backup-tools-0.1.0-SNAPSHOT.jar"
adapter="$root/backup-docker-tools/target/stargate-backup-docker-tools-0.1.0-SNAPSHOT.jar"
if [[ ! -f "$core" || ! -f "$adapter" ]]; then
    printf '%s\n' 'Build the adapter first: bash tools/with-toolchain.sh mvn --offline -pl backup-docker-tools -am package' >&2
    exit 1
fi
exec bash "$root/tools/with-toolchain.sh" java -XX:+PerfDisableSharedMem -XX:-CreateCoredumpOnCrash -XX:ErrorFile=/dev/null --enable-native-access=ALL-UNNAMED -cp "$core:$adapter" app.zcat.stargate.backup.DockerImportMain --core-jar "$core" --adapter-jar "$adapter" "$@"
