#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors
# SPDX-License-Identifier: Apache-2.0
# Synthetic-only regression: its only writable storage is a new tmpfs.
set -euo pipefail
if [[ $# != 1 || ! $1 =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s\n' 'Usage: test-restricted-init.sh sha256:TRUSTED_LOCAL_HELPER_IMAGE_ID' >&2
    exit 2
fi
root=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
core="$root/backup-tools/target/stargate-backup-tools-0.1.0-SNAPSHOT.jar"
adapter="$root/backup-docker-tools/target/stargate-backup-docker-tools-0.1.0-SNAPSHOT.jar"
classes="$root/backup-docker-tools/target/test-classes"
if [[ ! -f "$core" || ! -f "$adapter" || ! -f "$classes/app/zcat/stargate/backup/RestrictedInitProbe.class" ]]; then
    printf '%s\n' 'Build the adapter reactor with tests before running this probe.' >&2
    exit 1
fi
work=$(mktemp -d /tmp/stargate-restricted-init.XXXXXXXX)
trap 'rm -f -- "$work/probe.jar"; rmdir -- "$work"' EXIT
jar --create --file "$work/probe.jar" -C "$classes" app/zcat/stargate/backup/RestrictedInitProbe.class
chmod 0644 "$work/probe.jar"
docker --host unix:///var/run/docker.sock run --rm --pull=never --network none \
    --read-only --user 0:0 --userns host --cap-drop ALL --cap-add CHOWN \
    --security-opt no-new-privileges --tmpfs /dest:mode=0700 \
    --entrypoint /opt/java/bin/java \
    --mount "type=bind,src=$core,dst=/tool/core.jar,readonly" \
    --mount "type=bind,src=$adapter,dst=/tool/adapter.jar,readonly" \
    --mount "type=bind,src=$work/probe.jar,dst=/tool/probe.jar,readonly" \
    "$1" -XX:+PerfDisableSharedMem --enable-native-access=ALL-UNNAMED \
    -cp /tool/core.jar:/tool/adapter.jar:/tool/probe.jar app.zcat.stargate.backup.RestrictedInitProbe
