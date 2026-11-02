#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
if [[ $# == 1 && ( $1 == --help || $1 == -h ) ]]; then
  printf '%s\n' 'Usage: bash extension/package.sh' 'Requires a Java 25 JDK. Builds local unsigned Firefox/Brave packages; no downloads or publishing.'
  exit 0
fi
[[ $# == 0 ]] || { printf '%s\n' 'Use --help or no arguments.' >&2; exit 64; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
exec bash "$root/../tools/with-toolchain.sh" java --source 25 "$root/PackageExtension.java" "$root"
