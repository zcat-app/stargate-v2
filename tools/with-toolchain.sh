#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Scope optional verified toolchains to Stargate; never change system alternatives.
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
[[ $# -gt 0 ]] || { printf 'Usage: bash tools/with-toolchain.sh COMMAND [ARGUMENT...]\n' >&2; exit 64; }
for kind in java maven; do
  file="$root/.local-setup/$kind-home"
  if [[ -e "$file" || -L "$file" ]]; then
    [[ -d "$root/.local-setup" && ! -L "$root/.local-setup" && $(stat -c %u -- "$root/.local-setup") == "$EUID" && $(stat -c %a -- "$root/.local-setup") == 700 ]] || { printf 'Unsafe Stargate toolchain selection directory.\n' >&2; exit 1; }
    [[ -f "$file" && ! -L "$file" && $(stat -c %u -- "$file") == "$EUID" && $(stat -c %a -- "$file") == 600 ]] || { printf 'Unsafe Stargate toolchain selection file.\n' >&2; exit 1; }
    mapfile -t lines < "$file"
    [[ ${#lines[@]} == 1 && ${lines[0]} == /* && ${lines[0]} != *[[:cntrl:]]* && -d ${lines[0]} ]] || { printf 'Invalid Stargate toolchain selection.\n' >&2; exit 1; }
    home_path=${lines[0]}
    [[ "$home_path" == "$(realpath -e -- "$home_path")" ]] || { printf 'Toolchain path must not use aliases.\n' >&2; exit 1; }
    if [[ "$kind" == java ]]; then executables=(java javac jlink); else executables=(mvn); fi
    for executable in "${executables[@]}"; do
      [[ -f "$home_path/bin/$executable" && -x "$home_path/bin/$executable" ]] || { printf 'Selected %s toolchain is incomplete; no system fallback is used.\n' "$kind" >&2; exit 1; }
    done
    if [[ "$kind" == java ]]; then export JAVA_HOME=$home_path; else export MAVEN_HOME=$home_path; fi
    export PATH="$home_path/bin:$PATH"
  fi
done
exec "$@"
