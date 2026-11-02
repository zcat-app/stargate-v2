#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
repository=$(git -C "$root" rev-parse --show-toplevel)
[[ "$repository" == "$root" ]] || { printf '%s\n' 'Run this check from its own initialized project repository.' >&2; exit 1; }
cd "$root"
failed=0
scan() {
  local status=0
  grep -En -- "$1" "$2" || status=$?
  case "$status" in
    0) failed=1 ;;
    1) ;;
    *) printf 'Cannot scan versioned file: %s\n' "$2" >&2; exit 1 ;;
  esac
}
while IFS= read -r -d '' path; do
  case "$path" in
    scratch/*|*/scratch/*|.local-manager/*|*/.local-manager/*|.local-setup/*|*/.local-setup/*|target/*|*/target/*|*.py|*.pyw|*.age|*.agekey|*.bundle|*/.git-credentials|.git-credentials|admin-token|admin-token.*|*/admin-token|*/admin-token.*|key-passphrase|*/key-passphrase|credentials.json|*/credentials.json|*private*.pem|*private*.key|server.key|*/server.key)
      printf 'Forbidden versioned path: %s\n' "$path" >&2; failed=1 ;;
  esac
  case "$path" in
    .env.example|*/.env.example) ;;
    .env|.env.*|*/.env|*/.env.*|id_rsa|id_ed25519|*/id_rsa|*/id_ed25519)
      printf 'Forbidden operator credential/environment path: %s\n' "$path" >&2; failed=1 ;;
  esac
  case "$path" in
    *.java)
      scan 'new ProcessBuilder\([^;]*("python[0-9.]*"|"/[^" ]*/python[0-9.]*")|command\("python[0-9.]*"' "$path" ;;
    *.sh|*.service|*.service.in)
      scan '^[[:space:]]*(exec[[:space:]]+)?(/[^[:space:]]*/)?python[0-9.]*[[:space:]]|^ExecStart=.*(python|ABSOLUTE_PYTHON)' "$path" ;;
  esac
done < <(git ls-files -z)
if (( failed )); then exit 1; fi
printf '%s\n' 'Versioned source path and explicit interpreter-call checks passed.'
