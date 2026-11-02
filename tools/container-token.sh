#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Export the selected installation's administrator token. No app-image utilities.
set +x
set -euo pipefail
unset TAR_OPTIONS
umask 077
staging=''
cleanup() { if [[ -n "$staging" ]]; then rm -rf -- "$staging"; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { printf '%s\n' 'Could not export the administrator token for this installation. Check the selected Compose configuration/project and Docker access.' >&2; exit 1; }
usage() { printf '%s\n' 'Usage: bash tools/container-token.sh [--project NAME] [--env-file PATH]' 'Honors COMPOSE_FILE and the selected Docker context. Writes the token to stdout only after validation.' 'Redirect stdout to a private file; do not enable shell tracing or put the token in command arguments.'; }
compose=(docker compose)
while (( $# )); do
  case "$1" in
    --help|-h) usage; exit 0 ;;
    --project|--env-file)
      [[ $# -ge 2 && -n $2 && $2 != --* ]] || { usage >&2; exit 64; }
      if [[ $1 == --project ]]; then compose+=(--project-name "$2"); else compose+=(--env-file "$2"); fi
      shift 2 ;;
    --project=*) [[ -n ${1#*=} ]] || exit 64; compose+=(--project-name "${1#*=}"); shift ;;
    --env-file=*) [[ -n ${1#*=} ]] || exit 64; compose+=(--env-file "${1#*=}"); shift ;;
    *) usage >&2; exit 64 ;;
  esac
done
for tool in docker head tar cmp stat grep cat mktemp rm; do command -v "$tool" >/dev/null || fail; done
# Secret staging must not follow an untrusted TMPDIR or a replaceable parent.
[[ -d /tmp && ! -L /tmp && -k /tmp && $(stat -c '%u' /tmp) == 0 ]] || fail
staging=$(mktemp -d /tmp/stargate-token-XXXXXXXX) || fail
if ! "${compose[@]}" cp app:/data/admin-token - 2>/dev/null | head -c 65537 > "$staging/archive.tar"; then fail; fi
[[ $(stat -c '%s' "$staging/archive.tar") -le 65536 ]] || fail
if ! tar --list --quoting-style=literal --file "$staging/archive.tar" > "$staging/members" 2>/dev/null; then fail; fi
printf '%s\n' admin-token > "$staging/expected"
cmp -s "$staging/expected" "$staging/members" || fail
if ! tar --list --verbose --numeric-owner --file "$staging/archive.tar" > "$staging/types" 2>/dev/null; then fail; fi
[[ $(head -c 1 "$staging/types") == - ]] || fail
if ! tar --extract --to-stdout --file "$staging/archive.tar" -- admin-token 2>/dev/null | head -c 130 > "$staging/token"; then fail; fi
size=$(stat -c '%s' "$staging/token")
[[ $size -ge 43 && $size -le 129 ]] || fail
[[ $(LC_ALL=C grep -c '^' "$staging/token") == 1 ]] || fail
LC_ALL=C grep -aEq '^[A-Za-z0-9_-]{43,128}$' "$staging/token" || fail
cat -- "$staging/token"
