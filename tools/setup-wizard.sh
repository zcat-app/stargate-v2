#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Configuration preparation only. Bash + Docker Compose + standard Linux tools.
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
PREVIEW=false
STAGING=''
cleanup() { if [[ -n "$STAGING" ]]; then rm -rf -- "$STAGING"; fi; }
trap cleanup EXIT
trap 'printf "\nCancelled. Services were not changed.\n" >&2; exit 130' INT
trap 'printf "\nInterrupted. Services were not changed.\n" >&2; exit 143' TERM
fail() { printf '%s\n' "$*" >&2; exit 1; }
case "${1-}" in
  --prerequisites) [[ $# == 1 ]] || fail 'Use --prerequisites without extra arguments.'; exec bash "$ROOT/tools/setup-prerequisites.sh" --guided ;;
  --check-prerequisites) [[ $# == 1 ]] || fail 'Use --check-prerequisites without extra arguments.'; exec bash "$ROOT/tools/setup-prerequisites.sh" --check images ;;
  --preview) PREVIEW=true ;;
  --help|-h) printf '%s\n' 'Usage: bash tools/setup-wizard.sh [--preview|--prerequisites|--check-prerequisites]' 'Prepare remote configuration, or check/install operator prerequisites.' 'Preview writes nothing and does not run Docker.'; exit 0 ;;
  '') ;;
  *) fail 'Use --preview, --help, or no option.' ;;
esac
[[ $# -le 1 ]] || fail 'Use --preview, --help, or no option.'
(( EUID != 0 )) || fail 'Run this wizard as the operator, without sudo. Only the protected TLS metadata check may request sudo.'

ask() {
  local label=$1 default=${2-}
  while :; do
    printf '%s' "$label"
    [[ -z "$default" ]] || printf ' [%s]' "$default"
    printf ': '
    if ! IFS= read -r REPLY; then printf '\nCancelled. No configuration published.\n' >&2; exit 130; fi
    REPLY=${REPLY:-$default}
    if [[ "$REPLY" == *[[:cntrl:]]* ]]; then printf 'Use one line without control characters.\n'; continue; fi
    return 0
  done
}
yes() {
  while :; do
    ask "$1" "${2:-no}"
    case "${REPLY,,}" in y|yes) return 0;; n|no) return 1;; *) printf 'Enter yes or no.\n';; esac
  done
}
required() { while :; do ask "$1" "${2-}"; [[ -z "$REPLY" ]] || return 0; printf 'Please enter a value.\n'; done; }
port() {
  while :; do
    ask "$1" "${2-}"
    if [[ "$REPLY" =~ ^[0-9]{1,5}$ ]] && (( 10#$REPLY >= 1 && 10#$REPLY <= 65535 )); then REPLY=$((10#$REPLY)); return 0; fi
    printf 'Enter a port from 1 to 65535.\n'
  done
}
host_ok() {
  [[ ${#1} -le 253 && "$1" != *.onion && "$1" != *.i2p ]] || return 1
  local label
  local -a labels
  IFS=. read -r -a labels <<< "$1"
  [[ "$1" != *..* && "$1" != .* && "$1" != *. ]] || return 1
  for label in "${labels[@]}"; do [[ "$label" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$ ]] || return 1; done
  [[ ${#labels[@]} -gt 0 ]]
}
path_value() {
  local value=$1
  [[ "$value" != \~/* ]] || value="$HOME/${value:2}"
  realpath -ms -- "$value"
}
files() {
  local kind=$1 needed=$2 value
  FILES=()
  printf '%s: one path per line, in original order. Blank finishes.\n' "$kind"
  while :; do
    ask "File $((${#FILES[@]}+1))"
    if [[ -z "$REPLY" ]]; then
      if [[ "$needed" == true && ${#FILES[@]} == 0 ]]; then printf 'Select at least one source file.\n'; continue; fi
      return 0
    fi
    value=$(path_value "$REPLY")
    if [[ -f "$value" && -r "$value" ]]; then FILES+=("$value"); else printf 'File missing or inaccessible. Enter its path, never secret contents.\n'; fi
  done
}
quoted() { printf '%q ' "$@"; printf '\n'; }
# JSON strings are also valid YAML scalars. Escape dollars for Compose itself;
# values are data, never shell code. Control characters were rejected at entry.
yaml_string() {
  local value=${1//\$/\$\$}
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '"%s"' "$value"
}

printf '%s\n' 'Stargate operator setup — configuration preparation' \
  'Configuration uses Bash, Docker Compose and standard Linux tools; no Python is needed.' \
  'Prepared images, selected Nym requester and staged TLS files are prerequisites.' \
  'Use --prerequisites for guided host setup before configuration.' \
  'Missing prerequisites can open a separate guided setup with its own confirmation. No Stargate deployment. Ctrl+C cancels.'
printf '\n1. Installation\n'
if yes 'Existing installation? (keep its exact project and settings)' yes; then EXISTING=true; else EXISTING=false; fi
while :; do
  if $EXISTING; then required 'Existing Compose project name'; else required 'New Compose project name' stargate-v2; fi
  [[ "$REPLY" =~ ^[a-z0-9][a-z0-9_-]*$ ]] && break
  printf 'Use lowercase letters, digits, hyphens or underscores.\n'
done
PROJECT=$REPLY
if ! $EXISTING && yes 'Use standard Tor + I2P + Nym source files? (recommended)' yes; then
  SOURCES=("$ROOT/compose.yaml" "$ROOT/compose.nym.yaml")
else
  printf 'Use original pre-remote sources and every override, not generated remote configuration.\n'
  files 'Compose sources' true; SOURCES=("${FILES[@]}")
fi
printf 'Include all environment files used by the installation, including .env when selected.\n'
printf 'Nym needs your selected public requester setting. No provider is chosen here.\n'
files 'Environment files (paths only)' false; ENVS=("${FILES[@]}")

printf '\n2. Public and private endpoints\n'
while :; do
  if $EXISTING; then
    required 'Current HTTPS device API address, including port'
    if [[ "${REPLY,,}" =~ ^https://([^/:?#@[:space:]]+)(:([0-9]{1,5}))?$ ]]; then
      HOST=${BASH_REMATCH[1],,}; API_PORT=${BASH_REMATCH[3]:-443}
      if host_ok "$HOST" && (( 10#$API_PORT >= 1 && 10#$API_PORT <= 65535 )); then API_PORT=$((10#$API_PORT)); break; fi
    fi
  else
    required 'Hostname you control (no https://, for example gate.example.org)'; HOST=${REPLY,,}
    if host_ok "$HOST"; then port 'HTTPS device API port' 9443; API_PORT=$REPLY; break; fi
  fi
  printf 'Use a valid HTTPS origin without a path, query or embedded login.\n'
done
ORIGIN="https://$HOST"; [[ "$API_PORT" == 443 ]] || ORIGIN+=":$API_PORT"
while :; do
  if $EXISTING; then
    port 'Current public TLS browser-proxy port'; TLS_PORT=$REPLY
    port 'Current loopback manager host port'; MANAGER_PORT=$REPLY
    port 'Current loopback plaintext proxy host port'; LOCAL_PORT=$REPLY
  else
    port 'Public TLS browser-proxy port' 9444; TLS_PORT=$REPLY
    port 'Loopback manager host port' 9080; MANAGER_PORT=$REPLY
    port 'Loopback plaintext proxy host port' 8881; LOCAL_PORT=$REPLY
  fi
  if [[ "$API_PORT" != "$TLS_PORT" && "$API_PORT" != "$MANAGER_PORT" && "$API_PORT" != "$LOCAL_PORT" && "$TLS_PORT" != "$MANAGER_PORT" && "$TLS_PORT" != "$LOCAL_PORT" && "$MANAGER_PORT" != "$LOCAL_PORT" ]]; then break; fi
  printf 'All four host ports must differ. Re-enter the proxy and loopback ports.\n'
done
if $EXISTING; then required 'Current staged TLS directory'; else required 'Staged TLS directory' /srv/stargate/tls; fi
CERT=$(path_value "$REPLY")
while :; do
  required 'New private output file' "$ROOT/.local-setup/compose.remote.yaml"
  OUTPUT=$(path_value "$REPLY")
  if [[ ! -e "$OUTPUT" && ! -L "$OUTPUT" ]]; then break; fi
  printf 'That output exists. Choose a new name; existing files are kept.\n'
done
PARENT=${OUTPUT%/*}
COMPOSE=(docker compose --project-name "$PROJECT")
for value in "${ENVS[@]}"; do COMPOSE+=(--env-file "$value"); done
for value in "${SOURCES[@]}"; do COMPOSE+=(--file "$value"); done

printf '\n3. Review your choices\nProject: %s\n' "$PROJECT"
printf 'Compose sources, in order:\n'; printf '  %s\n' "${SOURCES[@]}"
printf 'Environment files, in order:\n'
if [[ ${#ENVS[@]} -eq 0 ]]; then printf '  None selected; default .env and shell settings can still apply.\n'; else printf '  %s\n' "${ENVS[@]}"; fi
printf 'Device API: %s\nTLS proxy port: %s\nLoopback manager: 127.0.0.1:%s\nLoopback proxy: 127.0.0.1:%s\n' "$ORIGIN" "$TLS_PORT" "$MANAGER_PORT" "$LOCAL_PORT"
printf 'TLS directory: %s\nNew private output: %s\n' "$CERT" "$OUTPUT"
printf '%s\n' 'Tor, I2P and Nym stay selected. Native port publications are cleared.' \
  'The four app port publications are replaced by exactly the endpoints above.' \
  'Images, volume mappings, capacity and other settings come from your selected sources.' \
  'Nym initializes its own local key passphrase; preserve nym-data and nym-secrets together.' \
  'No keys, administrator tokens or passphrases are requested.' \
  'No services, firewall, certificates or secrets are installed or changed.'
if $PREVIEW; then printf '\nPreview complete. No files written and Docker was not run.\n'; exit 0; fi
if ! yes 'Prepare this private configuration file after review?' yes; then printf 'Cancelled. No files written or commands run.\n'; exit 0; fi
if ! bash "$ROOT/tools/setup-prerequisites.sh" --check images; then
  printf 'Prerequisites are not ready. No configuration was written.\n'
  if yes 'Open guided prerequisite setup now?' yes; then
    bash "$ROOT/tools/setup-prerequisites.sh" --guided images
  fi
  fail 'Rerun the wizard after prerequisite checks pass. Your configuration choices are shown in the recap above.'
fi
# Metadata only: stat does not open file contents. Do not run this wizard as root.
# Protected UID-10001 directories need privileged traversal, not relaxed modes.
TLS_STAT=(stat -c '%f %u %a' -- "$CERT" "$CERT/server.crt" "$CERT/server.key")
if ! TLS_METADATA=$("${TLS_STAT[@]}" 2>/dev/null); then
  printf '%s\n' 'TLS metadata is protected. sudo will run only /usr/bin/stat on the selected directory and two files.' \
    'It reads no key contents and changes no ownership or permissions. Never run the whole wizard with sudo.'
  command -v sudo >/dev/null || fail 'sudo is needed for this metadata check. Use the reviewed TLS staging procedure; do not loosen permissions.'
  TLS_METADATA=$(sudo -- /usr/bin/stat "${TLS_STAT[@]:1}") || fail 'Cannot inspect staged TLS metadata. No configuration published; do not loosen permissions.'
fi
mapfile -t TLS_ROWS <<< "$TLS_METADATA"
[[ ${#TLS_ROWS[@]} == 3 ]] || fail 'Unexpected TLS metadata. No configuration published.'
for index in 0 1 2; do
  read -r TLS_BITS TLS_UID TLS_MODE TLS_EXTRA <<< "${TLS_ROWS[$index]}"
  [[ "$TLS_BITS" =~ ^[0-9a-f]+$ && "$TLS_UID" =~ ^[0-9]+$ && "$TLS_MODE" =~ ^[0-7]{3,4}$ && -z "$TLS_EXTRA" ]] || fail 'Invalid TLS metadata.'
  [[ "$TLS_UID" == 10001 ]] || fail 'The staged TLS directory and both files must belong to app UID 10001.'
  if (( index == 0 )); then
    (( (16#$TLS_BITS & 0170000) == 0040000 )) || fail 'TLS directory must be a real directory, not a symlink.'
    [[ "$TLS_MODE" == 750 || "$TLS_MODE" == 700 ]] || fail 'TLS directory must have mode 0750 or 0700 so the app can traverse it.'
  else
    (( (16#$TLS_BITS & 0170000) == 0100000 )) || fail 'Staged TLS files must be regular files, not symlinks.'
    [[ "$TLS_MODE" == 600 || "$TLS_MODE" == 400 ]] || fail 'Both staged TLS files must have mode 0600 or 0400.'
  fi
done
if [[ ! -e "$PARENT" && ! -L "$PARENT" ]]; then mkdir -m 700 -- "$PARENT"; fi
[[ -d "$PARENT" && ! -L "$PARENT" && $(stat -c %u -- "$PARENT") == "$EUID" && $(stat -c %a -- "$PARENT") == 700 ]] || fail 'Select an output directory you own, mode 0700, without a symlink.'
STAGING=$(mktemp -d -- "$PARENT/.stargate-setup.XXXXXXXX")
OVERLAY=$STAGING/remote.yaml
cat > "$OVERLAY" <<EOF
services:
  app:
    environment:
      STARGATE_MANAGER_ORIGIN: "http://127.0.0.1:$MANAGER_PORT"
      STARGATE_PROXY_PORT: "$LOCAL_PORT"
      STARGATE_PUBLIC_ORIGIN: "$ORIGIN"
      STARGATE_TLS_PROXY_PORT: "$TLS_PORT"
      STARGATE_NYM_ENABLED: "true"
    ports: !override
      - "127.0.0.1:$MANAGER_PORT:9080"
      - "127.0.0.1:$LOCAL_PORT:8881"
      - "$TLS_PORT:8882"
      - "$API_PORT:9443"
    volumes:
      - type: bind
        source: $(yaml_string "$CERT")
        target: /run/stargate-tls
        read_only: true
        bind:
          create_host_path: false
  tor:
    ports: !reset []
  i2p:
    ports: !reset []
  nym:
    ports: !reset []
EOF
# Compose performs the merge and serialization; no separate JSON/YAML runtime.
if ! "${COMPOSE[@]}" --file "$OVERLAY" config --format yaml > "$STAGING/result.yaml" 2> "$STAGING/diagnostic"; then
  fail 'Compose could not prepare configuration. Check your inputs, Nym requester and support for !override/!reset; no output published. See docs/operator-setup-wizard.md.'
fi
if ! docker compose --project-name "$PROJECT" --file "$STAGING/result.yaml" config --quiet > /dev/null 2> "$STAGING/diagnostic"; then
  fail 'The rendered configuration did not validate. No output published.'
fi
if ! SERVICES=$(docker compose --project-name "$PROJECT" --file "$STAGING/result.yaml" config --services 2> "$STAGING/diagnostic"); then
  fail 'Compose could not confirm the service set. No output published.'
fi
for value in app tor i2p nym; do
  if ! grep -Fxq -- "$value" <<< "$SERVICES"; then fail 'The full app/Tor/I2P/Nym service set is required. No output published.'; fi
done
# Same-filesystem hard-link publication refuses races/overwrites as well.
ln -T -- "$STAGING/result.yaml" "$OUTPUT"
printf '\nConfiguration prepared: %s\n' "$OUTPUT"
printf 'Read-only validation command: '; quoted docker compose --project-name "$PROJECT" --file "$OUTPUT" config --quiet
printf '%s\n' 'Review the full resolved file privately, especially images, volume mappings, networks and any custom overrides.' \
  'No services started. Follow docs/operator-guide.md for deliberate startup and private administration.'
