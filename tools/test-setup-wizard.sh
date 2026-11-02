#!/usr/bin/env bash
# Focused, offline boundary checks. Fake Docker is confined to this test's PATH.
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
TEST=$(mktemp -d /tmp/stargate-shell-wizard-test.XXXXXXXX)
trap 'rm -rf -- "$TEST"' EXIT
mkdir -m 700 "$TEST/bin" "$TEST/tls"
printf 'synthetic metadata fixture, not TLS\n' > "$TEST/tls/server.crt"
printf 'synthetic metadata fixture, not TLS\n' > "$TEST/tls/server.key"
printf 'synthetic source\n' > "$TEST/source with spaces.yaml"
printf 'synthetic selected env\n' > "$TEST/selected.env"
export WIZARD_TEST_ROOT=$TEST
cat > "$TEST/bin/stat" <<'EOF'
#!/usr/bin/env bash
if [[ "$1" == -c && "$2" == '%f %u %a' ]]; then
  [[ ${WIZARD_PROTECTED_TLS:-false} == false ]] || exit 1
  printf '%s\n' "${WIZARD_DIR_METADATA:-41e8 10001 750}" "${WIZARD_CRT_METADATA:-8180 10001 600}" "${WIZARD_KEY_METADATA:-8180 10001 600}"
else exec /usr/bin/stat "$@"; fi
EOF
cat > "$TEST/bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 8 && "$1" == -- && "$2" == /usr/bin/stat && "$3" == -c && "$4" == '%f %u %a' && "$5" == -- && "$6" == "$WIZARD_TEST_ROOT/tls" && "$7" == "$6/server.crt" && "$8" == "$6/server.key" ]] || exit 91
printf 'metadata-only\n' >> "$WIZARD_TEST_ROOT/sudo-calls"
[[ ${WIZARD_SUDO_FAIL:-false} == false ]] || exit 1
WIZARD_PROTECTED_TLS=false "$WIZARD_TEST_ROOT/bin/stat" "${@:3}"
EOF
cat > "$TEST/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%q ' "$@" >> "$WIZARD_TEST_ROOT/calls"; printf '\n' >> "$WIZARD_TEST_ROOT/calls"
case "$*" in
  '--version') printf 'Docker version 29.1.3, build fixture\n' ;;
  'compose version --short') printf '5.1.4\n' ;;
  'info --format {{.ServerVersion}}') printf '29.1.3\n' ;;
  *'--format yaml')
    [[ ${WIZARD_FAKE_FAIL:-false} == false ]] || { printf 'SYNTHETIC_PRIVATE_DIAGNOSTIC\n' >&2; exit 2; }
    overlay=''
    while [[ $# -gt 0 ]]; do
      if [[ "$1" == --file ]]; then overlay=$2; shift; fi
      shift
    done
    cp -- "$overlay" "$WIZARD_TEST_ROOT/observed-overlay"
    if [[ -n ${WIZARD_RACE_TARGET:-} ]]; then
      case "${WIZARD_RACE_KIND:-file}" in
        file) printf 'keep concurrent file\n' > "$WIZARD_RACE_TARGET" ;;
        directory) mkdir -m 700 -- "$WIZARD_RACE_TARGET"; printf 'keep marker\n' > "$WIZARD_RACE_TARGET/marker" ;;
        symlink) ln -s -- "$WIZARD_TEST_ROOT/race-link-target" "$WIZARD_RACE_TARGET" ;;
      esac
    fi
    printf '%s\n' 'name: fixture' 'services:' '  app: {image: fixture-app}' '  tor: {image: fixture-tor}' '  i2p: {image: fixture-i2p}' '  nym: {image: fixture-nym}' ;;
  *'--services') printf 'app\ntor\ni2p\n'; [[ ${WIZARD_MISSING_NYM:-false} == true ]] || printf 'nym\n' ;;
  *'--quiet') exit 0 ;;
  *) printf 'Unexpected Docker invocation\n' >&2; exit 90 ;;
esac
EOF
chmod 700 "$TEST/bin/stat" "$TEST/bin/docker" "$TEST/bin/sudo"
export PATH="$TEST/bin:$PATH"
# Existing flow: explicit origins and ALL current local/public ports.
answers() {
  printf '%s\n' '' fixture "$TEST/source with spaces.yaml" '' "$TEST/selected.env" '' \
    https://fixture.invalid:19443 19444 19080 18881 "$TEST/tls" "$1" "${2-}"
}
run() { bash "$ROOT/tools/setup-wizard.sh" "$@"; }
check() { printf 'PASS %s\n' "$1"; }

answers "$TEST/preview/result.yaml" | run --preview > "$TEST/preview-log"
[[ ! -e "$TEST/calls" && ! -e "$TEST/preview" ]]
grep -Fq '3. Review your choices' "$TEST/preview-log"
grep -Fq 'Loopback manager: 127.0.0.1:19080' "$TEST/preview-log"
check 'existing preview preserves explicit endpoints; no Docker or writes'

printf '%s\n' '' fixture "$TEST/source with spaces.yaml" '' "$TEST/selected.env" '' \
  https://fixture.invalid:19443 19443 19080 18881 19444 19080 18881 "$TEST/tls" "$TEST/port-retry/out.yaml" |
  run --preview > "$TEST/port-retry-log"
grep -Fq 'All four host ports must differ' "$TEST/port-retry-log"
grep -Fq 'TLS proxy port: 19444' "$TEST/port-retry-log"
[[ ! -e "$TEST/calls" && ! -e "$TEST/port-retry" ]]
check 'duplicate port retry retains other setup choices'

printf '%s\n' no '' '' '' fixture.invalid '' '' '' '' '' "$TEST/new-preview/out.yaml" | run --preview > "$TEST/new-preview-log"
grep -Fq 'Device API: https://fixture.invalid:9443' "$TEST/new-preview-log"
grep -Fq 'TLS proxy port: 9444' "$TEST/new-preview-log"
grep -Fq 'compose.nym.yaml' "$TEST/new-preview-log"
[[ ! -e "$TEST/new-preview" && ! -e "$TEST/calls" ]]
check 'new defaults use all three networks and existing standard ports'

answers "$TEST/cancel/result.yaml" no | run > "$TEST/cancel-log"
[[ ! -e "$TEST/cancel" && ! -e "$TEST/calls" ]]
check 'declining recap writes nothing and runs no Docker'

if run --preview </dev/null > "$TEST/eof-log" 2>&1; then exit 1; else [[ $? == 130 ]]; fi
[[ ! -e "$TEST/calls" ]]
check 'EOF cancels'

answers "$TEST/success/result.yaml" | run > "$TEST/success-log"
[[ $(/usr/bin/stat -c %a "$TEST/success/result.yaml") == 600 && $(/usr/bin/stat -c %a "$TEST/success") == 700 ]]
grep -Fq 'ports: !override' "$TEST/observed-overlay"
[[ $(grep -Fc 'ports: !reset []' "$TEST/observed-overlay") == 3 ]]
grep -Fq '127.0.0.1:19080:9080' "$TEST/observed-overlay"
grep -Fq 'STARGATE_NYM_ENABLED: "true"' "$TEST/observed-overlay"
grep -Fq 'source\ with\ spaces.yaml' "$TEST/calls"
if grep -Eq '(^| )(up|run|restart|build|pull|exec)( |$)' "$TEST/calls"; then exit 1; fi
[[ $(find "$TEST/success" -mindepth 1 -maxdepth 1 | wc -l) == 1 ]]
check 'private non-overwriting publication, argv boundaries, only Compose config calls'

export WIZARD_PROTECTED_TLS=true
answers "$TEST/protected/result.yaml" | run > "$TEST/protected-log"
[[ $(cat "$TEST/sudo-calls") == metadata-only && -f "$TEST/protected/result.yaml" ]]
grep -Fq 'Never run the whole wizard with sudo' "$TEST/protected-log"
export WIZARD_SUDO_FAIL=true
if answers "$TEST/sudo-failed/result.yaml" | run > "$TEST/sudo-failed-log" 2>&1; then exit 1; fi
[[ ! -e "$TEST/sudo-failed" ]]
unset WIZARD_PROTECTED_TLS WIZARD_SUDO_FAIL
check 'protected TLS uses only privileged stat; denied metadata leaves no output'

for metadata in '8180 1002 600' '81a0 10001 640' 'a180 10001 600' '8180 10001 000' '8180 10001 4600'; do
  export WIZARD_KEY_METADATA=$metadata
  if answers "$TEST/bad-key/result.yaml" | run > "$TEST/bad-key-log" 2>&1; then exit 1; fi
  [[ ! -e "$TEST/bad-key" ]]
done
unset WIZARD_KEY_METADATA
check 'wrong key owner, loose mode, symlink, unreadable key and special mode refused'
for metadata in '41c0 0 700' '4180 10001 600' '43f8 10001 1770' 'a1e8 10001 750'; do
  export WIZARD_DIR_METADATA=$metadata
  if answers "$TEST/bad-dir/result.yaml" | run > "$TEST/bad-dir-log" 2>&1; then exit 1; fi
  [[ ! -e "$TEST/bad-dir" ]]
done
unset WIZARD_DIR_METADATA
for metadata in '8180 0 600' '8100 10001 000' 'a180 10001 600'; do
  export WIZARD_CRT_METADATA=$metadata
  if answers "$TEST/bad-crt/result.yaml" | run > "$TEST/bad-crt-log" 2>&1; then exit 1; fi
  [[ ! -e "$TEST/bad-crt" ]]
done
unset WIZARD_CRT_METADATA
check 'inaccessible or linked directory and unreadable or linked certificate refused'

saved=$(cat "$TEST/success/result.yaml")
# Existing output reprompts to a fresh path without losing answers.
{ answers "$TEST/success/result.yaml" "$TEST/second/result.yaml"; printf 'no\n'; } | run --preview > "$TEST/retry-log"
grep -Fq 'That output exists' "$TEST/retry-log"
[[ $(cat "$TEST/success/result.yaml") == "$saved" && ! -e "$TEST/second" ]]
check 'existing output kept; prompt retries'

export WIZARD_RACE_TARGET="$TEST/race/result.yaml"
if answers "$WIZARD_RACE_TARGET" | run > "$TEST/race-log" 2>&1; then exit 1; fi
[[ $(cat "$WIZARD_RACE_TARGET") == 'keep concurrent file' ]]
[[ $(find "$TEST/race" -mindepth 1 -maxdepth 1 | wc -l) == 1 ]]
unset WIZARD_RACE_TARGET
check 'late output collision preserves concurrent file and cleans staging'

mkdir -m 700 "$TEST/race-link-target"
printf 'keep marker\n' > "$TEST/race-link-target/marker"
for kind in directory symlink; do
  export WIZARD_RACE_KIND=$kind WIZARD_RACE_TARGET="$TEST/race-$kind/result.yaml"
  if answers "$WIZARD_RACE_TARGET" | run > "$TEST/race-$kind-log" 2>&1; then exit 1; fi
  [[ $(cat "$WIZARD_RACE_TARGET/marker") == 'keep marker' && ! -e "$WIZARD_RACE_TARGET/result.yaml" ]]
  [[ $(find "$TEST/race-$kind" -mindepth 1 -maxdepth 1 | wc -l) == 1 ]]
done
unset WIZARD_RACE_TARGET WIZARD_RACE_KIND
check 'late directory and directory-symlink collisions are refused without nested publication'

export WIZARD_FAKE_FAIL=true
if answers "$TEST/failed/result.yaml" | run > "$TEST/failure-log" 2>&1; then exit 1; fi
[[ ! -e "$TEST/failed/result.yaml" ]]
if grep -Fq SYNTHETIC_PRIVATE_DIAGNOSTIC "$TEST/failure-log"; then exit 1; fi
[[ $(find "$TEST/failed" -mindepth 1 -maxdepth 1 | wc -l) == 0 ]]
unset WIZARD_FAKE_FAIL
check 'helper failure cleans staging and does not echo private diagnostics'

export WIZARD_MISSING_NYM=true
if answers "$TEST/missing/result.yaml" | run > "$TEST/missing-log" 2>&1; then exit 1; fi
[[ ! -e "$TEST/missing/result.yaml" ]]
unset WIZARD_MISSING_NYM
check 'missing service refused'

mkdir -m 755 "$TEST/shared"
before=$(wc -l < "$TEST/calls")
if answers "$TEST/shared/result.yaml" | run > "$TEST/shared-log" 2>&1; then exit 1; fi
[[ $(/usr/bin/stat -c %a "$TEST/shared") == 755 && ! -e "$TEST/shared/result.yaml" && $(wc -l < "$TEST/calls") == "$((before+3))" ]]
check 'unsafe existing output directory is not changed or used'

# Metacharacters stay literal in YAML, protected from both Bash and Compose.
# This path contains an actual dollar and quote; no eval or interpolated program.
mkdir -m 700 "$TEST/tls-\$value\"quote"
printf 'fixture\n' > "$TEST/tls-\$value\"quote/server.crt"
printf 'fixture\n' > "$TEST/tls-\$value\"quote/server.key"
# Serializer exercised by sourcing ONLY the extracted function, not the wizard.
serializer=$(sed -n '/^yaml_string() {/,/^}/p' "$ROOT/tools/setup-wizard.sh")
value=$(bash -c "$serializer"'; yaml_string "$1"' bash '/tmp/$value"quote\path')
read -r expected <<'LITERAL'
"/tmp/$$value\"quote\\path"
LITERAL
[[ "$value" == "$expected" ]]
check 'YAML data quoting preserves literal dollars, quotes and backslashes'
printf 'All shell wizard checks passed.\n'
