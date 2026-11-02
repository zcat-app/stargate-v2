#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Operator prerequisites only; never deploy or rebuild Stargate.
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
# shellcheck source=containers/setup/prerequisites.sh
source "$ROOT/containers/setup/prerequisites.sh"
WORK=''
trap '[[ -z "$WORK" ]] || rm -rf -- "$WORK"' EXIT
fail() { printf '%s\n' "$*" >&2; exit 1; }
ask_yes() {
  local answer
  while :; do
    printf '%s [Y/n]: ' "$1"
    IFS= read -r answer || { printf '\nCancelled.\n'; exit 130; }
    case ${answer,,} in ''|yes|y) return 0;; no|n) return 1;; *) printf 'Enter yes or no.\n';; esac
  done
}
[[ ${1-} != --help ]] || { printf '%s\n' 'Usage: bash tools/setup-wizard.sh --prerequisites' 'Read-only check: bash tools/setup-prerequisites.sh --check images|tools|build' 'Guided setup: bash tools/setup-prerequisites.sh --guided [images|tools|build]'; exit 0; }
[[ ${1-} == --check || ${1-} == --guided ]] || fail 'Use --check or --guided.'
[[ $# -le 2 ]] || fail 'Too many arguments.'
GUIDED=false; [[ $1 != --guided ]] || GUIDED=true
PROFILE=${2-}
(( EUID != 0 )) || fail 'Run as the operator, without sudo. Individual package actions explain and request sudo when needed.'
for command in timeout stat realpath uname sed awk mktemp chmod mkdir cp mv rm; do command -v "$command" >/dev/null || fail "Missing standard Linux utility: $command"; done
if [[ -z "$PROFILE" ]]; then
  $GUIDED || fail 'Select images, tools or build.'
  printf '%s\n' 'What will this host do?' '  1. Configure prepared images (Docker/Compose only)' '  2. Run host tools too (Java 25 JDK)' '  3. Build from source (JDK, Maven and Git)' 'Press Enter for 1. This does not start Stargate.'
  IFS= read -r choice || exit 130
  case ${choice:-1} in 1) PROFILE=images;; 2) PROFILE=tools;; 3) PROFILE=build;; *) fail 'Choose 1, 2 or 3.';; esac
fi
[[ "$PROFILE" == images || "$PROFILE" == tools || "$PROFILE" == build ]] || fail 'Select images, tools or build.'
version_pattern='^[[:space:]]*\{[[:space:]]*"version"[[:space:]]*:[[:space:]]*"(25\.[0-9]+\.[0-9]+)"[[:space:]]*\}[[:space:]]*$'
pin=$(< "$ROOT/containers/java-runtime.json")
[[ "$pin" =~ $version_pattern ]] || fail 'Invalid shared Java version declaration.'
JAVA_REQUIRED=${BASH_REMATCH[1]}
[[ "$JAVA_REQUIRED" == "$JAVA_SETUP_VERSION" ]] || fail 'Installer pin differs from project Java requirement; review release inputs first.'
OS_ID=$(sed -nE 's/^ID="?([a-z0-9]+)"?$/\1/p' /etc/os-release)
OS_VERSION=$(sed -nE 's/^VERSION_ID="?([0-9.]+)"?$/\1/p' /etc/os-release)
ARCH=$(uname -m)
SUPPORTED=false; [[ "$OS_ID" != ubuntu || "$OS_VERSION" != 24.04 || "$ARCH" != x86_64 ]] || SUPPORTED=true
check() {
  NEED_DOCKER=false; NEED_COMPOSE=false; NEED_ACCESS=false; NEED_JAVA=false; NEED_MAVEN=false; NEED_GIT=false
  printf '\nPrerequisite check — %s, %s %s %s\n' "$PROFILE" "$OS_ID" "$OS_VERSION" "$ARCH"
  if [[ "$ARCH" != x86_64 || $(uname -s) != Linux ]]; then printf 'Unsupported: qualified platform is Linux amd64.\n'; return 1; fi
  if command -v docker >/dev/null; then
    printf 'Docker: '; if ! timeout 10 docker --version; then printf 'Needs repair: existing Docker CLI failed; automatic replacement refused.\n'; NEED_ACCESS=true; fi
    compose=$(timeout 10 docker compose version --short 2>/dev/null) || compose=''
    if [[ "$compose" =~ ^v?([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] && (( 10#${BASH_REMATCH[1]} > 2 || (10#${BASH_REMATCH[1]} == 2 && (10#${BASH_REMATCH[2]} > 24 || (10#${BASH_REMATCH[2]} == 24 && 10#${BASH_REMATCH[3]} >= 4))) )); then printf 'Compose: %s\n' "$compose"; else printf 'Needs setup: Compose 2.24.4+ with !override/!reset.\n'; NEED_COMPOSE=true; fi
    if timeout 10 docker info --format '{{.ServerVersion}}' >/dev/null 2>&1; then printf 'Docker daemon/access: available.\n'; else printf 'Needs setup: Docker daemon is unavailable or this login lacks access.\n'; NEED_ACCESS=true; fi
  else printf 'Needs setup: Docker and Compose.\n'; NEED_DOCKER=true; NEED_COMPOSE=true; fi
  if [[ "$PROFILE" != images ]]; then
    java_version=$(bash "$ROOT/tools/with-toolchain.sh" java --version 2>/dev/null) || java_version=''
    javac_version=$(bash "$ROOT/tools/with-toolchain.sh" javac --version 2>/dev/null) || javac_version=''
    jlink_version=$(bash "$ROOT/tools/with-toolchain.sh" jlink --version 2>/dev/null) || jlink_version=''
    if [[ ${java_version%%$'\n'*} == "openjdk $JAVA_REQUIRED "* && "$javac_version" == "javac $JAVA_REQUIRED" && "$jlink_version" == "$JAVA_REQUIRED" ]]; then
      printf 'Java JDK: %s; javac/jlink match.\n' "${java_version%%$'\n'*}"
      printf 'Java executable: '; bash "$ROOT/tools/with-toolchain.sh" /bin/bash -c 'command -v java'
    else printf 'Needs setup: matching Java/javac/jlink %s JDK.\n' "$JAVA_REQUIRED"; NEED_JAVA=true; fi
  fi
  if [[ "$PROFILE" == build ]]; then
    if maven=$(bash "$ROOT/tools/with-toolchain.sh" mvn -Dstyle.color=never --version 2>/dev/null); then
      maven=$(sed -E 's/\x1B\[[0-9;]*[[:alpha:]]//g' <<< "$maven")
      printf 'Maven found: %s\n' "${maven%%$'\n'*}"
      printf 'Maven executable: '; bash "$ROOT/tools/with-toolchain.sh" /bin/bash -c 'command -v mvn'
      if [[ ${maven%%$'\n'*} != "Apache Maven $MAVEN_SETUP_VERSION "* ]]; then printf 'Needs setup: Maven %s is the verified build baseline; this version is not qualified here.\n' "$MAVEN_SETUP_VERSION"; NEED_MAVEN=true; fi
      if [[ "$maven" != *$'\n'"Java version: $JAVA_REQUIRED,"* ]]; then printf 'Needs setup: Maven is not using required Java %s.\n' "$JAVA_REQUIRED"; NEED_JAVA=true; fi
    else printf 'Needs setup: Maven (installer baseline %s).\n' "$MAVEN_SETUP_VERSION"; NEED_MAVEN=true; fi
    if command -v git >/dev/null; then git --version; else printf 'Needs setup: Git for native source verification.\n'; NEED_GIT=true; fi
    printf 'Native patched builds, test records and Maven dependencies are separate prerequisites; not prepared here.\n'
  fi
  ! $NEED_DOCKER && ! $NEED_COMPOSE && ! $NEED_ACCESS && ! $NEED_JAVA && ! $NEED_MAVEN && ! $NEED_GIT
}
if check; then printf '\nReady for selected host tasks. No installation needed.\n'; exit 0; fi
$GUIDED || exit 2
$SUPPORTED || fail 'Guided installation is limited to Ubuntu 24.04 amd64. See docs/setup-prerequisites.md for other hosts.'
if $NEED_ACCESS && ! $NEED_DOCKER; then printf '%s\n' 'Existing Docker service, socket and groups will not be changed automatically.' 'Check the selected Docker context/service and group access; use a fresh SSH login after permissions change.'; fi
printf '\nSetup recap\n'
$NEED_JAVA && printf '  Install verified Temurin %s privately; select it for Stargate only.\n' "$JAVA_SETUP_BUILD"
$NEED_MAVEN && printf '  Install verified Maven %s privately; select it for Stargate only.\n' "$MAVEN_SETUP_VERSION"
if $NEED_DOCKER; then printf '  Install Docker/Compose from signed Docker APT repository on a fresh host. This may start Docker; sudo required.\n'; elif $NEED_COMPOSE; then printf '  Existing Docker needs Compose repair; no daemon package will be automatically upgraded.\n'; fi
$NEED_GIT && printf '  Install Git from the trusted Ubuntu repository.\n'
printf '%s\n' 'Missing curl/GnuPG/CA certificates require sudo installation from trusted Ubuntu repositories.' 'No Stargate services, certificates, state volumes, firewall or Java alternatives will change.'
if ! ask_yes 'Proceed with the listed supported setup actions?'; then printf 'Cancelled. No installation performed.\n'; exit 0; fi
if ! command -v curl >/dev/null || ! command -v gpg >/dev/null || $NEED_GIT; then
  sudo -- /usr/bin/apt-get -o APT::Update::Error-Mode=any update
  packages=(ca-certificates curl gnupg); $NEED_GIT && packages+=(git)
  sudo -- /usr/bin/apt-get install --no-remove --no-upgrade --no-install-recommends --yes "${packages[@]}"
fi
for command in curl gpg sha256sum tar; do command -v "$command" >/dev/null || fail "Missing installer tool: $command"; done
WORK=$(mktemp -d /tmp/stargate-prerequisites.XXXXXXXX)
chmod 700 "$WORK"
fetch() { curl --fail --location --silent --show-error --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 120 --max-filesize 268435456 --output "$2" "$1"; }
verify_signature() {
  local kind=$1 key=$2 key_hash=$3 expected_signer=$4 archive=$5 signature=$6
  printf '%s  %s\n' "$key_hash" "$key" | sha256sum --check --status || fail "$kind public-key input changed."
  local key_home="$WORK/gpg-$kind"
  mkdir -m 700 -- "$key_home"
  gpg --homedir "$key_home" --no-autostart --batch --import "$key" > /dev/null 2> "$key_home/import-log"
  gpg --homedir "$key_home" --no-autostart --no-auto-key-retrieve --batch --status-fd 1 --verify "$signature" "$archive" > "$key_home/status" 2> "$key_home/verify-log" || fail "$kind signature was rejected."
  awk -v signer="$expected_signer" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==signer || $NF==signer) {ok=1} END {exit !ok}' "$key_home/status" || fail "$kind signer does not match its pin."
}
select_home() {
  local kind=$1 selected_home=$2 dir="$ROOT/.local-setup"
  [[ -e "$dir" || -L "$dir" ]] || mkdir -m 700 -- "$dir"
  [[ -d "$dir" && ! -L "$dir" && $(stat -c %u -- "$dir") == "$EUID" && $(stat -c %a -- "$dir") == 700 ]] || fail 'Use an operator-owned private .local-setup directory (0700).'
  local temp
  temp=$(mktemp -- "$dir/.$kind-home.XXXXXXXX")
  printf '%s\n' "$selected_home" > "$temp"
  chmod 600 "$temp"
  mv -T -- "$temp" "$dir/$kind-home"
}
install_tool() {
  local kind=$1 name=$2 url=$3 signature_url=$4 hash=$5 key=$6 key_hash=$7 signer=$8
  local base="$HOME/.local/share/stargate/toolchains" destination
  mkdir -p -- "$base"
  [[ "$base" == "$(realpath -e -- "$base")" && $(stat -c %u -- "$base") == "$EUID" ]] || fail 'Toolchain directory must be operator-owned without aliases.'
  chmod 700 -- "$base"
  destination="$base/$name"
  [[ ! -e "$destination" && ! -L "$destination" ]] || fail "Toolchain destination exists: $destination; inspect before retrying."
  printf 'Downloading and verifying %s...\n' "$kind"
  fetch "$url" "$WORK/$kind.tar.gz"; fetch "$signature_url" "$WORK/$kind.sig"
  printf '%s  %s\n' "$hash" "$WORK/$kind.tar.gz" | sha256sum --check --status || fail "$kind checksum mismatch."
  verify_signature "$kind" "$key" "$key_hash" "$signer" "$WORK/$kind.tar.gz" "$WORK/$kind.sig"
  tar -tzf "$WORK/$kind.tar.gz" > "$WORK/$kind.paths"
  while IFS= read -r entry; do [[ "$entry" == "$name/"* && "$entry" != /* && "/$entry/" != */../* ]] || fail 'Release archive contains an unexpected path.'; done < "$WORK/$kind.paths"
  mkdir -m 700 -- "$WORK/$kind-extracted"
  tar --extract --gzip --file "$WORK/$kind.tar.gz" --directory "$WORK/$kind-extracted" --no-same-owner --no-same-permissions
  [[ -d "$WORK/$kind-extracted/$name" && ! -L "$WORK/$kind-extracted/$name" ]] || fail 'Release root is not a directory.'
  local stage
  stage=$(mktemp -d -- "$base/.install-$kind.XXXXXXXX")
  cp -a -- "$WORK/$kind-extracted/$name/." "$stage/"
  mv -T --no-clobber -- "$stage" "$destination"
  if [[ -d "$stage" ]]; then rm -rf -- "$stage"; fail 'Destination appeared during installation; existing toolchain preserved.'; fi
  if [[ "$kind" == java ]]; then
    local observed
    observed=$("$destination/bin/java" --version)
    [[ ${observed%%$'\n'*} == "openjdk $JAVA_REQUIRED "* ]] || fail 'Installed JDK version did not match.'
    "$destination/bin/javac" --version >/dev/null; "$destination/bin/jlink" --version >/dev/null
  else bash "$ROOT/tools/with-toolchain.sh" "$destination/bin/mvn" --version >/dev/null; fi
  select_home "$kind" "$destination"
  printf '%s selected for Stargate: %s\n' "$kind" "$destination"
}
if $NEED_JAVA; then install_tool java "$JAVA_SETUP_ROOT" "$JAVA_SETUP_URL" "$JAVA_SETUP_SIGNATURE_URL" "$JAVA_SETUP_SHA256" "$ROOT/containers/setup/temurin.asc" "$JAVA_SETUP_KEY_SHA256" "$JAVA_SETUP_KEY_FINGERPRINT"; fi
if $NEED_MAVEN; then install_tool maven "$MAVEN_SETUP_ROOT" "$MAVEN_SETUP_URL" "$MAVEN_SETUP_SIGNATURE_URL" "$MAVEN_SETUP_SHA256" "$ROOT/containers/setup/maven.asc" "$MAVEN_SETUP_KEY_SHA256" "$MAVEN_SETUP_KEY_FINGERPRINT"; fi
docker_fresh_packages() {
  local package status query_status
  command -v dpkg-query >/dev/null || fail 'Cannot inspect existing package state; automatic installation refused.'
  for package in docker.io docker-ce docker-ce-cli containerd containerd.io runc podman-docker; do
    if status=$(dpkg-query --show --showformat='${db:Status-Abbrev}' "$package" 2>/dev/null); then
      [[ "$status" != ii* ]] || fail "Existing runtime package: $package. Automatic installation refused to protect other workloads."
    else query_status=$?; [[ "$query_status" == 1 ]] || fail 'Cannot determine runtime package state.'; fi
  done
}
docker_fresh_processes() {
  local comm_file process_name proc_root=${1:-/proc}
  for comm_file in "$proc_root"/[0-9]*/comm; do
    [[ -e "$comm_file" ]] || continue
    if ! IFS= read -r process_name < "$comm_file"; then
      [[ ! -e "$comm_file" ]] || fail 'Cannot inspect running runtime processes; automatic installation refused.'
      continue
    fi
    case "$process_name" in dockerd|containerd) fail "Existing runtime process: $process_name. Automatic installation refused.";; esac
  done
}
docker_client_config_guard() {
  [[ -z ${DOCKER_HOST-} && -z ${DOCKER_CONTEXT-} ]] || fail 'A Docker host/context is selected in the environment; automatic local installation refused.'
  local client_config="${DOCKER_CONFIG:-$HOME/.docker}/config.json"
  [[ ! -e "$client_config" && ! -L "$client_config" ]] || fail 'Existing Docker client configuration found; automatic installation refused. Inspect it privately; no credentials were read.'
}
docker_fresh_paths() {
  local existing
  for existing in /var/lib/docker /etc/docker /var/lib/containerd /etc/containerd /run/containerd /run/docker.sock \
    /etc/systemd/system/docker.service /etc/systemd/system/docker.service.d /etc/systemd/system/docker.socket /etc/systemd/system/docker.socket.d \
    /etc/systemd/system/containerd.service /etc/systemd/system/containerd.service.d /lib/systemd/system/docker.service /lib/systemd/system/containerd.service \
    /usr/lib/systemd/system/docker.service /usr/lib/systemd/system/containerd.service /etc/default/docker /etc/default/containerd \
    /usr/local/bin/docker /usr/local/bin/dockerd /usr/local/sbin/dockerd /usr/bin/docker /usr/bin/dockerd; do
    if ! sudo -- /usr/bin/test ! -e "$existing" || ! sudo -- /usr/bin/test ! -L "$existing"; then fail "Existing container runtime path: $existing. Automatic installation refused."; fi
  done
}
if $NEED_DOCKER; then
  docker_client_config_guard
  printf '%s  %s\n' "$DOCKER_SETUP_KEY_SHA256" "$ROOT/containers/setup/docker.asc" | sha256sum --check --status || fail 'Docker key input changed.'
  docker_fresh_packages
  docker_fresh_processes /proc
  docker_fresh_paths
  [[ ! -e /etc/apt/sources.list.d/stargate-docker.sources && ! -e /etc/apt/keyrings/stargate-docker.asc ]] || fail 'Docker repository files already exist; inspect before retrying.'
  sudo -- /usr/bin/install -d -o root -g root -m 0755 /etc/apt/keyrings
  # Public input is deliberately opened without privilege; only the fixed output is root-written.
  # shellcheck disable=SC2024
  sudo -- /bin/sh -c 'set -C; umask 022; /usr/bin/cat > "$1"' sh /etc/apt/keyrings/stargate-docker.asc < "$ROOT/containers/setup/docker.asc"
  printf '%s\n' 'Types: deb' 'URIs: https://download.docker.com/linux/ubuntu' 'Suites: noble' 'Components: stable' 'Architectures: amd64' 'Signed-By: /etc/apt/keyrings/stargate-docker.asc' > "$WORK/docker.sources"
  # shellcheck disable=SC2024
  sudo -- /bin/sh -c 'set -C; umask 022; /usr/bin/cat > "$1"' sh /etc/apt/sources.list.d/stargate-docker.sources < "$WORK/docker.sources"
  sudo -- /usr/bin/apt-get -o APT::Update::Error-Mode=any update
  sudo -- /usr/bin/apt-get install --no-remove --no-upgrade --no-install-recommends --yes docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  printf '%s\n' 'Docker packages installed; the package manager may have started Docker.' 'No Docker-group membership was granted automatically. Check daemon and login access below.'
fi
if ! check; then
  printf '%s\n' 'Another step is needed. Existing Docker service/access problems and Compose-only repair are not changed automatically.' 'See docs/setup-prerequisites.md for exact commands; rerun checks after resolving them.'
  printf '%s\n' 'Read-only diagnosis: docker context show; docker info; id -nG' \
    'On a systemd host, inspect: sudo systemctl status docker --no-pager' \
    'Starting Docker can resume existing containers. Only after reviewing the host: sudo systemctl enable --now docker' \
    'Docker-group membership grants root-level control. If appropriate for this trusted operator:'
  printf '  sudo usermod --append --groups docker -- %q\n' "$(id -un)"
  printf '%s\n' 'Then log out and reconnect over SSH before rerunning the prerequisite check.'
  exit 2
fi
printf '\nPrerequisites ready. Reused/installed versions and paths are shown above. No Stargate services changed.\n'
