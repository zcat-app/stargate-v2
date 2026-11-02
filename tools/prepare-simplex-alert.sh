#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Local public build inputs only: no downloads, Docker, profiles or services.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
release=''; inputs="$root/target/container"; stage=''; gpg_home=''
fail() { printf '%s\n' "$*" >&2; exit 1; }
cleanup() {
  if [[ -n "$gpg_home" ]]; then
    gpgconf --homedir "$gpg_home" --kill gpg-agent >/dev/null 2>&1 || true
    rm -rf -- "$gpg_home"
  fi
  if [[ -n "$stage" ]]; then rm -rf -- "$stage"; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
while (( $# )); do
  case "$1" in
    --release-dir) [[ $# -ge 2 && -z "$release" ]] || fail 'Use --release-dir once with a path.'; release=$2; shift 2 ;;
    --runtime-inputs) [[ $# -ge 2 ]] || fail 'Missing runtime inputs path.'; inputs=$2; shift 2 ;;
    --help|-h) printf '%s\n' 'Usage: bash tools/prepare-simplex-alert.sh --release-dir VERIFIED_RELEASE [--runtime-inputs PREPARED_CONTEXT]' 'Output: target/simplex-alert-container (must not exist). No downloads, Docker, profiles or deployment.'; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done
[[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || fail 'Qualified only for Linux amd64.'
[[ -n "$release" ]] || fail 'Select the already authenticated local release directory.'
for tool in jq gpg gpgconf sha256sum realpath cp find mv; do command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"; done
release=$(realpath -e -- "$release"); inputs=$(realpath -e -- "$inputs")
pin="$root/containers/simplex-alert/release.json"
hash=$(jq -er '.sha256 | select(test("^[0-9a-f]{64}$"))' "$pin")
signer=$(jq -er '.signingFingerprint | select(test("^[0-9A-F]{40}$"))' "$pin")
artifact=$(jq -er '.artifact | select(test("^[A-Za-z0-9_./-]+$"))' "$pin")
for name in simplex-chat _sha256sums _sha256sums.asc release-key.asc; do
  [[ -f "$release/$name" && ! -L "$release/$name" ]] || fail "Missing regular release input: $name"
done
printf '%s  %s\n' "$hash" "$release/simplex-chat" | sha256sum --check --strict --status || fail 'SimpleX binary does not match the release pin.'
[[ $(grep -Fxc -- "$hash  $artifact" "$release/_sha256sums") == 1 ]] || fail 'Pinned artifact must occur exactly once in the signed manifest.'
gpg_home=$(mktemp -d "${TMPDIR:-/tmp}/stargate-simplex-gpg.XXXXXXXX")
chmod 0700 "$gpg_home"
gpg_args=(gpg --homedir "$gpg_home" --batch --no-auto-key-retrieve)
"${gpg_args[@]}" --import "$release/release-key.asc" >/dev/null 2>&1 || fail 'Release key import failed.'
"${gpg_args[@]}" --status-fd 1 --verify "$release/_sha256sums.asc" "$release/_sha256sums" > "$gpg_home/status" 2> "$gpg_home/diagnostics" || fail 'Release signature verification failed.'
awk -v signer="$signer" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==signer || $NF==signer) {matched=1} END {exit !matched}' "$gpg_home/status" || fail 'Release signer differs from the independent pin.'
[[ -d "$inputs/rootfs-app" && ! -L "$inputs/rootfs-app" && -d "$inputs/java" && ! -L "$inputs/java" ]] || fail 'Runtime roots must be real directories, not symlinks.'
[[ -x "$inputs/java/bin/java" ]] || fail 'Prepare the patched runtime inputs first.'
version=$("$inputs/java/bin/java" --version)
java_version=$(jq -er '.version | select(test("^[0-9]+(\\.[0-9]+)*$"))' "$root/containers/java-runtime.json")
[[ "$version" == "openjdk $java_version "* ]] || fail "Expected the qualified Java $java_version runtime."
jar="$root/simplex-alert/target/simplex-alert-0.1.0-SNAPSHOT.jar"
[[ -f "$jar" && ! -L "$jar" ]] || fail 'Build the sender first: bash tools/with-toolchain.sh mvn -f simplex-alert/pom.xml package'
destination="$root/target/simplex-alert-container"
[[ ! -e "$destination" && ! -L "$destination" ]] || fail 'Output already exists; preserve/review it before a deliberate restage.'
mkdir -p -- "$root/target"
[[ $(realpath -e -- "$root/target") == "$root/target" ]] || fail 'Output parent must not be a symlink.'
stage=$(mktemp -d "$root/target/.simplex-stage.XXXXXXXX")
cp -a -- "$inputs/rootfs-app" "$stage/rootfs"
cp -a -- "$inputs/java" "$stage/java"
[[ -z $(find "$stage" ! -type f ! -type d ! -type l -print -quit) ]] || fail 'Runtime inputs contain a special file.'
cp --preserve=mode,timestamps -- "$release/simplex-chat" "$stage/simplex-chat"
chmod 0755 "$stage/simplex-chat"
cp -- "$jar" "$stage/simplex-alert.jar"
mkdir "$stage/provenance"
cp -- "$pin" "$stage/provenance/release.json"
cp -- "$root/containers/simplex-alert/libraries.json" "$root/containers/simplex-alert/LICENSE-AGPL-3.0.txt" "$stage/provenance/"
for name in _sha256sums _sha256sums.asc release-key.asc; do cp -- "$release/$name" "$stage/provenance/$name"; done
expected_hash=$(jq -er .sha256 "$stage/provenance/release.json")
printf '%s  %s\n' "$expected_hash" "$stage/simplex-chat" | sha256sum --check --strict --status || fail 'Copied binary differs from the release pin.'
"${gpg_args[@]}" --status-fd 1 --verify "$stage/provenance/_sha256sums.asc" "$stage/provenance/_sha256sums" > "$gpg_home/status" 2> "$gpg_home/diagnostics" || fail 'Copied release signature verification failed.'
awk -v signer="$signer" '$1=="[GNUPG:]" && $2=="VALIDSIG" && ($3==signer || $NF==signer) {matched=1} END {exit !matched}' "$gpg_home/status" || fail 'Copied release signer differs from the independent pin.'
[[ $(grep -Fxc -- "$expected_hash  $artifact" "$stage/provenance/_sha256sums") == 1 ]] || fail 'Copied manifest differs from the pinned artifact.'
cat > "$stage/provenance/NOTICE" <<'NOTICE'
SimpleX Chat upstream binary, AGPL-3.0. Corresponding version source:
https://github.com/simplex-chat/simplex-chat/tree/v7.0.0
Signature key matched the officially published fingerprint;
this is not independent out-of-band owner authentication.
NOTICE
chmod 0644 "$stage/simplex-alert.jar" "$stage/provenance/"*
chmod 0755 "$stage/provenance"
# Do not follow image symlinks into the host. Record their literal targets.
printf '{}\n' > "$stage/provenance/file-hashes.tmp"
printf '{}\n' > "$stage/provenance/link-targets.tmp"
while IFS= read -r -d '' path; do
  relative=${path#"$stage/"}
  [[ "$relative" != provenance/*.tmp ]] || continue
  hash=$(sha256sum < "$path"); hash=${hash%% *}
  jq --arg path "$relative" --arg hash "$hash" '. + {($path):$hash}' "$stage/provenance/file-hashes.tmp" > "$stage/provenance/next.tmp"
  mv -- "$stage/provenance/next.tmp" "$stage/provenance/file-hashes.tmp"
done < <(find "$stage" -type f -print0)
while IFS= read -r -d '' path; do
  relative=${path#"$stage/"}; target=$(readlink -- "$path")
  jq --arg path "$relative" --arg target "$target" '. + {($path):$target}' "$stage/provenance/link-targets.tmp" > "$stage/provenance/next.tmp"
  mv -- "$stage/provenance/next.tmp" "$stage/provenance/link-targets.tmp"
done < <(find "$stage" -type l -print0)
jq -n --arg java "$version" --slurpfile hashes "$stage/provenance/file-hashes.tmp" --slurpfile links "$stage/provenance/link-targets.tmp" '{java:$java,sha256:$hashes[0],symlinks:$links[0]}' > "$stage/provenance/image-inputs.json"
chmod 0644 "$stage/provenance/image-inputs.json"
rm -- "$stage/provenance/file-hashes.tmp" "$stage/provenance/link-targets.tmp"
mv -T --no-clobber -- "$stage" "$destination"
[[ ! -e "$stage" ]] || fail 'Output appeared concurrently; no existing output was replaced.'
stage=''
printf '%s\n' 'Prepared opt-in SimpleX image inputs; no service was started.'
