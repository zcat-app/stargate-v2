#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Opt-in proof with local authenticated public release files; no Docker/network.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
: "${STARGATE_TEST_SIMPLEX_RELEASE:?Select the authenticated local v7.0.0 release directory}"
: "${STARGATE_TEST_RUNTIME_INPUTS:?Select the qualified local prepared runtime context}"
proof=$(mktemp -d "${TMPDIR:-/tmp}/stargate-simplex-shell-test.XXXXXXXX")
cleanup() { rm -rf -- "$proof"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
checkout="$proof/checkout"
mkdir -p "$checkout/tools" "$checkout/containers/simplex-alert" "$checkout/simplex-alert/target" "$proof/release"
cp "$root/tools/prepare-simplex-alert.sh" "$checkout/tools/"
cp "$root/containers/simplex-alert/"{release.json,libraries.json,LICENSE-AGPL-3.0.txt} "$checkout/containers/simplex-alert/"
cp "$root/containers/java-runtime.json" "$checkout/containers/"
cp "$root/simplex-alert/target/simplex-alert-0.1.0-SNAPSHOT.jar" "$checkout/simplex-alert/target/"
for name in simplex-chat _sha256sums _sha256sums.asc release-key.asc; do cp --reflink=auto "$STARGATE_TEST_SIMPLEX_RELEASE/$name" "$proof/release/$name"; done
run() { bash "$checkout/tools/prepare-simplex-alert.sh" --release-dir "$proof/release" --runtime-inputs "$STARGATE_TEST_RUNTIME_INPUTS"; }
refuse() {
  local expected=$1
  if run > "$proof/result" 2>&1; then printf 'Unexpected success: %s\n' "$expected" >&2; exit 1; fi
  grep -Fq -- "$expected" "$proof/result" || { cat "$proof/result" >&2; exit 1; }
  [[ ! -e "$checkout/target/simplex-alert-container" ]]
  if [[ -d "$checkout/target" ]]; then [[ -z $(find "$checkout/target" -maxdepth 1 -name '.simplex-stage.*' -print -quit) ]]; fi
  printf 'PASS refusal: %s\n' "$expected"
}
printf x >> "$proof/release/simplex-chat"
refuse 'binary does not match'
cp --reflink=auto "$STARGATE_TEST_SIMPLEX_RELEASE/simplex-chat" "$proof/release/simplex-chat"
printf '\nunsigned change\n' >> "$proof/release/_sha256sums"
refuse 'signature verification failed'
cp "$STARGATE_TEST_SIMPLEX_RELEASE/_sha256sums" "$proof/release/_sha256sums"
jq '.signingFingerprint="0000000000000000000000000000000000000000"' "$checkout/containers/simplex-alert/release.json" > "$proof/pin"
mv "$proof/pin" "$checkout/containers/simplex-alert/release.json"
refuse 'signer differs'
cp "$root/containers/simplex-alert/release.json" "$checkout/containers/simplex-alert/release.json"
cp "$proof/release/release-key.asc" "$proof/key"
rm "$proof/release/release-key.asc"
ln -s "$proof/key" "$proof/release/release-key.asc"
refuse 'Missing regular release input'
rm "$proof/release/release-key.asc"
cp "$proof/key" "$proof/release/release-key.asc"
original_inputs=$STARGATE_TEST_RUNTIME_INPUTS
mkdir -p "$proof/linked-root/java"
ln -s "$original_inputs/rootfs-app" "$proof/linked-root/rootfs-app"
STARGATE_TEST_RUNTIME_INPUTS="$proof/linked-root" refuse 'Runtime roots must be real directories'
rm "$proof/linked-root/rootfs-app"
mkdir "$proof/linked-root/rootfs-app"
rmdir "$proof/linked-root/java"
ln -s "$original_inputs/java" "$proof/linked-root/java"
STARGATE_TEST_RUNTIME_INPUTS="$proof/linked-root" refuse 'Runtime roots must be real directories'
run > "$proof/result" 2>&1
output="$checkout/target/simplex-alert-container"
[[ -d "$output" && $(stat -c %a "$output") == 700 && $(stat -c %a "$output/simplex-chat") == 755 ]]
[[ $(stat -c %a "$output/simplex-alert.jar") == 644 && $(stat -c %a "$output/provenance") == 755 && $(stat -c %a "$output/provenance/image-inputs.json") == 644 ]]
[[ $(sha256sum < "$output/simplex-chat" | cut -d ' ' -f1) == $(jq -r .sha256 "$root/containers/simplex-alert/release.json") ]]
while IFS=$'\t' read -r path hash; do
  [[ -f "$output/$path" && ! -L "$output/$path" ]]
  [[ $(sha256sum < "$output/$path" | cut -d ' ' -f1) == "$hash" ]]
done < <(jq -r '.sha256 | to_entries[] | [.key,.value] | @tsv' "$output/provenance/image-inputs.json")
while IFS=$'\t' read -r path target; do [[ -L "$output/$path" && $(readlink "$output/$path") == "$target" ]]; done < <(jq -r '.symlinks | to_entries[] | [.key,.value] | @tsv' "$output/provenance/image-inputs.json")
printf 'PASS signed real release, private staging, copied-byte hashes and literal image symlinks\n'
printf sentinel > "$output/operator-sentinel"
if run > "$proof/result" 2>&1; then exit 1; fi
grep -Fq 'Output already exists' "$proof/result"
[[ $(cat "$output/operator-sentinel") == sentinel ]]
printf 'PASS existing output retained\n'
printf 'SimpleX Bash preparation proof passed. No Docker, network, profiles or messages.\n'
