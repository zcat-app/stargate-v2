#!/usr/bin/env bash
# Prepare a Tor-only context from an exact existing image, preserving its OS fixes.
# Does not start a container, access volumes, install host packages or build an image.
set -euo pipefail
umask 022
if [[ $# != 3 || ! $1 =~ ^sha256:[0-9a-f]{64}$ ]]; then
  echo 'Usage: prepare-tor-update.sh BASE_IMAGE_ID NEW_OUTPUT_DIRECTORY VERIFIED_DEB_DIRECTORY' >&2
  exit 64
fi
project=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
base=$1
output=$(realpath -m -- "$2")
packages=$(realpath -e -- "$3")
[[ ! -e $output && ! -L $output && -d $packages ]]
for tool in docker jq dpkg-deb sha256sum tar awk; do command -v "$tool" >/dev/null; done
mkdir -m 0755 -- "$output"
cp -- "$project/containers/tor-packages.json" "$output/tor-packages.json"
jq -e 'type=="array" and length==2 and
  ([.[].package]|sort)==["tor","tor-geoipdb"] and
  ([.[].version]|unique|length)==1 and
  all(.[]; (keys|sort)==["package","sha256","url","version"] and
    (.sha256|test("^[0-9a-f]{64}$")) and
    (.version|test("^[0-9]+(\\.[0-9]+){3}-[0-9]+~noble\\+[0-9]+$")))' \
  "$output/tor-packages.json" >/dev/null
mkdir -- "$output/rootfs-tor" "$output/unpacked" "$output/controls"
container=''
cleanup() { if [[ -n $container ]]; then docker rm -- "$container" >/dev/null; fi; }
trap cleanup EXIT
# An unstarted container has image files only, without any deployed router state.
container=$(docker create --network none --label app.zcat.stargate.purpose=tor-update-input "$base" --version)
docker export "$container" | tar --extract --same-permissions --no-same-owner --file - --directory "$output/rootfs-tor"
docker rm -- "$container" >/dev/null
container=''
root=$output/rootfs-tor
regular_destination() { [[ -f $1 && ! -L $1 && $(realpath -e -- "$1") == "$1" ]]; }
for path in usr/share/stargate/runtime-files.json var/lib/dpkg/status usr/bin/tor \
  usr/share/tor/geoip usr/share/tor/geoip6 \
  usr/share/stargate/licenses/tor.copyright usr/share/stargate/licenses/tor-geoipdb.copyright; do
  regular_destination "$root/$path"
done
[[ $(jq -r .image_role "$root/usr/share/stargate/runtime-files.json") == tor ]]
jq -e '.packages.tor.Version==.packages["tor-geoipdb"].Version and
  (.packages.tor.Version|test("^[0-9]+(\\.[0-9]+){3}-[0-9]+~noble\\+[0-9]+$"))' \
  "$root/usr/share/stargate/runtime-files.json" >/dev/null
find "$root" -type d -printf '%m %P\n' | sort > "$output/preserved-directory-modes.txt"
find "$root" -type f ! -path '*/usr/bin/tor' ! -path '*/usr/share/tor/geoip*' \
  ! -path '*/usr/share/stargate/runtime-files.json' ! -path '*/var/lib/dpkg/status' \
  ! -path '*/usr/share/stargate/licenses/tor*.copyright' -print0 | sort -z | xargs -0 sha256sum > "$output/preserved-files.sha256"
while IFS=$'\t' read -r name version url hash; do
  arch=all; [[ $name != tor ]] || arch=amd64
  filename=${name}_${version}_${arch}.deb
  [[ $url == "https://deb.torproject.org/torproject.org/pool/main/t/tor/$filename" ]]
  deb=$packages/$filename
  printf '%s  %s\n' "$hash" "$deb" | sha256sum --check --status
  [[ $(dpkg-deb --field "$deb" Package) == "$name" && $(dpkg-deb --field "$deb" Version) == "$version" && $(dpkg-deb --field "$deb" Architecture) == "$arch" ]]
  dpkg-deb --extract "$deb" "$output/unpacked"
  dpkg-deb --field "$deb" > "$output/controls/$name"
done < <(jq -r '.[]|[.package,.version,.url,.sha256]|@tsv' "$output/tor-packages.json")
for path in usr/bin/tor usr/share/tor/geoip usr/share/tor/geoip6; do
  [[ -f $output/unpacked/$path && ! -L $output/unpacked/$path ]]
  regular_destination "$root/$path"
  cp --preserve=mode -- "$output/unpacked/$path" "$root/$path"
  hash=$(sha256sum "$root/$path"); hash=${hash%% *}
  jq --arg path "/$path" --arg hash "$hash" '.files|=map(if .path==$path then .sha256=$hash else . end)' \
    "$root/usr/share/stargate/runtime-files.json" > "$output/record.tmp"
  mv -- "$output/record.tmp" "$root/usr/share/stargate/runtime-files.json"
done
awk 'BEGIN {RS="";ORS="\n\n"} $0 !~ /^Package: tor(-geoipdb)?\n/ {print}' "$root/var/lib/dpkg/status" > "$output/status.tmp"
for name in tor tor-geoipdb; do
  regular_destination "$root/usr/share/stargate/licenses/$name.copyright"
  [[ $(realpath -e -- "$output/unpacked/usr/share/doc/$name/copyright") == "$output/unpacked/"* ]]
  cp -L -- "$output/unpacked/usr/share/doc/$name/copyright" "$root/usr/share/stargate/licenses/$name.copyright"
  cat "$output/controls/$name" >> "$output/status.tmp"
  printf 'Status: install ok installed\nX-Stargate-Runtime-Slice: yes\n\n' >> "$output/status.tmp"
  jq -Rn '[inputs|select(test("^[A-Za-z0-9-]+: "))|capture("(?<key>[^:]+): (?<value>.*)")|{(.key):.value}]|add|.Status="install ok installed"|.["X-Stargate-Runtime-Slice"]="yes"' \
    < "$output/controls/$name" > "$output/control.json"
  jq --arg name "$name" --slurpfile control "$output/control.json" '.packages[$name]=$control[0]' \
    "$root/usr/share/stargate/runtime-files.json" > "$output/record.tmp"
  mv -- "$output/record.tmp" "$root/usr/share/stargate/runtime-files.json"
done
mv -- "$output/status.tmp" "$root/var/lib/dpkg/status"
for name in tor tor-geoipdb; do
  hash=$(sha256sum "$root/usr/share/stargate/licenses/$name.copyright"); hash=${hash%% *}
  jq --arg path "/usr/share/stargate/licenses/$name.copyright" --arg hash "$hash" '.files|=map(if .path==$path then .sha256=$hash else . end)' "$root/usr/share/stargate/runtime-files.json" > "$output/record.tmp"
  mv -- "$output/record.tmp" "$root/usr/share/stargate/runtime-files.json"
done
jq --arg base "$base" '.previous_runtime_source_image_id=.source_image_id|.source_image_id=$base|.method="Tor package files updated from checksum-pinned release artifacts; all other runtime files preserved from the exact base image. Package control metadata describes file subsets."' \
  "$root/usr/share/stargate/runtime-files.json" > "$output/record.tmp"
mv -- "$output/record.tmp" "$root/usr/share/stargate/runtime-files.json"
sha256sum --check --status "$output/preserved-files.sha256"
find "$root" -type d -printf '%m %P\n' | sort > "$output/directory-modes-after.txt"
cmp -- "$output/preserved-directory-modes.txt" "$output/directory-modes-after.txt"
install -d -m 0700 "$output/owned-tor/var/lib/tor" "$output/owned-tor/run/tor-control"
cp -- "$project/containers/torrc" "$output/torrc"
printf 'Prepared %s from %s; preserved non-Tor files verified. No image built.\n' "$output" "$base"
