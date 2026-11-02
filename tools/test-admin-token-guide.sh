#!/usr/bin/env bash
# Synthetic commands only. No real token, SSH host, desktop clipboard or Docker.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
fixture=$(mktemp -d /tmp/stargate-admin-guide-test-XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/bin" "$fixture/local"
export GUIDE_TEST_FIXTURE="$fixture" GUIDE_TEST_LOCAL_DIRECTORY="$fixture/local" GUIDE_TEST_REMOTE_EXPORT="$fixture/remote-export"
printf '%043d\n' 0 > "$fixture/original-token"
cp "$fixture/original-token" "$GUIDE_TEST_REMOTE_EXPORT"
extract() {
  awk -v marker="$1" '/^```sh/{inside=1;block="";next} inside && /^```/{if(index(block,"# stargate-guide: " marker "\n"))printf "%s",block;inside=0;next} inside{block=block $0 "\n"}' "$root/docs/operator-guide.md" > "$fixture/$1.sh"
  [[ -s "$fixture/$1.sh" ]]
  # Substitute only laptop paths, leaving the remote SSH command literal intact.
  sed -i "s|^admin_directory=.*|admin_directory=\"\$GUIDE_TEST_LOCAL_DIRECTORY\"|;s|^    less -- .*|    less -- \"\$GUIDE_TEST_LOCAL_DIRECTORY/admin-token\"|;s|^rm -f -- .*|rm -f -- \"\$GUIDE_TEST_LOCAL_DIRECTORY/admin-token\"|" "$fixture/$1.sh"
  bash -n "$fixture/$1.sh"
}
for block in laptop-copy laptop-view token-cleanup clipboard-wayland clipboard-x11; do extract "$block"; done
cat > "$fixture/bin/scp" <<'SCP'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 3 && $1 == -- && $2 == OPERATOR@VPS_HOST:.local/share/stargate-admin/admin-token ]]
cp -- "$GUIDE_TEST_REMOTE_EXPORT" "$3"
exit "${GUIDE_TEST_SCP_FAIL:-0}"
SCP
cat > "$fixture/bin/ssh" <<'SSH'
#!/usr/bin/env bash
set -euo pipefail
expected="rm -f -- \"\$HOME/.local/share/stargate-admin/admin-token\""
[[ $# == 2 && $1 == OPERATOR@VPS_HOST && $2 == "$expected" ]]
rm -f -- "$GUIDE_TEST_REMOTE_EXPORT"
SSH
cat > "$fixture/bin/less" <<'LESS'
#!/usr/bin/env bash
set -euo pipefail
[[ ${LESSSECURE-} == 1 && ${LESSHISTFILE-} == - && -z ${LESS-} && -z ${LESSOPEN-} && -z ${LESSCLOSE-} && -z ${LESS_IS_MORE-} && -z ${LESSSECURE_ALLOW-} ]]
touch "$GUIDE_TEST_FIXTURE/view-used"
exec /usr/bin/less "$@"
LESS
cat > "$fixture/bin/wl-copy" <<'WAYLAND'
#!/usr/bin/env bash
set -euo pipefail
[[ $* == --clear || $* == '--primary --clear' ]]
printf '%s\n' "$*" >> "$GUIDE_TEST_FIXTURE/wayland"
WAYLAND
cat > "$fixture/bin/xclip" <<'X11'
#!/usr/bin/env bash
set -euo pipefail
[[ $# == 2 && $1 == -selection && ( $2 == clipboard || $2 == primary ) ]]
[[ $(wc -c) == 0 ]]
printf '%s\n' "$*" >> "$GUIDE_TEST_FIXTURE/x11"
X11
chmod 0755 "$fixture/bin/"*
export PATH="$fixture/bin:$PATH"
printf '%s' previous-export > "$fixture/local/admin-token"
chmod 0644 "$fixture/local/admin-token"
bash "$fixture/laptop-copy.sh"
cmp "$fixture/local/admin-token" "$fixture/original-token"
[[ $(stat -c '%a' "$fixture/local/admin-token") == 600 ]]
if GUIDE_TEST_SCP_FAIL=1 bash "$fixture/laptop-copy.sh" > "$fixture/failed.stdout" 2> "$fixture/failed.stderr"; then exit 1; fi
cmp "$fixture/local/admin-token" "$fixture/original-token"
[[ ! -s $fixture/failed.stdout && $(find "$fixture/local" -name '.admin-token-*' | wc -l) == 0 ]]
if bash "$fixture/laptop-view.sh" > "$fixture/noninteractive.stdout" 2> "$fixture/noninteractive.stderr"; then exit 1; fi
[[ ! -s $fixture/noninteractive.stdout && ! -e $fixture/view-used ]]
printf q | env TERM=xterm LESSSECURE_ALLOW=shell,edit,logfile,lesskey LESS="-o$fixture/unwanted-log" LESSOPEN="touch $fixture/unwanted-filter" LESSCLOSE="touch $fixture/unwanted-close" \
  script -q -e -c "bash '$fixture/laptop-view.sh'" /dev/null > "$fixture/view.stdout"
[[ -f $fixture/view-used && ! -e $fixture/unwanted-log && ! -e $fixture/unwanted-filter && ! -e $fixture/unwanted-close ]]
grep -Fqf "$fixture/original-token" "$fixture/view.stdout"
bash "$fixture/clipboard-wayland.sh"
bash "$fixture/clipboard-x11.sh"
[[ $(wc -l < "$fixture/wayland") == 2 && $(wc -l < "$fixture/x11") == 2 ]]
bash "$fixture/token-cleanup.sh"
[[ ! -e $fixture/local/admin-token && ! -e $GUIDE_TEST_REMOTE_EXPORT ]]
[[ $(stat -c '%s' "$fixture/original-token") == 44 ]]
printf '%s\n' 'Guide copy/permissions/failure/viewer/clipboard-arguments/cleanup checks PASS'
