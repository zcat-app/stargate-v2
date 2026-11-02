#!/usr/bin/env bash
# Synthetic boundary tests; no real administrator token or product container.
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
fixture=$(mktemp -d /tmp/stargate-token-tests-XXXXXXXX)
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/bin" "$fixture/data"
cat > "$fixture/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
printf '%s\0' "$@" > "$TOKEN_TEST_ARGS"
cat -- "$TOKEN_TEST_ARCHIVE"
exit "${TOKEN_TEST_EXIT:-0}"
DOCKER
chmod 0755 "$fixture/bin/docker"
export PATH="$fixture/bin:$PATH" TOKEN_TEST_ARGS="$fixture/args" TOKEN_TEST_ARCHIVE="$fixture/archive.tar"
printf '%043d\n' 0 > "$fixture/data/admin-token"
tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token
bash "$root/tools/container-token.sh" --project 'synthetic-project' --env-file 'literal path/$not-expanded.env' > "$fixture/result"
cmp "$fixture/result" "$fixture/data/admin-token"
mapfile -d '' -t args < "$TOKEN_TEST_ARGS"
[[ ${args[*]} == "compose --project-name synthetic-project --env-file literal path/\$not-expanded.env cp app:/data/admin-token -" ]]
refused() { if bash "$root/tools/container-token.sh" > "$fixture/result" 2> "$fixture/error"; then printf 'Unexpected success: %s\n' "$1" >&2; exit 1; fi; [[ ! -s $fixture/result ]]; }
TOKEN_TEST_EXIT=1; export TOKEN_TEST_EXIT; refused 'Docker failure after valid bytes'; unset TOKEN_TEST_EXIT
printf '%s' invalid > "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token; refused 'invalid token'
printf '%043d\0\n' 0 > "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token; refused 'binary token'
printf '%043d\n%043d\n' 0 0 > "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token; refused 'multiple lines'
printf '%043d\n' 0 > "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token admin-token; refused 'duplicate members'
printf '%s' extra > "$fixture/data/extra"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token extra; refused 'extra member'
rm "$fixture/data/admin-token"; ln -s extra "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token; refused 'symlink member'
rm "$fixture/data/admin-token"; ln "$fixture/data/extra" "$fixture/data/admin-token"; tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" extra admin-token; tar --delete -f "$TOKEN_TEST_ARCHIVE" extra; refused 'hardlink member'
head -c 70000 /dev/zero > "$TOKEN_TEST_ARCHIVE"; refused 'oversized archive'
printf '%s' 'not tar' > "$TOKEN_TEST_ARCHIVE"; refused 'malformed archive'
if bash "$root/tools/container-token.sh" --project > "$fixture/result" 2>/dev/null; then exit 1; fi
[[ ! -s $fixture/result ]]
printf '%s\n' 'Token export synthetic checks PASS'
# Execute the guide's actual export block against the synthetic Docker response.
rm "$fixture/data/admin-token"
printf '%043d\n' 0 > "$fixture/data/admin-token"
tar -cf "$TOKEN_TEST_ARCHIVE" -C "$fixture/data" admin-token
export TOKEN_TEST_PRIVATE_OUTPUT="$fixture/private" stargate_config="$fixture/compose.json" stargate_project=synthetic-project
mkdir -m 0700 "$TOKEN_TEST_PRIVATE_OUTPUT"
printf '%s' previous-copy > "$TOKEN_TEST_PRIVATE_OUTPUT/admin-token"
chmod 0644 "$TOKEN_TEST_PRIVATE_OUTPUT/admin-token"
guide_substitution="s|\"\$HOME/.local/share/stargate-admin\"|\"\$TOKEN_TEST_PRIVATE_OUTPUT\"|"
awk '/^### Retrieve and keep/{section=1} section && /^```sh/{printing=1;next} printing && /^```/{exit} printing{print}' "$root/docs/operator-guide.md" | sed "$guide_substitution" > "$fixture/guide.sh"
(cd "$root" && bash "$fixture/guide.sh")
cmp "$TOKEN_TEST_PRIVATE_OUTPUT/admin-token" "$fixture/data/admin-token"
[[ $(stat -c '%a' "$TOKEN_TEST_PRIVATE_OUTPUT/admin-token") == 600 ]]
TOKEN_TEST_EXIT=1; export TOKEN_TEST_EXIT
if (cd "$root" && bash "$fixture/guide.sh") > "$fixture/result" 2> "$fixture/error"; then exit 1; fi
cmp "$TOKEN_TEST_PRIVATE_OUTPUT/admin-token" "$fixture/data/admin-token"
[[ ! -s $fixture/result ]]
[[ $(find "$TOKEN_TEST_PRIVATE_OUTPUT" -name '.admin-token-*' | wc -l) == 0 ]]
printf '%s\n' 'Guide repeat-export permissions and failure preservation PASS'
