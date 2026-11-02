# Export an administrator token

Use `bash tools/container-token.sh`, preserving the installation's selected
`COMPOSE_FILE`, optional `--project NAME` and `--env-file PATH`, and Docker
context. The [operator guide](operator-guide.md#retrieve-and-keep-the-administrator-token)
contains the private-file export procedure. The helper uses Bash, Docker Compose and standard GNU utilities; no utility inside the app image or host Java is required.

The token is still read from `app:/data/admin-token` through Docker's archive
stream and written unchanged to stdout. The helper does not rotate credentials,
start a container, modify a volume or print a token before validation finishes.
It disables tracing, ignores `TAR_OPTIONS`, stages privately under root-owned
sticky `/tmp`, limits the archive to 64 KiB and requires exactly one regular
`admin-token` member. Token bytes must be one line of 43–128 URL-safe characters,
with an optional final newline; malformed, binary, oversized, duplicate and
link inputs fail without token output. All staging files are removed on normal
completion/failure and handled signals; a hard kill can leave a private temporary
directory. These bounds cover the actual tiny Docker token archive, not user
connection capacity.

Stdout is intentional: use `umask 077` **before the caller's redirection** to a
private destination. The helper cannot change permissions on a file already
opened by the caller. The operator guide therefore stages into a fresh private
file and atomically replaces the final copy, rather than redirecting over an
existing possibly looser file. It also cannot prevent an operator from deliberately
displaying/copying the token. Preserve the original token in the app-data volume;
exported copies are not encrypted vaults.
