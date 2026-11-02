#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
# Private PATH/home/checkout fixtures; privileged host operations are forbidden.
set -euo pipefail
umask 077
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
TEST=$(mktemp -d /tmp/stargate-prerequisites-test.XXXXXXXX)
trap 'rm -rf -- "$TEST"' EXIT
mkdir -m 700 "$TEST/bin" "$TEST/home" "$TEST/project"
mkdir -p "$TEST/project/tools" "$TEST/project/containers/setup"
cp "$ROOT/tools/setup-prerequisites.sh" "$ROOT/tools/with-toolchain.sh" "$TEST/project/tools/"
cp "$ROOT/containers/java-runtime.json" "$TEST/project/containers/"
cp "$ROOT/containers/setup/"* "$TEST/project/containers/setup/"
export PREREQ_TEST=$TEST PREREQ_CACHE="$ROOT/target/prerequisite-downloads"
cat > "$TEST/bin/docker" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$PREREQ_TEST/docker-calls"
case "$*" in
 '--version') printf 'Docker version 29.1.3, fixture\n';;
 'compose version --short') printf '%s\n' "${PREREQ_COMPOSE:-5.1.4}";;
 'info --format {{.ServerVersion}}') [[ ${PREREQ_ACCESS:-true} == true ]];;
 *) exit 91;;
esac
SH
cat > "$TEST/bin/sudo" <<'SH'
#!/usr/bin/env bash
printf 'Unexpected privileged operation\n' >> "$PREREQ_TEST/sudo-calls"
exit 92
SH
for tool in java javac jlink mvn; do printf '#!/usr/bin/env bash\nexit 1\n' > "$TEST/bin/$tool"; done
cat > "$TEST/bin/curl" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
out='';url=${@: -1}
while [[ $# -gt 0 ]]; do if [[ $1 == --output ]]; then out=$2; shift; fi; shift; done
case "$url" in
 *OpenJDK25U*.tar.gz) file=temurin-jdk.tar.gz;;
 *OpenJDK25U*.tar.gz.sig) file=temurin-jdk.tar.gz.sig;;
 *apache-maven*.tar.gz) file=maven.tar.gz;;
 *apache-maven*.tar.gz.asc) file=maven.tar.gz.asc;;
 *) exit 93;;
esac
cp -- "$PREREQ_CACHE/$file" "$out"
if [[ ${PREREQ_TAMPER:-false} == true && $file == temurin-jdk.tar.gz ]]; then printf 'tamper' >> "$out"; fi
if [[ ${PREREQ_WRONG_SIGNATURE:-false} == true && $file == temurin-jdk.tar.gz.sig ]]; then cp "$PREREQ_CACHE/maven.tar.gz.asc" "$out"; fi
SH
chmod 700 "$TEST/bin/"*
export PATH="$TEST/bin:$PATH" HOME="$TEST/home"
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_CONFIG
run() { bash "$TEST/project/tools/setup-prerequisites.sh" "$@"; }
run --check images > "$TEST/images.log"
[[ ! -e "$TEST/project/.local-setup" && ! -e "$TEST/sudo-calls" ]]
printf 'PASS image check needs no Java and writes no selection\n'
export PREREQ_ACCESS=false
if run --check images > "$TEST/access.log"; then exit 1; else [[ $? == 2 ]]; fi
[[ ! -e "$TEST/sudo-calls" ]]
unset PREREQ_ACCESS
export PREREQ_COMPOSE=2.24.3
if run --check images > "$TEST/compose.log"; then exit 1; else [[ $? == 2 ]]; fi
unset PREREQ_COMPOSE
printf 'PASS missing access/Compose reported without repair\n'
printf 'no\n' | run --guided tools > "$TEST/cancel.log"
[[ ! -e "$TEST/home/.local" && ! -e "$TEST/project/.local-setup" && ! -e "$TEST/sudo-calls" ]]
if run --guided tools </dev/null > "$TEST/eof.log"; then exit 1; else [[ $? == 130 ]]; fi
printf 'PASS cancellation/EOF performs no installation\n'
# A successful process alone is insufficient: all effective Java tools and the
# Maven JVM must match the selected baseline.
printf '#!/usr/bin/env bash\nprintf "openjdk 25.0.5 fixture\\n"\n' > "$TEST/bin/java"
printf '#!/usr/bin/env bash\nprintf "javac 21.0.1\\n"\n' > "$TEST/bin/javac"
printf '#!/usr/bin/env bash\nprintf "25.0.5\\n"\n' > "$TEST/bin/jlink"
if run --check tools > "$TEST/mixed-compiler.log"; then exit 1; else [[ $? == 2 ]]; fi
printf '#!/usr/bin/env bash\nprintf "javac 25.0.5\\n"\n' > "$TEST/bin/javac"
printf '#!/usr/bin/env bash\nprintf "21.0.1\\n"\n' > "$TEST/bin/jlink"
if run --check tools > "$TEST/mixed-linker.log"; then exit 1; else [[ $? == 2 ]]; fi
printf '#!/usr/bin/env bash\nprintf "25.0.5\\n"\n' > "$TEST/bin/jlink"
printf '#!/usr/bin/env bash\nprintf "Apache Maven 3.10.0 fixture\\nJava version: 21.0.1, fixture\\n"\n' > "$TEST/bin/mvn"
if run --check build > "$TEST/mixed-maven.log"; then exit 1; else [[ $? == 2 ]]; fi
printf '#!/usr/bin/env bash\nprintf "Apache Maven 3.8.0 fixture\\nJava version: 25.0.5, fixture\\n"\n' > "$TEST/bin/mvn"
if run --check build > "$TEST/old-maven.log"; then exit 1; else [[ $? == 2 ]]; fi
for tool in java javac jlink mvn; do printf '#!/usr/bin/env bash\nexit 1\n' > "$TEST/bin/$tool"; done
printf 'PASS mixed compilers/linkers/Maven JVM and unqualified Maven refused\n'
cat > "$TEST/bin/dpkg-query" <<'SH'
#!/usr/bin/env bash
if [[ ${@: -1} == containerd ]]; then printf 'ii '; exit 0; fi
exit 1
SH
chmod 700 "$TEST/bin/dpkg-query"
guard=$(sed -n '/^docker_fresh_packages() {/,/^}/p' "$ROOT/tools/setup-prerequisites.sh")
if bash -c "$guard"'; fail() { printf "%s\n" "$*"; exit 1; }; docker_fresh_packages' > "$TEST/runtime-guard.log"; then exit 1; fi
grep -Fq 'Existing runtime package: containerd' "$TEST/runtime-guard.log"
[[ ! -e "$TEST/sudo-calls" ]]
printf 'PASS existing containerd package refused before privileged writes\n'
mkdir -p "$TEST/proc/1"
printf 'dockerd\n' > "$TEST/proc/1/comm"
process_guard=$(sed -n '/^docker_fresh_processes() {/,/^}/p' "$ROOT/tools/setup-prerequisites.sh")
if bash -c "$process_guard"'; fail() { printf "%s\n" "$*"; exit 1; }; docker_fresh_processes "$1"' bash "$TEST/proc" > "$TEST/process-guard.log"; then exit 1; fi
grep -Fq 'Existing runtime process: dockerd' "$TEST/process-guard.log"
mkdir -m 700 "$TEST/home/.docker"
printf '{"currentContext":"fixture-remote"}\n' > "$TEST/home/.docker/config.json"
client_guard=$(sed -n '/^docker_client_config_guard() {/,/^}/p' "$ROOT/tools/setup-prerequisites.sh")
if bash -c "$client_guard"'; fail() { printf "%s\n" "$*"; exit 1; }; docker_client_config_guard' > "$TEST/client-guard.log"; then exit 1; fi
grep -Fq 'Existing Docker client configuration' "$TEST/client-guard.log"
if grep -Fq fixture-remote "$TEST/client-guard.log"; then exit 1; fi
rm -- "$TEST/home/.docker/config.json"
mkdir -m 700 "$TEST/path-guard-bin"
cat > "$TEST/path-guard-bin/sudo" <<'SH'
#!/usr/bin/env bash
[[ $# == 5 && $1 == -- && $2 == /usr/bin/test && $3 == '!' && ( $4 == -e || $4 == -L ) ]] || exit 92
[[ $5 != /usr/bin/docker ]]
SH
chmod 700 "$TEST/path-guard-bin/sudo"
path_guard=$(sed -n '/^docker_fresh_paths() {/,/^}/p' "$ROOT/tools/setup-prerequisites.sh")
if PATH="$TEST/path-guard-bin:$PATH" bash -c "$path_guard"'; fail() { printf "%s\n" "$*"; exit 1; }; docker_fresh_paths' > "$TEST/path-guard.log"; then exit 1; fi
grep -Fq 'Existing container runtime path: /usr/bin/docker' "$TEST/path-guard.log"
printf 'PASS stored Docker context and non-executable client path refused\n'
if [[ -f "$PREREQ_CACHE/temurin-jdk.tar.gz" && -f "$PREREQ_CACHE/maven.tar.gz" ]]; then
 export PREREQ_TAMPER=true
 if printf 'yes\n' | run --guided tools > "$TEST/tamper.log" 2>&1; then exit 1; fi
 [[ ! -e "$TEST/project/.local-setup/java-home" ]]
 grep -Fq 'java checksum mismatch' "$TEST/tamper.log"
 unset PREREQ_TAMPER
 printf 'PASS tampered release rejected before activation\n'
 export PREREQ_WRONG_SIGNATURE=true
 if printf 'yes\n' | run --guided tools > "$TEST/signature.log" 2>&1; then exit 1; fi
 [[ ! -e "$TEST/project/.local-setup/java-home" ]]
 grep -Fq 'java signature was rejected' "$TEST/signature.log"
 unset PREREQ_WRONG_SIGNATURE
 sed -i 's/^JAVA_SETUP_KEY_FINGERPRINT=.*/JAVA_SETUP_KEY_FINGERPRINT=0000000000000000000000000000000000000000/' "$TEST/project/containers/setup/prerequisites.sh"
 if printf 'yes\n' | run --guided tools > "$TEST/signer.log" 2>&1; then exit 1; fi
 [[ ! -e "$TEST/project/.local-setup/java-home" ]]
 grep -Fq 'java signer does not match its pin' "$TEST/signer.log"
 cp "$ROOT/containers/setup/prerequisites.sh" "$TEST/project/containers/setup/prerequisites.sh"
 printf 'PASS invalid signature and wrong signer rejected before activation\n'
 printf 'yes\n' | run --guided build > "$TEST/installed.log"
 run --check build > "$TEST/recheck.log"
 [[ $(stat -c %a "$TEST/project/.local-setup/java-home") == 600 && $(stat -c %a "$TEST/project/.local-setup") == 700 ]]
 [[ ! -e "$TEST/sudo-calls" ]]
 bash "$TEST/project/tools/with-toolchain.sh" java --version > "$TEST/java-version.txt"
 bash "$TEST/project/tools/with-toolchain.sh" mvn --version > "$TEST/maven-version.txt"
 grep -Fq 'openjdk 25.0.5 ' "$TEST/java-version.txt"
 grep -Fq 'Apache Maven 3.10.0' "$TEST/maven-version.txt"
 printf 'class SelectedJdkProof { public static void main(String[] args) { if (Runtime.version().feature()!=25) throw new IllegalStateException(); System.out.println("JAVA_SOURCE_25_PASS"); } }\n' > "$TEST/SelectedJdkProof.java"
 bash "$TEST/project/tools/with-toolchain.sh" java --source 25 "$TEST/SelectedJdkProof.java" > "$TEST/source-proof.txt"
 grep -Fxq JAVA_SOURCE_25_PASS "$TEST/source-proof.txt"
 chmod 644 "$TEST/project/.local-setup/java-home"
 if bash "$TEST/project/tools/with-toolchain.sh" java --version > "$TEST/unsafe.log" 2>&1; then exit 1; fi
 chmod 600 "$TEST/project/.local-setup/java-home"
 mkdir -m 700 "$TEST/empty-java"
 printf '%s\n' "$TEST/empty-java" > "$TEST/project/.local-setup/java-home"
 printf '#!/usr/bin/env bash\nprintf "openjdk 25.0.5 fallback\\n"\n' > "$TEST/bin/java"
 if bash "$TEST/project/tools/with-toolchain.sh" java --version > "$TEST/missing-selected.log" 2>&1; then exit 1; fi
 grep -Fq 'toolchain is incomplete' "$TEST/missing-selected.log"
 printf 'PASS real signatures/JDK/Maven, persistence and unsafe selection refusal\n'
else printf 'SKIP real artifact install: populate target/prerequisite-downloads first\n'; fi
printf 'Prerequisite fixture checks passed. Host settings unchanged.\n'
