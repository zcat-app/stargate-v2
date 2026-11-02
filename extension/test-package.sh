#!/usr/bin/env bash
# Copyright 2026 The Stargate Authors; SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
classes=$(mktemp -d /tmp/stargate-package-classes-XXXXXXXX)
trap 'rm -rf -- "$classes"' EXIT
javac --release 25 -d "$classes" "$root/PackageExtension.java" "$root/TestPackageExtension.java"
java -cp "$classes" TestPackageExtension "$root"
