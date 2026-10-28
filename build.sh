#!/bin/bash
# Build the CVE-2026-98260 payload for arm64 Android.
#
# The payload re-executes itself through /proc/self/exe, so it must be static
# and non-PIE. Set ANDROID_NDK_HOME (or edit the default below).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ndk="${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME to an NDK r26+ install}"
api="${ANDROID_API:-35}"
toolchain="$ndk/toolchains/llvm/prebuilt/$(uname | grep -qi linux && echo linux-x86_64 || echo darwin-x86_64)"
cc="$toolchain/bin/aarch64-linux-android$api-clang"
strip="$toolchain/bin/llvm-strip"

out="${1:-$here/cve-2026-98260}"

"$cc" -std=gnu11 -O2 -g -static -pthread -D_GNU_SOURCE \
  -Wall -Wextra -Wno-unused-parameter -Wno-sign-compare -Wno-unused-function \
  "$here/kernel/cve-2026-98260.c" -o "$out"
"$strip" --strip-all "$out"

echo "built: $out"