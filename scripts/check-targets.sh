#!/usr/bin/env bash
# Does everything build for the systems it is meant for?  make check-targets
#
#   the client library   Windows, macOS, Android (and Linux, by `make test`)
#   the bridge           Linux only: it runs on servers (make release-all)
#   the hub              Linux only: it runs on servers
#
# C code of the dependencies (ring) is compiled with zig for Windows and
# macOS, and with the NDK for Android. A target whose compiler is not on
# this machine is skipped, and said so.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$VLINK_DIR"

say() { echo ">> $*"; }
failed=0
skipped=0

[ -x "$VLINK_TOOLS/zig/zig" ] && export PATH="$VLINK_TOOLS/zig:$PATH"
have_target() { ! command -v rustup >/dev/null 2>&1 || rustup target list --installed | grep -qx "$1"; }

zig_build() {  # zig_build <target> <packages...>
  local target="$1"; shift
  if ! command -v zig >/dev/null 2>&1 || ! command -v cargo-zigbuild >/dev/null 2>&1 || ! have_target "$target"; then
    say "$target: skipped (needs zig, cargo-zigbuild and the rust target)"; skipped=1; return
  fi
  local args=(); for p in "$@"; do args+=(-p "$p"); done
  if cargo zigbuild -q --locked --target "$target" "${args[@]}"; then say "$target: $* build"; else say "$target: FAILED"; failed=1; fi
}

android_build() {  # android_build <target> <clang prefix> <packages...>
  local target="$1" prefix="$2"; shift 2
  local ndk; ndk="$(ls -d "${ANDROID_NDK_HOME:-$VLINK_TOOLS/android-sdk/ndk}"/*/toolchains/llvm/prebuilt/linux-x86_64/bin 2>/dev/null | tail -1)"
  local cc="$ndk/${prefix}26-clang"
  if [ ! -x "$cc" ] || ! have_target "$target"; then
    say "$target: skipped (needs the Android NDK and the rust target)"; skipped=1; return
  fi
  local var="${target//-/_}" args=(); for p in "$@"; do args+=(-p "$p"); done
  if env "CC_$var=$cc" "AR_$var=$ndk/llvm-ar" "CARGO_TARGET_$(echo "$var" | tr a-z A-Z)_LINKER=$cc" \
      cargo build -q --locked --target "$target" "${args[@]}"; then
    say "$target: $* build"
  else
    say "$target: FAILED"; failed=1
  fi
}

zig_build x86_64-pc-windows-gnu vlink-client
zig_build aarch64-apple-darwin vlink-client
android_build aarch64-linux-android aarch64-linux-android vlink-client
android_build armv7-linux-androideabi armv7a-linux-androideabi vlink-client

[ "$failed" = 0 ] || { echo "vlink: some targets do not build" >&2; exit 1; }
[ "$skipped" = 0 ] || say "some targets were skipped"
