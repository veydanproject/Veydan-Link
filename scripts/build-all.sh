#!/usr/bin/env bash
# The bridge for every system somebody may run it on:  make release-all
#
#   dist/all/vlink-linux-x86_64     static
#   dist/all/vlink-linux-aarch64    static
#   dist/all/vlink-windows-x86_64.exe
#   dist/all/vlink-macos-aarch64
#   dist/all/SHA256SUMS
#
# Everything is compiled here, with zig as the C compiler of each target.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$VLINK_DIR"
[ -x "$VLINK_TOOLS/zig/zig" ] && export PATH="$VLINK_TOOLS/zig:$PATH"
command -v zig >/dev/null && command -v cargo-zigbuild >/dev/null \
  || { echo "vlink build: zig and cargo-zigbuild are needed (make release fetches them)" >&2; exit 1; }

mkdir -p dist/all
build() {  # build <target> <file in target dir> <name in dist/all>
  echo ">> $3"
  cargo zigbuild -q --release --locked --target "$1" -p vlink 2>/dev/null \
    || cargo zigbuild --release --locked --target "$1" -p vlink
  cp "$(cargo_target_dir)/$1/release/$2" "dist/all/$3"
}
build x86_64-unknown-linux-musl  vlink     vlink-linux-x86_64
build aarch64-unknown-linux-musl vlink     vlink-linux-aarch64
build x86_64-pc-windows-gnu      vlink.exe vlink-windows-x86_64.exe
build aarch64-apple-darwin       vlink     vlink-macos-aarch64
(cd dist/all && sha256sum vlink-* > SHA256SUMS && ls -la)
