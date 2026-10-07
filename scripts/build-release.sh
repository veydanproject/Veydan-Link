#!/usr/bin/env bash
# Builds the bridge: one static file that runs on any Linux server.
#
#   dist/vlink                the bridge
#   dist/SHA256SUMS           their checksums
#   dist/RELEASE              the release name, <version>-<build time>
#
# A static build needs a C compiler for musl. Order of choice: zig (fetched
# into the tools directory when missing), then musl-gcc from the system.
#
#   VLINK_TARGET=aarch64-unknown-linux-musl   another machine type
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/env.sh"
cd "$VLINK_DIR"

# The monorepo's build environment points C compilers at the desktop's
# glibc headers (CFLAGS) and the linker at its libraries (RUSTFLAGS). A
# static musl build must see none of that: C compiled against glibc 2.38+
# headers wants __isoc23_sscanf and open64, which musl has not.
unset CFLAGS CXXFLAGS CPPFLAGS RUSTFLAGS GCC_EXEC_PREFIX

TARGET="${VLINK_TARGET:-x86_64-unknown-linux-musl}"
ZIG_VERSION="${VLINK_ZIG_VERSION:-0.13.0}"
ZIG_DIR="$VLINK_TOOLS/zig"

say() { echo ">> $*"; }
die() { echo "vlink build: $*" >&2; exit 1; }

[ -s trust/root.crt ] && grep -q "BEGIN CERTIFICATE" trust/root.crt \
  || die "trust/root.crt is missing: the bridge is built around the root (vhub new-root)"

# --- toolchain ---------------------------------------------------------------
if command -v rustup >/dev/null 2>&1; then
  rustup target list --installed | grep -qx "$TARGET" || {
    say "adding rust target $TARGET"
    rustup target add "$TARGET" >/dev/null
  }
fi

fetch_zig() {
  [ "${VLINK_NO_FETCH:-0}" = 1 ] && return 1
  local arch; arch="$(uname -m)"
  local name="zig-linux-$arch-$ZIG_VERSION"
  say "fetching zig $ZIG_VERSION into $ZIG_DIR"
  mkdir -p "$ZIG_DIR"
  curl -fsSL "https://ziglang.org/download/$ZIG_VERSION/$name.tar.xz" \
    | tar -xJ -C "$ZIG_DIR" --strip-components=1
}

[ -x "$ZIG_DIR/zig" ] && export PATH="$ZIG_DIR:$PATH"

builder=""
if command -v zig >/dev/null 2>&1 || fetch_zig; then
  export PATH="$ZIG_DIR:$PATH"
  if ! command -v cargo-zigbuild >/dev/null 2>&1; then
    say "installing cargo-zigbuild"
    cargo install cargo-zigbuild --locked >/dev/null 2>&1 || die "cannot install cargo-zigbuild"
  fi
  builder="zigbuild"
elif command -v musl-gcc >/dev/null 2>&1; then
  builder="build"
else
  die "no C compiler for $TARGET: install zig (https://ziglang.org) or musl-tools"
fi

# --- build -------------------------------------------------------------------
version="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)"
release="$version-$(date -u +%Y%m%d%H%M%S)"
say "building vlink $release for $TARGET (cargo $builder)"
cargo "$builder" --release --locked --target "$TARGET" -p vlink

mkdir -p dist
for name in vlink; do
  bin="$(cargo_target_dir)/$TARGET/release/$name"
  [ -x "$bin" ] || die "no binary at $bin"
  # A binary that needs libraries from the build machine is not a release.
  if command -v ldd >/dev/null 2>&1 && ldd "$bin" 2>/dev/null | grep -q '=>'; then
    die "$bin is dynamically linked"
  fi
  # Renamed into place: a copy that is running cannot be written over.
  cp "$bin" "dist/$name.new"
  mv -f "dist/$name.new" "dist/$name"
done
(cd dist && sha256sum vlink > SHA256SUMS)
echo "$release" > dist/RELEASE

say "dist/vlink  $(du -h dist/vlink | cut -f1)   $release"
