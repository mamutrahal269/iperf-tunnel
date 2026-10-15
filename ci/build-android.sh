#!/usr/bin/env bash
set -euo pipefail

TARGET=aarch64-linux-android
API=28
TERMUX_PREFIX=/data/data/com.termux/files/usr
TERMUX_REPO=https://packages.termux.dev/apt/termux-main

: "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME is not set}"
TOOLCHAIN="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64"
CC="$TOOLCHAIN/bin/$TARGET$API-clang"
CXX="$TOOLCHAIN/bin/$TARGET$API-clang++"

WORK="$PWD/.android-build"
SYSROOT="$WORK/termux-sysroot"
mkdir -p "$SYSROOT"

echo "==> fetching openssl from termux repo"
curl -fsSL "$TERMUX_REPO/dists/stable/main/binary-aarch64/Packages.gz" | gzip -dc >"$WORK/Packages"
DEB_PATH=$(awk '/^Package: openssl$/,/^$/' "$WORK/Packages" | sed -n 's/^Filename: //p')
test -n "$DEB_PATH"
curl -fsSL -o "$WORK/openssl.deb" "$TERMUX_REPO/$DEB_PATH"
dpkg-deb -x "$WORK/openssl.deb" "$SYSROOT"

OPENSSL_ROOT="$SYSROOT$TERMUX_PREFIX"
test -f "$OPENSSL_ROOT/include/openssl/ssl.h"

# --- iperf3 (libiperf) ---
echo "==> building libiperf for $TARGET"
./configure \
  --host="$TARGET" \
  --without-sctp \
  --disable-shared \
  CC="$CC" \
  CXX="$CXX" \
  --with-openssl="$OPENSSL_ROOT" \
  CPPFLAGS="-I$OPENSSL_ROOT/include" \
  LDFLAGS="-L$OPENSSL_ROOT/lib -Wl,-rpath,$TERMUX_PREFIX/lib"
make -j"$(nproc)"
test -f src/.libs/libiperf.a

# --- iperf-tunnel ---
echo "==> building iperf-tunnel for $TARGET"
make -C src/tunnel \
  CC="$CC" \
  SCTP_LIB= \
  CPPFLAGS="-I$PWD/src -I$OPENSSL_ROOT/include" \
  LDFLAGS="-L$OPENSSL_ROOT/lib -Wl,-rpath,$TERMUX_PREFIX/lib" \
  LDLIBS="-lssl -lcrypto -lm"

echo "==> verifying binary"
BIN=iperf-tunnel
file "$BIN" | grep -q "ELF 64-bit.*ARM aarch64"
readelf -l "$BIN" | grep -q "interpreter: /system/bin/linker64"
readelf -d "$BIN" | grep -q "libssl.so.3"
readelf -d "$BIN" | grep -q "libcrypto.so.3"
if readelf -d "$BIN" | grep -q "libsctp"; then
  echo "ERROR: binary must not depend on libsctp" >&2
  exit 1
fi
file "$BIN"
echo "==> android build OK"
