#!/bin/sh
# Local, pinned dependency; never installs into the system.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
version=1.0.22
sha=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
base="$root/build/sodium"
archive="$base/download/libsodium-$version.tar.gz"
mkdir -p "$base/download"
if [ ! -f "$archive" ]; then
  curl --fail --location "https://download.libsodium.org/libsodium/releases/libsodium-$version.tar.gz" -o "$archive"
fi
printf '%s  %s\n' "$sha" "$archive" | shasum -a 256 -c -
if [ ! -d "$base/libsodium-$version" ]; then tar -xzf "$archive" -C "$base"; fi
platform=${1:-macos}
case "$platform" in
  macos) sdk=macosx; flags='-arch arm64 -mmacosx-version-min=13.0'; host=arm-apple-darwin ;;
  iphoneos) sdk=iphoneos; flags='-arch arm64 -miphoneos-version-min=17.0'; host=arm-apple-darwin ;;
  iphonesimulator) sdk=iphonesimulator; flags='-target arm64-apple-ios17.0-simulator'; host=arm-apple-darwin ;;
  *) echo 'usage: build-sodium.sh [macos|iphoneos|iphonesimulator]' >&2; exit 2 ;;
esac
mkdir -p "$base/obj-$platform"
cd "$base/obj-$platform"
CC="$(xcrun --sdk "$sdk" -f clang)" CFLAGS="-O2 $flags -isysroot $(xcrun --sdk "$sdk" --show-sdk-path)" \
  "$base/libsodium-$version/configure" --host="$host" --prefix="$base/$platform" --disable-shared --enable-static
make -j 4
if [ "$platform" = macos ]; then make -j 4 check; fi
make install
