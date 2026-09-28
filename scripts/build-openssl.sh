#!/bin/sh
# Private, pinned OpenSSL build. No system installation or trust-store changes.
set -eu
cd "$(dirname "$0")/.."
destination=${1:-"$PWD/build/tls"}
mkdir -p "$destination"
destination=$(cd "$destination" && pwd)
commit=c1eeb9406b6142148f267594197d853403d10208
if [ ! -d "$destination/openssl-src/.git" ]; then
    git clone --depth 1 --branch openssl-3.5.4 https://github.com/openssl/openssl.git "$destination/openssl-src"
fi
test "$(git -C "$destination/openssl-src" rev-parse HEAD)" = "$commit"
cd "$destination/openssl-src"
./Configure no-shared no-tests --prefix="$destination/openssl" > "$destination/openssl-config.log"
make -j"${JOBS:-8}" > "$destination/openssl-build.log" 2>&1
make install_sw > "$destination/openssl-install.log" 2>&1
mkdir -p "$destination/openssl/ssl"
cp apps/openssl.cnf "$destination/openssl/ssl/openssl.cnf"
"$destination/openssl/bin/openssl" version
