#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
export ZEN_COMPILER="$compiler"
"${PYTHON:-python3}" tests/check_tls13.py --zen "$compiler" --std "$ZEN_STD"
"${PYTHON:-python3}" scripts/check-tls13-interop.py
"${PYTHON:-python3}" scripts/check-tls13-session.py
"${PYTHON:-python3}" scripts/check-tls13-dhe.py
"${PYTHON:-python3}" scripts/check-tls13-server.py
