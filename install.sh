#!/usr/bin/env bash
# Pasang NetFlow sebagai perintah `ntf`.
# Pemakaian:
#   ./install.sh                 # build dengan fitur live (butuh libpcap-dev)
#   FEATURES= ./install.sh       # build mode simulasi saja
#   PREFIX=/usr/local ./install.sh
set -euo pipefail

cd "$(dirname "$0")"

FEATURES="${FEATURES-live}"
PREFIX="${PREFIX:-$HOME/.local}"

if [ -n "$FEATURES" ]; then
    cargo build --release --features "$FEATURES"
else
    cargo build --release
fi

install -Dm755 target/release/ntf "$PREFIX/bin/ntf"
echo "ntf terpasang di $PREFIX/bin/ntf"
echo "Cek dengan: ntf --version"
