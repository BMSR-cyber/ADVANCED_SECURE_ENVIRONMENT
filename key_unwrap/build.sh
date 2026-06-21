#!/usr/bin/env bash
# Build the Rust key-unwrap cdylib used by src/rust_unwrap.py.
# Requires rustup/cargo. Output: target/release/libkey_unwrap.so
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
cargo build --release
echo "built: $(pwd)/target/release/libkey_unwrap.so"
echo "optionally: sudo cp target/release/libkey_unwrap.so /usr/local/lib/"
