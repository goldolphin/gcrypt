#!/bin/bash

set -eu

echo "=== Building gcrypt universal binary for macOS ==="
echo ""

echo "[1/4] Checking for required targets..."
rustup target add x86_64-apple-darwin aarch64-apple-darwin 2>/dev/null || true

echo "[2/4] Building x86_64 version..."
cargo build --release --target x86_64-apple-darwin

echo "[3/4] Building aarch64 version..."
cargo build --release --target aarch64-apple-darwin

echo "[4/4] Creating universal binary..."
lipo -create -output target/release/gcrypt-universal \
    target/x86_64-apple-darwin/release/gcrypt \
    target/aarch64-apple-darwin/release/gcrypt

echo ""
echo "=== Build completed successfully! ==="
echo ""

file target/release/gcrypt-universal

echo ""
echo "Universal binary location: target/release/gcrypt-universal"