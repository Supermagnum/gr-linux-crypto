#!/bin/bash

# LibFuzzer build script for gr-linux-crypto
# This script compiles LibFuzzer-compatible fuzzing harnesses

set -e

echo "=== LibFuzzer Build Script ==="
echo "Building LibFuzzer-compatible fuzzing harnesses..."

# Create build directory
BUILD_DIR="libfuzzer_build"
mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Get include and library paths
GNURADIO_CFLAGS=$(pkg-config --cflags gnuradio-runtime 2>/dev/null || echo "")
KEYUTILS_CFLAGS=$(pkg-config --cflags libkeyutils 2>/dev/null || echo "")
GNURADIO_LIBS=$(pkg-config --libs gnuradio-runtime 2>/dev/null || echo "-lgnuradio-runtime -lgnuradio-pmt")
KEYUTILS_LIBS=$(pkg-config --libs libkeyutils 2>/dev/null || echo "-lkeyutils")

# Base project include paths (go up from libfuzzer_build to project root)
# libfuzzer_build -> security/fuzzing -> security -> project root
# Actually: security/fuzzing -> project root (only 2 levels up)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
INCLUDE_PATHS="-I$PROJECT_ROOT/include -I$PROJECT_ROOT/lib $GNURADIO_CFLAGS $KEYUTILS_CFLAGS"

# Library paths
LIBRARY_PATH="-L$PROJECT_ROOT/build"
# Ensure library can be found at runtime
export LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH"
LIBRARY_LIBS="$LIBRARY_PATH -lgnuradio-linux-crypto $GNURADIO_LIBS $KEYUTILS_LIBS"

# Set compiler flags for LibFuzzer
export CXXFLAGS="-fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer -std=c++17 $INCLUDE_PATHS"
export LDFLAGS="-fsanitize=fuzzer,address,undefined $LIBRARY_LIBS"

echo "Compiler flags: $CXXFLAGS"
echo "Linker flags: $LDFLAGS"
echo "Project root: $PROJECT_ROOT"

# Build kernel keyring fuzzer
echo "Building kernel_keyring_libfuzzer..."
clang++ $CXXFLAGS -o kernel_keyring_libfuzzer ../kernel_keyring_libfuzzer.cpp $LDFLAGS

# Build kernel crypto AES fuzzer
echo "Building kernel_crypto_aes_libfuzzer..."
clang++ $CXXFLAGS -o kernel_crypto_aes_libfuzzer ../kernel_crypto_aes_libfuzzer.cpp $LDFLAGS

# Build nitrokey fuzzer
echo "Building nitrokey_libfuzzer..."
clang++ $CXXFLAGS -o nitrokey_libfuzzer ../nitrokey_libfuzzer.cpp $LDFLAGS

# Build OpenSSL fuzzer
echo "Building openssl_libfuzzer..."
clang++ $CXXFLAGS -o openssl_libfuzzer ../openssl_libfuzzer.cpp $LDFLAGS -lssl -lcrypto

echo ""
echo "=== Build Complete ==="
echo "LibFuzzer binaries created:"
ls -la *.libfuzzer 2>/dev/null || echo "No .libfuzzer files found"
ls -la kernel_* nitrokey_* openssl_* 2>/dev/null || echo "No fuzzer binaries found"

echo ""
echo "=== Fuzzer Information ==="
for fuzzer in kernel_* nitrokey_* openssl_*; do
    if [ -f "$fuzzer" ]; then
        echo "--- $fuzzer ---"
        echo "Size: $(stat -c%s "$fuzzer") bytes"
        echo "Type: $(file "$fuzzer")"
        echo ""
    fi
done

echo "=== LibFuzzer Build Complete ==="
echo "Ready to run LibFuzzer tests!"




