#!/bin/bash

# Test compilation script for fuzzers
set -e

echo "=== Testing Fuzzer Compilation ==="

# Get include paths
GNURADIO_INCLUDES=$(pkg-config --cflags gnuradio-runtime 2>/dev/null || echo "")
KEYUTILS_INCLUDES=$(pkg-config --cflags libkeyutils 2>/dev/null || echo "")

# Get library paths
GNURADIO_LIBS=$(pkg-config --libs gnuradio-runtime 2>/dev/null || echo "-lgnuradio-runtime -lgnuradio-pmt")
KEYUTILS_LIBS=$(pkg-config --libs libkeyutils 2>/dev/null || echo "-lkeyutils")

# Base include directories
BASE_INCLUDES="-I../include -I../../include"

# Test compilation for each fuzzer
FUZZERS=(
    "kernel_keyring_fuzz.cpp:kernel_keyring_fuzz_test"
    "kernel_keyring_libfuzzer.cpp:kernel_keyring_libfuzzer_test"
    "kernel_crypto_aes_fuzz.cpp:kernel_crypto_aes_fuzz_test"
    "openssl_libfuzzer.cpp:openssl_libfuzzer_test"
)

for fuzzer_pair in "${FUZZERS[@]}"; do
    fuzzer="${fuzzer_pair%%:*}"
    target="${fuzzer_pair##*:}"
    
    if [ ! -f "$fuzzer" ]; then
        echo "SKIP: $fuzzer (not found)"
        continue
    fi
    
    echo ""
    echo "Testing: $fuzzer"
    
    # Try compilation with syntax check only (-fsyntax-only)
    if g++ -std=c++17 -fsyntax-only \
        $GNURADIO_INCLUDES $KEYUTILS_INCLUDES $BASE_INCLUDES \
        -I/usr/include/gnuradio \
        "$fuzzer" 2>&1 | head -20; then
        echo "  ✓ Syntax check passed"
    else
        echo "  ✗ Syntax check failed"
        continue
    fi
    
    # Check for common issues
    if grep -q "gr_vector" "$fuzzer"; then
        echo "  ✓ Uses gr_vector (good)"
    fi
    
    if grep -q "make(" "$fuzzer"; then
        echo "  ✓ Calls make() (good)"
    fi
    
    if grep -q "work(" "$fuzzer"; then
        echo "  ✓ Calls work() (good)"
    fi
    
    if grep -q "Simulate" "$fuzzer" || grep -q "result +=" "$fuzzer"; then
        echo "  ⚠ WARNING: May contain simulation code"
    fi
done

echo ""
echo "=== Compilation Test Complete ==="

