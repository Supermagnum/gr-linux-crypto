#!/bin/bash

# LibFuzzer run script for gr-linux-crypto
# This script runs LibFuzzer tests for 6 hours

set -e

# Get script directory and set up library path
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
export LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH"

echo "=== LibFuzzer Run Script ==="
echo "Starting LibFuzzer tests for 6 hours..."
echo "Library path: $LD_LIBRARY_PATH"

# Create reports directory
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
REPORTS_DIR="$SCRIPT_DIR/reports/libfuzzer_$TIMESTAMP"
mkdir -p "$REPORTS_DIR"
cd "$REPORTS_DIR"

echo "Reports directory: $REPORTS_DIR"
echo "Script directory: $SCRIPT_DIR"

# Create corpus directories
mkdir -p corpus_kernel_keyring
mkdir -p corpus_kernel_crypto_aes
mkdir -p corpus_nitrokey
mkdir -p corpus_openssl

# Generate minimal, format-aware seed corpus
echo "Generating minimal structured seed corpus..."
echo "Using format-specific seeds to encourage exploration through mutations"

# kernel_keyring: expects key_serial_t (4 bytes) + optional bool (1 byte)
echo "Creating corpus for corpus_kernel_keyring..."
printf "\x00\x00\x00\x00\x00" > corpus_kernel_keyring/seed_minimal_00      # key_id=0, auto_repeat=false
printf "\x00\x00\x00\x00\x01" > corpus_kernel_keyring/seed_minimal_01      # key_id=0, auto_repeat=true
printf "\xFF\xFF\xFF\xFF\x00" > corpus_kernel_keyring/seed_boundary_ff    # max key_id, auto_repeat=false
printf "\x01\x00\x00\x00\x01" > corpus_kernel_keyring/seed_small_01       # small key_id, auto_repeat=true
printf "\x00\x00\x00\x01\x00" > corpus_kernel_keyring/seed_valid_01       # valid key_id, auto_repeat=false
echo "Created $(ls -1 corpus_kernel_keyring 2>/dev/null | wc -l) test cases in corpus_kernel_keyring"

# kernel_crypto_aes: expects Key (16/24/32 bytes) + IV (16 bytes) + mode byte + data
echo "Creating corpus for corpus_kernel_crypto_aes..."
# AES-128 minimal: 16-byte key + 16-byte IV
printf "\x00%.0s" {1..16} | cat - <(printf "\x00%.0s" {1..16}) > corpus_kernel_crypto_aes/seed_aes128_minimal
# AES-192 minimal: 24-byte key + 16-byte IV  
printf "\x00%.0s" {1..24} | cat - <(printf "\x00%.0s" {1..16}) > corpus_kernel_crypto_aes/seed_aes192_minimal
# AES-256 minimal: 32-byte key + 16-byte IV
printf "\x00%.0s" {1..32} | cat - <(printf "\x00%.0s" {1..16}) > corpus_kernel_crypto_aes/seed_aes256_minimal
# AES-128 with pattern key
printf "\x55%.0s" {1..16} | cat - <(printf "\xAA%.0s" {1..16}) > corpus_kernel_crypto_aes/seed_aes128_pattern
# AES-256 with sequential key
printf "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F" | cat - <(printf "\xFF%.0s" {1..16}) > corpus_kernel_crypto_aes/seed_aes256_sequential
echo "Created $(ls -1 corpus_kernel_crypto_aes 2>/dev/null | wc -l) test cases in corpus_kernel_crypto_aes"

# nitrokey: expects Slot number (1 byte) + optional bool (1 byte)
echo "Creating corpus for corpus_nitrokey..."
printf "\x00\x00" > corpus_nitrokey/seed_slot0_false    # slot 0, auto_repeat=false
printf "\x00\x01" > corpus_nitrokey/seed_slot0_true     # slot 0, auto_repeat=true
printf "\x0F\x00" > corpus_nitrokey/seed_slot15_false  # slot 15, auto_repeat=false
printf "\x07\x01" > corpus_nitrokey/seed_slot7_true    # slot 7, auto_repeat=true
printf "\x01\x00" > corpus_nitrokey/seed_slot1_false   # slot 1, auto_repeat=false
echo "Created $(ls -1 corpus_nitrokey 2>/dev/null | wc -l) test cases in corpus_nitrokey"

# openssl: minimal valid operation seeds
echo "Creating corpus for corpus_openssl..."
# Minimal AES key (16 bytes)
printf "\x00%.0s" {1..16} > corpus_openssl/seed_aes128_key
# Minimal hash input (1 byte)
printf "\x00" > corpus_openssl/seed_hash_minimal
# Minimal HMAC (key + data)
printf "\x00%.0s" {1..16} | cat - <(printf "\x00") > corpus_openssl/seed_hmac_minimal
# Pattern key
printf "\x55%.0s" {1..16} > corpus_openssl/seed_key_pattern
# Sequential key
printf "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F" > corpus_openssl/seed_key_sequential
echo "Created $(ls -1 corpus_openssl 2>/dev/null | wc -l) test cases in corpus_openssl"

echo ""
echo "=== Starting LibFuzzer Tests ==="

# Run kernel keyring fuzzer
echo "Starting kernel_keyring_libfuzzer..."
timeout 6h env LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH" "$SCRIPT_DIR/libfuzzer_build/kernel_keyring_libfuzzer" corpus_kernel_keyring > kernel_keyring.log 2>&1 &
KERNEL_KEYRING_PID=$!

# Run kernel crypto AES fuzzer
echo "Starting kernel_crypto_aes_libfuzzer..."
timeout 6h env LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH" "$SCRIPT_DIR/libfuzzer_build/kernel_crypto_aes_libfuzzer" corpus_kernel_crypto_aes > kernel_crypto_aes.log 2>&1 &
KERNEL_CRYPTO_AES_PID=$!

# Run nitrokey fuzzer
echo "Starting nitrokey_libfuzzer..."
timeout 6h env LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH" "$SCRIPT_DIR/libfuzzer_build/nitrokey_libfuzzer" corpus_nitrokey > nitrokey.log 2>&1 &
NITROKEY_PID=$!

# Run OpenSSL fuzzer
echo "Starting openssl_libfuzzer..."
timeout 6h env LD_LIBRARY_PATH="$PROJECT_ROOT/build:$LD_LIBRARY_PATH" "$SCRIPT_DIR/libfuzzer_build/openssl_libfuzzer" corpus_openssl > openssl.log 2>&1 &
OPENSSL_PID=$!

echo ""
echo "=== LibFuzzer Tests Started ==="
echo "Process IDs:"
echo "  kernel_keyring: $KERNEL_KEYRING_PID"
echo "  kernel_crypto_aes: $KERNEL_CRYPTO_AES_PID"
echo "  nitrokey: $NITROKEY_PID"
echo "  openssl: $OPENSSL_PID"

echo ""
echo "=== Monitoring Progress ==="
echo "Checking progress every 30 seconds..."

# Monitor progress
for i in {1..720}; do  # 6 hours = 720 * 30 seconds
    echo "--- Progress Check $i ---"
    echo "Time: $(date)"
    
    # Check if processes are still running
    if ps -p $KERNEL_KEYRING_PID > /dev/null 2>&1; then
        echo "kernel_keyring: Running"
    else
        echo "kernel_keyring: Stopped"
    fi
    
    if ps -p $KERNEL_CRYPTO_AES_PID > /dev/null 2>&1; then
        echo "kernel_crypto_aes: Running"
    else
        echo "kernel_crypto_aes: Stopped"
    fi
    
    if ps -p $NITROKEY_PID > /dev/null 2>&1; then
        echo "nitrokey: Running"
    else
        echo "nitrokey: Stopped"
    fi
    
    if ps -p $OPENSSL_PID > /dev/null 2>&1; then
        echo "openssl: Running"
    else
        echo "openssl: Stopped"
    fi
    
    # Check log sizes
    echo "Log sizes:"
    for log in *.log; do
        if [ -f "$log" ]; then
            echo "  $log: $(stat -c%s "$log") bytes"
        fi
    done
    
    echo ""
    sleep 30
done

echo ""
echo "=== LibFuzzer Tests Complete ==="
echo "Final status:"
echo "Time: $(date)"

# Final process check
echo "Final process status:"
if ps -p $KERNEL_KEYRING_PID > /dev/null 2>&1; then
    echo "kernel_keyring: Still running"
else
    echo "kernel_keyring: Completed"
fi

if ps -p $KERNEL_CRYPTO_AES_PID > /dev/null 2>&1; then
    echo "kernel_crypto_aes: Still running"
else
    echo "kernel_crypto_aes: Completed"
fi

if ps -p $NITROKEY_PID > /dev/null 2>&1; then
    echo "nitrokey: Still running"
else
    echo "nitrokey: Completed"
fi

if ps -p $OPENSSL_PID > /dev/null 2>&1; then
    echo "openssl: Still running"
else
    echo "openssl: Completed"
fi

echo ""
echo "=== LibFuzzer Run Complete ==="
echo "Reports saved in: $REPORTS_DIR"




