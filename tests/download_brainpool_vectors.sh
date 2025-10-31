#!/bin/bash
# Download Brainpool test vectors from various sources

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="${SCRIPT_DIR}/test_vectors"

mkdir -p "${VECTORS_DIR}"
cd "${VECTORS_DIR}"

echo "Downloading Brainpool test vectors..."

# Wycheproof (recommended)
echo ""
echo "=== Downloading Wycheproof vectors ==="
if [ -d "wycheproof" ]; then
    echo "Wycheproof directory exists, skipping clone..."
else
    git clone --depth 1 https://github.com/google/wycheproof.git || true
fi

if [ -d "wycheproof/testvectors" ]; then
    echo "Copying Wycheproof Brainpool vectors..."
    cp wycheproof/testvectors/ecdh_brainpoolP256r1_test.json . 2>/dev/null || true
    cp wycheproof/testvectors/ecdh_brainpoolP384r1_test.json . 2>/dev/null || true
    cp wycheproof/testvectors/ecdh_brainpoolP512r1_test.json . 2>/dev/null || true
    cp wycheproof/testvectors/ecdsa_brainpoolP256r1_sha256_test.json . 2>/dev/null || true
    cp wycheproof/testvectors/ecdsa_brainpoolP384r1_sha384_test.json . 2>/dev/null || true
    cp wycheproof/testvectors/ecdsa_brainpoolP512r1_sha512_test.json . 2>/dev/null || true
fi

# Linux kernel testmgr.h
echo ""
echo "=== Downloading Linux kernel testmgr.h ==="
wget -q -O testmgr.h https://raw.githubusercontent.com/torvalds/linux/master/crypto/testmgr.h || \
    curl -s -o testmgr.h https://raw.githubusercontent.com/torvalds/linux/master/crypto/testmgr.h || \
    echo "Warning: Failed to download testmgr.h"

# Extract Brainpool references
if [ -f "testmgr.h" ]; then
    echo "Extracting Brainpool references from testmgr.h..."
    grep -i brainpool testmgr.h > testmgr_brainpool.txt 2>/dev/null || true
fi

# OpenSSL test vectors
echo ""
echo "=== Downloading OpenSSL test vectors ==="
if [ -d "openssl" ]; then
    echo "OpenSSL directory exists, skipping clone..."
else
    git clone --depth 1 --branch master https://github.com/openssl/openssl.git || true
fi

if [ -d "openssl/test" ]; then
    echo "Searching for Brainpool references in OpenSSL tests..."
    grep -r -i brainpool openssl/test/ > openssl_brainpool.txt 2>/dev/null || true
fi

# mbedTLS test vectors
echo ""
echo "=== Downloading mbedTLS test vectors ==="
if [ -d "mbedtls" ]; then
    echo "mbedTLS directory exists, skipping clone..."
else
    git clone --depth 1 https://github.com/Mbed-TLS/mbedtls.git || true
fi

if [ -d "mbedtls/tests/suites" ]; then
    echo "Searching for Brainpool test data in mbedTLS..."
    find mbedtls/tests/suites -name "*.data" -exec grep -l -i brainpool {} \; > mbedtls_brainpool_files.txt 2>/dev/null || true
    
    # Copy relevant files
    if [ -f "mbedtls_brainpool_files.txt" ]; then
        while IFS= read -r file; do
            if [ -f "$file" ]; then
                filename=$(basename "$file")
                cp "$file" "mbedtls_${filename}" 2>/dev/null || true
            fi
        done < mbedtls_brainpool_files.txt
    fi
fi

echo ""
echo "=== Download complete ==="
echo "Test vectors available in: ${VECTORS_DIR}"
ls -lh "${VECTORS_DIR}"/*brainpool* "${VECTORS_DIR}"/*.json 2>/dev/null | head -20 || true

