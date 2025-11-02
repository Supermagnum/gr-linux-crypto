#!/bin/bash
# Setup test vectors for gr-linux-crypto tests

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="${SCRIPT_DIR}/test_vectors"
WYCHEPROOF_REPO="https://github.com/google/wycheproof.git"
WYCHEPROOF_DIR="/tmp/wycheproof"

echo "Setting up test vectors for gr-linux-crypto..."
echo "=============================================="

# Create vectors directory if it doesn't exist
mkdir -p "${VECTORS_DIR}"

# Download Wycheproof vectors
echo ""
echo "1. Downloading Wycheproof test vectors..."
if [ -d "${WYCHEPROOF_DIR}" ]; then
    echo "   Wycheproof repo already exists, updating..."
    cd "${WYCHEPROOF_DIR}"
    git pull || echo "   (Git pull failed, using existing)"
else
    echo "   Cloning Wycheproof repository..."
    git clone "${WYCHEPROOF_REPO}" "${WYCHEPROOF_DIR}" || {
        echo "   ERROR: Failed to clone Wycheproof repository"
        echo "   You may need to install git or check network connectivity"
        exit 1
    }
fi

# Copy Brainpool vectors
echo ""
echo "2. Copying Brainpool test vectors..."
BRAINPOOL_VECTORS=$(find "${WYCHEPROOF_DIR}/testvectors" -name "*brainpool*.json" 2>/dev/null || true)

if [ -z "$BRAINPOOL_VECTORS" ]; then
    echo "   WARNING: No Brainpool vectors found in Wycheproof repo"
    echo "   The repository structure may have changed"
else
    COUNT=0
    for vector_file in $BRAINPOOL_VECTORS; do
        filename=$(basename "$vector_file")
        cp "$vector_file" "${VECTORS_DIR}/${filename}"
        COUNT=$((COUNT + 1))
        echo "   Copied: ${filename}"
    done
    echo "   Copied ${COUNT} Brainpool test vector files"
fi

# Copy other relevant vectors (AES, ChaCha20 if available)
echo ""
echo "3. Copying other crypto test vectors..."
if [ -d "${WYCHEPROOF_DIR}/testvectors" ]; then
    # Copy AES-GCM vectors if they exist
    AES_VECTORS=$(find "${WYCHEPROOF_DIR}/testvectors" -name "*aes*.json" 2>/dev/null | head -5 || true)
    if [ -n "$AES_VECTORS" ]; then
        for vector_file in $AES_VECTORS; do
            filename=$(basename "$vector_file")
            cp "$vector_file" "${VECTORS_DIR}/${filename}" 2>/dev/null || true
        done
        echo "   Copied AES test vectors"
    fi
    
    # Copy ChaCha20-Poly1305 vectors if they exist
    CHACHA_VECTORS=$(find "${WYCHEPROOF_DIR}/testvectors" -name "*chacha*.json" 2>/dev/null | head -5 || true)
    if [ -n "$CHACHA_VECTORS" ]; then
        for vector_file in $CHACHA_VECTORS; do
            filename=$(basename "$vector_file")
            cp "$vector_file" "${VECTORS_DIR}/${filename}" 2>/dev/null || true
        done
        echo "   Copied ChaCha20-Poly1305 test vectors"
    fi
fi

# Create README
cat > "${VECTORS_DIR}/README.md" << 'EOF'
# Test Vectors

This directory contains cryptographic test vectors for gr-linux-crypto validation.

## Sources

### Wycheproof Project
- **Repository:** https://github.com/google/wycheproof
- **Description:** Comprehensive test vectors from Google's Wycheproof project
- **Format:** JSON
- **Coverage:** Brainpool curves, AES-GCM, ChaCha20-Poly1305, and more

### NIST CAVP
- **Source:** NIST Cryptographic Algorithm Validation Program
- **Format:** Text files
- **Coverage:** AES-GCM, ECDSA, ECDH

### RFC 8439
- **Source:** RFC 8439 (ChaCha20 and Poly1305)
- **Format:** Text files
- **Coverage:** ChaCha20-Poly1305 test vectors

## Setup

Run the setup script to download vectors:

```bash
./setup_test_vectors.sh
```

Or manually:

```bash
git clone https://github.com/google/wycheproof.git /tmp/wycheproof
cp /tmp/wycheproof/testvectors/*brainpool*.json tests/test_vectors/
```

## Usage

Test vectors are automatically used by:

- `test_brainpool_vectors.py` - Brainpool ECC test vectors
- `test_nist_vectors.py` - NIST CAVP vectors
- `test_brainpool_all_sources.py` - Multi-source Brainpool validation

## File Naming

- `*brainpool*.json` - Brainpool ECC test vectors (Wycheproof)
- `*aes*.json` - AES test vectors (Wycheproof)
- `*chacha*.json` - ChaCha20-Poly1305 vectors (Wycheproof)

EOF

# Download NIST CAVP vectors
echo ""
echo "4. Downloading NIST CAVP test vectors..."
if command -v python3 &> /dev/null; then
    python3 "${SCRIPT_DIR}/download_nist_vectors.py" "${VECTORS_DIR}" || {
        echo "   WARNING: NIST vector download failed (using minimal vectors if available)"
    }
else
    echo "   WARNING: python3 not found, skipping NIST vector download"
    echo "   Run manually: python3 tests/download_nist_vectors.py tests/test_vectors"
fi

echo ""
echo "Setup complete!"
echo "==============="
echo ""
echo "Test vectors are now in: ${VECTORS_DIR}"
echo ""
echo "You can now run tests that require vectors:"
echo "  pytest tests/test_brainpool_vectors.py -v"
echo "  pytest tests/test_nist_vectors.py -v"
echo ""
echo "Note: NIST vectors are downloaded automatically. For full comprehensive"
echo "      vectors, you may download from NIST CAVP website if needed."

