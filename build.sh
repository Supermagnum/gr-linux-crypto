#!/bin/bash
# Build script for gr-linux-crypto

set -e

echo "Building gr-linux-crypto module..."

# Check dependencies
echo "Checking dependencies..."

# Check for GNU Radio
if ! pkg-config --exists gnuradio-runtime; then
    echo "ERROR: GNU Radio not found. Please install GNU Radio development packages."
    exit 1
fi

# Check for OpenSSL (CMake uses find_package(OpenSSL); pkg-config is a coarse pre-check)
if ! pkg-config --exists openssl; then
    echo "WARNING: OpenSSL pkg-config not found. Brainpool blocks need OpenSSL (libssl-dev)."
fi

# Check for keyutils
if ! ldconfig -p | grep -q libkeyutils; then
    echo "WARNING: libkeyutils not found. Kernel keyring features may not work."
fi

# Prefer /usr/local libsodium when present (X-Wing KEM requires 1.0.22+)
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
if pkg-config --exists libsodium 2>/dev/null; then
    echo "libsodium: $(pkg-config --modversion libsodium) (via pkg-config)"
else
    echo "WARNING: libsodium not found. Sodium PDU blocks (KEM, SHA3) will be disabled."
    echo "         Install libsodium 1.0.22+ or set PKG_CONFIG_PATH to /usr/local/lib/pkgconfig."
fi

# Check for libnitrokey (optional)
if ! pkg-config --exists libnitrokey-1 2>/dev/null && ! pkg-config --exists libnitrokey 2>/dev/null; then
    echo "NOTE: libnitrokey not found. Nitrokey block builds with stub behaviour."
fi

echo "Dependencies check completed."

# Create build directory
mkdir -p build
cd build

# Configure with CMake
echo "Configuring with CMake..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr/local \
    -DCMAKE_CXX_STANDARD=17

# Build
echo "Building..."
make -j"$(nproc)"

echo "Build completed successfully!"
echo ""
echo "To install:"
echo "  sudo make install"
echo ""
echo "To uninstall:"
echo "  sudo make uninstall"
echo ""
echo "Python tests and scripts (recommended):"
echo "  cd .. && python3 -m venv .venv && source .venv/bin/activate"
echo "  pip3 install -r requirements.txt"
echo "  pytest tests/ -v"
echo ""
echo "Ephemeral key CLI:"
echo "  export GR_LINUX_CRYPTO_DIR=\$(pwd)/.."
echo "  python3 scripts/epk_generate.py --help"
