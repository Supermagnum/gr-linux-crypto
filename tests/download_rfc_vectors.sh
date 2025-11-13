#!/bin/bash
# Download script for RFC test vectors (RFC 7027, RFC 6954, RFC 8734)
#
# Note: RFCs typically don't provide downloadable test vector files.
# Test vectors are embedded in the RFC text itself (usually in appendices).
# This script provides a framework for extracting vectors from RFC text.
#
# Usage:
#   cd tests
#   ./download_rfc_vectors.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VECTORS_DIR="${SCRIPT_DIR}/test_vectors"

echo "RFC Test Vector Download Script"
echo "================================"
echo ""

# Create test_vectors directory if it doesn't exist
mkdir -p "${VECTORS_DIR}"

echo "Note: RFC test vectors are typically embedded in the RFC text itself."
echo "You may need to extract them manually from the RFC appendices."
echo ""

# RFC 7027: Additional Elliptic Curves for OpenPGP
echo "RFC 7027: Additional Elliptic Curves for OpenPGP"
echo "URL: https://datatracker.ietf.org/doc/html/rfc7027"
echo "Test vectors: Appendix A"
echo ""

# RFC 6954: Using ECC Brainpool curves in IKEv2
echo "RFC 6954: Using the Elliptic Curve Diffie-Hellman Key Agreement Algorithm"
echo "          with Brainpool curves in IKEv2"
echo "URL: https://datatracker.ietf.org/doc/html/rfc6954"
echo "Test vectors: Appendix A"
echo ""

# RFC 8734: Using Brainpool Curves in TLS 1.3
echo "RFC 8734: Using Brainpool Curves in TLS 1.3"
echo "URL: https://datatracker.ietf.org/doc/html/rfc8734"
echo "Test vectors: Appendix A"
echo ""

echo "To extract test vectors:"
echo "1. Download RFC text from IETF datatracker"
echo "2. Extract test vectors from appendices"
echo "3. Convert to JSON format (see test_rfc_vectors.py for format)"
echo "4. Place in ${VECTORS_DIR}/"
echo ""

# Create placeholder JSON files with structure
cat > "${VECTORS_DIR}/rfc7027_test_vectors.json" << 'EOF'
[
  {
    "comment": "RFC 7027 test vectors - extract from RFC 7027 Appendix A",
    "note": "Place test vectors here in JSON format. See test_rfc_vectors.py for structure."
  }
]
EOF

cat > "${VECTORS_DIR}/rfc6954_test_vectors.json" << 'EOF'
[
  {
    "comment": "RFC 6954 test vectors - extract from RFC 6954 Appendix A",
    "note": "Place test vectors here in JSON format. See test_rfc_vectors.py for structure."
  }
]
EOF

cat > "${VECTORS_DIR}/rfc8734_test_vectors.json" << 'EOF'
[
  {
    "comment": "RFC 8734 test vectors - extract from RFC 8734 Appendix A",
    "note": "Place test vectors here in JSON format. See test_rfc_vectors.py for structure."
  }
]
EOF

echo "Created placeholder JSON files:"
echo "  - ${VECTORS_DIR}/rfc7027_test_vectors.json"
echo "  - ${VECTORS_DIR}/rfc6954_test_vectors.json"
echo "  - ${VECTORS_DIR}/rfc8734_test_vectors.json"
echo ""
echo "Download complete (placeholders created)."
echo "Extract actual test vectors from RFC appendices and update these files."

