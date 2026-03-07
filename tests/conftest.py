"""
Pytest configuration and shared fixtures for gr-linux-crypto tests.
"""

import os
import sys

# Add parent directory to path for imports
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, parent_dir)
python_dir = os.path.join(parent_dir, "python")
sys.path.insert(0, python_dir)
# When package is not installed, make "gr_linux_crypto" resolve to python/ (same content)
# by ensuring the project root is first and gr_linux_crypto exists as alias for python
_link = os.path.join(parent_dir, "gr_linux_crypto")
if not os.path.exists(_link) and os.path.isdir(python_dir):
    try:
        os.symlink("python", _link)
    except OSError:
        pass  # e.g. no permission; fall back to installed or PYTHONPATH
