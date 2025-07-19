"""
Test suite for the cryptographic steganography application.

This package contains unit tests for all core modules including:
- AES encryption/decryption
- RSA key operations
- HMAC signing/verification
- Steganography operations
- Full encryption/decryption pipelines
"""

import sys
import os

# Add the project root to the Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
