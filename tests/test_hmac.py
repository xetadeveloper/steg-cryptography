import sys
import os

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core import hmac_module  # Make sure core/ is a module (has __init__.py)

# Add your test function below here and use "python tests/test_hmac.py" to run the test


def test_hmac_valid():
    key = b'supersecretkey1234567890123456'  # 32-byte key
    message = b'This is a secret message'
    tag = hmac_module.generate_hmac(key, message)
    assert hmac_module.verify_hmac(key, message, tag)

def test_hmac_invalid():
    key = b'supersecretkey1234567890123456'
    message = b'Valid message'
    tampered = b'INVALID message'
    tag = hmac_module.generate_hmac(key, message)
    assert not hmac_module.verify_hmac(key, tampered, tag)
