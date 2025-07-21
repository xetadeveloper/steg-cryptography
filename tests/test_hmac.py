import sys
import os

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core import hmac_module  # Make sure core/ is a module (has __init__.py)

# Add your test function below here and use "python tests/test_hmac.py" to run the test


def test_hmac_valid():
    key = b'supersecretkey1234567890123456'  # 32-byte key
    message = b'This is a secret message'
    tag = hmac_module.generate_hmac(message, key)
    assert hmac_module.verify_hmac(message, tag, key)

def test_hmac_invalid():
    key = b'supersecretkey1234567890123456'
    message = b'Valid message'
    tampered = b'INVALID message'
    tag = hmac_module.generate_hmac(message, key)
    assert not hmac_module.verify_hmac(tampered, tag, key)

def test_hmac_hex_functions():
    """Test the hex string convenience functions"""
    key = "test_key_123"
    message = "Hello, HMAC world!"
    
    # Test hex generation
    hex_signature = hmac_module.generate_hmac_hex(message, key)
    
    # Test hex verification
    assert hmac_module.verify_hmac_hex(message, hex_signature, key)
    
    # Test with invalid hex
    assert not hmac_module.verify_hmac_hex("tampered message", hex_signature, key)

def test_authenticated_message():
    """Test the authenticated message creation and verification"""
    message = "Secret authenticated message"
    key = "auth_key_456"
    
    # Create authenticated message
    auth_data = hmac_module.create_authenticated_message(message, key)
    
    # Extract and verify
    result = hmac_module.extract_and_verify_message(auth_data['authenticated_message'], key)
    
    assert result['verified'] == True
    assert result['message'].decode('utf-8') == message

if __name__ == "__main__":
    print("🔍 Running HMAC tests...\n")
    test_hmac_valid()
    test_hmac_invalid() 
    test_hmac_hex_functions()
    test_authenticated_message()
    print("\n✅ All HMAC tests passed!")
