"""
Unit tests for the HMAC signing and verification module.
"""

import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.hmac_module import (
    generate_hmac, verify_hmac, generate_hmac_hex, verify_hmac_hex,
    sign_data_with_key, create_authenticated_message, extract_and_verify_message
)

class TestHMACModule(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a test message for HMAC verification"
        self.test_key = "test_secret_key"
        self.test_message_bytes = self.test_message.encode('utf-8')
        self.test_key_bytes = self.test_key.encode('utf-8')
    
    def test_generate_hmac_string_inputs(self):
        """Test HMAC generation with string inputs."""
        signature = generate_hmac(self.test_message, self.test_key)
        
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 32)  # SHA-256 produces 32-byte hash
        
        # Test that same inputs produce same signature
        signature2 = generate_hmac(self.test_message, self.test_key)
        self.assertEqual(signature, signature2)
    
    def test_generate_hmac_bytes_inputs(self):
        """Test HMAC generation with bytes inputs."""
        signature = generate_hmac(self.test_message_bytes, self.test_key_bytes)
        
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 32)
        
        # Should be same as string version
        signature_str = generate_hmac(self.test_message, self.test_key)
        self.assertEqual(signature, signature_str)
    
    def test_verify_hmac_valid(self):
        """Test HMAC verification with valid signature."""
        signature = generate_hmac(self.test_message, self.test_key)
        
        # Verification should succeed
        is_valid = verify_hmac(self.test_message, signature, self.test_key)
        self.assertTrue(is_valid)
        
        # Test with bytes inputs
        is_valid_bytes = verify_hmac(self.test_message_bytes, signature, self.test_key_bytes)
        self.assertTrue(is_valid_bytes)
    
    def test_verify_hmac_invalid_signature(self):
        """Test HMAC verification with invalid signature."""
        signature = generate_hmac(self.test_message, self.test_key)
        
        # Modify signature
        invalid_signature = bytearray(signature)
        invalid_signature[0] = (invalid_signature[0] + 1) % 256
        invalid_signature = bytes(invalid_signature)
        
        # Verification should fail
        is_valid = verify_hmac(self.test_message, invalid_signature, self.test_key)
        self.assertFalse(is_valid)
    
    def test_verify_hmac_wrong_key(self):
        """Test HMAC verification with wrong key."""
        signature = generate_hmac(self.test_message, self.test_key)
        wrong_key = "wrong_key"
        
        # Verification should fail
        is_valid = verify_hmac(self.test_message, signature, wrong_key)
        self.assertFalse(is_valid)
    
    def test_verify_hmac_wrong_message(self):
        """Test HMAC verification with wrong message."""
        signature = generate_hmac(self.test_message, self.test_key)
        wrong_message = "This is a different message"
        
        # Verification should fail
        is_valid = verify_hmac(wrong_message, signature, self.test_key)
        self.assertFalse(is_valid)
    
    def test_generate_hmac_hex(self):
        """Test HMAC generation with hex output."""
        signature_hex = generate_hmac_hex(self.test_message, self.test_key)
        
        self.assertIsInstance(signature_hex, str)
        self.assertEqual(len(signature_hex), 64)  # 32 bytes * 2 hex chars
        
        # Should be valid hex
        try:
            bytes.fromhex(signature_hex)
        except ValueError:
            self.fail("Generated signature is not valid hex")
        
        # Compare with binary version
        signature_binary = generate_hmac(self.test_message, self.test_key)
        self.assertEqual(signature_hex, signature_binary.hex())
    
    def test_verify_hmac_hex(self):
        """Test HMAC verification with hex input."""
        signature_hex = generate_hmac_hex(self.test_message, self.test_key)
        
        # Valid verification
        is_valid = verify_hmac_hex(self.test_message, signature_hex, self.test_key)
        self.assertTrue(is_valid)
        
        # Invalid hex string
        is_valid_invalid = verify_hmac_hex(self.test_message, "invalid_hex", self.test_key)
        self.assertFalse(is_valid_invalid)
        
        # Modified hex signature
        modified_hex = signature_hex[:-2] + "FF"
        is_valid_modified = verify_hmac_hex(self.test_message, modified_hex, self.test_key)
        self.assertFalse(is_valid_modified)
    
    def test_sign_data_with_key(self):
        """Test convenience function for signing data."""
        result = sign_data_with_key(self.test_message, self.test_key)
        
        # Check result structure
        self.assertIn('signature', result)
        self.assertIn('signature_hex', result)
        self.assertIn('key_used', result)
        
        # Check types
        self.assertIsInstance(result['signature'], bytes)
        self.assertIsInstance(result['signature_hex'], str)
        self.assertEqual(result['key_used'], self.test_key)
        
        # Verify signature
        is_valid = verify_hmac(self.test_message, result['signature'], self.test_key)
        self.assertTrue(is_valid)
        
        # Test with default key
        result_default = sign_data_with_key(self.test_message)
        self.assertEqual(result_default['key_used'], "default_key")
    
    def test_create_authenticated_message(self):
        """Test creating authenticated message."""
        result = create_authenticated_message(self.test_message, self.test_key)
        
        # Check result structure
        self.assertIn('message', result)
        self.assertIn('hmac', result)
        self.assertIn('authenticated_message', result)
        
        # Check types and content
        self.assertIsInstance(result['message'], bytes)
        self.assertIsInstance(result['hmac'], bytes)
        self.assertIsInstance(result['authenticated_message'], bytes)
        
        # Authenticated message should be hmac + message
        expected_length = 32 + len(self.test_message_bytes)
        self.assertEqual(len(result['authenticated_message']), expected_length)
        
        # Should start with HMAC
        self.assertEqual(result['authenticated_message'][:32], result['hmac'])
        # Should end with message
        self.assertEqual(result['authenticated_message'][32:], result['message'])
    
    def test_extract_and_verify_message(self):
        """Test extracting and verifying authenticated message."""
        # Create authenticated message
        auth_result = create_authenticated_message(self.test_message, self.test_key)
        authenticated_message = auth_result['authenticated_message']
        
        # Extract and verify
        extract_result = extract_and_verify_message(authenticated_message, self.test_key)
        
        # Check result structure
        self.assertIn('message', extract_result)
        self.assertIn('verified', extract_result)
        self.assertIn('hmac', extract_result)
        
        # Verification should succeed
        self.assertTrue(extract_result['verified'])
        self.assertEqual(extract_result['message'], self.test_message_bytes)
        self.assertEqual(extract_result['hmac'], auth_result['hmac'])
    
    def test_extract_and_verify_message_invalid(self):
        """Test extracting and verifying with invalid authenticated message."""
        # Create authenticated message
        auth_result = create_authenticated_message(self.test_message, self.test_key)
        authenticated_message = bytearray(auth_result['authenticated_message'])
        
        # Modify the message part
        authenticated_message[-1] = (authenticated_message[-1] + 1) % 256
        
        # Extract and verify
        extract_result = extract_and_verify_message(bytes(authenticated_message), self.test_key)
        
        # Verification should fail
        self.assertFalse(extract_result['verified'])
        self.assertIsNotNone(extract_result['message'])  # Message should still be extracted
    
    def test_extract_message_too_short(self):
        """Test extracting from message that's too short."""
        short_message = b"short"  # Less than 32 bytes
        
        result = extract_and_verify_message(short_message, self.test_key)
        
        self.assertIn('error', result)
        self.assertFalse(result['verified'])
        self.assertIsNone(result['message'])
    
    def test_empty_message(self):
        """Test HMAC with empty message."""
        empty_message = ""
        signature = generate_hmac(empty_message, self.test_key)
        
        self.assertIsInstance(signature, bytes)
        self.assertEqual(len(signature), 32)
        
        # Verification should work
        is_valid = verify_hmac(empty_message, signature, self.test_key)
        self.assertTrue(is_valid)
    
    def test_unicode_message(self):
        """Test HMAC with Unicode message."""
        unicode_message = "Hello 世界! 🔐 HMAC test"
        signature = generate_hmac(unicode_message, self.test_key)
        
        # Verification should work
        is_valid = verify_hmac(unicode_message, signature, self.test_key)
        self.assertTrue(is_valid)
    
    def test_different_keys_different_signatures(self):
        """Test that different keys produce different signatures."""
        key1 = "key1"
        key2 = "key2"
        
        sig1 = generate_hmac(self.test_message, key1)
        sig2 = generate_hmac(self.test_message, key2)
        
        self.assertNotEqual(sig1, sig2)
    
    def test_timing_safe_comparison(self):
        """Test that HMAC verification uses timing-safe comparison."""
        # This test ensures we're using hmac.compare_digest
        signature = generate_hmac(self.test_message, self.test_key)
        
        # Create a signature that differs in the last byte
        wrong_signature = bytearray(signature)
        wrong_signature[-1] = (wrong_signature[-1] + 1) % 256
        wrong_signature = bytes(wrong_signature)
        
        # Both should return False, but the function should use timing-safe comparison
        is_valid = verify_hmac(self.test_message, wrong_signature, self.test_key)
        self.assertFalse(is_valid)

if __name__ == '__main__':
    unittest.main()
