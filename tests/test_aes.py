"""
Unit tests for the AES encryption/decryption module.
"""

import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes_module import (
    generate_aes_key, generate_iv, aes_encrypt, aes_decrypt, 
    encrypt_with_key_generation
)

class TestAESModule(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a secret message for testing AES encryption!"
        self.test_key = generate_aes_key()
        self.test_iv = generate_iv()
    
    def test_generate_aes_key(self):
        """Test AES key generation."""
        key = generate_aes_key()
        self.assertEqual(len(key), 32, "AES key should be 32 bytes")
        self.assertIsInstance(key, bytes, "AES key should be bytes")
        
        # Test that keys are different
        key2 = generate_aes_key()
        self.assertNotEqual(key, key2, "Generated keys should be unique")
    
    def test_generate_iv(self):
        """Test IV generation."""
        iv = generate_iv()
        self.assertEqual(len(iv), 16, "IV should be 16 bytes")
        self.assertIsInstance(iv, bytes, "IV should be bytes")
        
        # Test that IVs are different
        iv2 = generate_iv()
        self.assertNotEqual(iv, iv2, "Generated IVs should be unique")
    
    def test_aes_encrypt_decrypt_string(self):
        """Test AES encryption and decryption with string input."""
        ciphertext, iv = aes_encrypt(self.test_message, self.test_key)
        
        # Verify ciphertext properties
        self.assertIsInstance(ciphertext, bytes, "Ciphertext should be bytes")
        self.assertIsInstance(iv, bytes, "IV should be bytes")
        self.assertNotEqual(ciphertext, self.test_message.encode(), "Ciphertext should be different from plaintext")
        
        # Test decryption
        decrypted = aes_decrypt(ciphertext, self.test_key, iv)
        self.assertEqual(decrypted, self.test_message, "Decrypted message should match original")
    
    def test_aes_encrypt_decrypt_bytes(self):
        """Test AES encryption and decryption with bytes input."""
        message_bytes = self.test_message.encode('utf-8')
        ciphertext, iv = aes_encrypt(message_bytes, self.test_key)
        
        decrypted = aes_decrypt(ciphertext, self.test_key, iv)
        self.assertEqual(decrypted, self.test_message, "Decrypted message should match original")
    
    def test_aes_encrypt_with_custom_iv(self):
        """Test AES encryption with custom IV."""
        custom_iv = generate_iv()
        ciphertext, returned_iv = aes_encrypt(self.test_message, self.test_key, custom_iv)
        
        self.assertEqual(returned_iv, custom_iv, "Should return the provided IV")
        
        decrypted = aes_decrypt(ciphertext, self.test_key, custom_iv)
        self.assertEqual(decrypted, self.test_message, "Decryption with custom IV should work")
    
    def test_encrypt_with_key_generation(self):
        """Test convenience function with automatic key generation."""
        result = encrypt_with_key_generation(self.test_message)
        
        # Verify result structure
        self.assertIn('ciphertext', result)
        self.assertIn('key', result)
        self.assertIn('iv', result)
        
        # Verify types
        self.assertIsInstance(result['ciphertext'], bytes)
        self.assertIsInstance(result['key'], bytes)
        self.assertIsInstance(result['iv'], bytes)
        
        # Verify sizes
        self.assertEqual(len(result['key']), 32)
        self.assertEqual(len(result['iv']), 16)
        
        # Test decryption
        decrypted = aes_decrypt(result['ciphertext'], result['key'], result['iv'])
        self.assertEqual(decrypted, self.test_message)
    
    def test_invalid_key_size(self):
        """Test error handling for invalid key sizes."""
        invalid_key = os.urandom(16)  # Wrong size (16 instead of 32)
        
        with self.assertRaises(ValueError):
            aes_encrypt(self.test_message, invalid_key)
        
        with self.assertRaises(ValueError):
            aes_decrypt(b"dummy", invalid_key, self.test_iv)
    
    def test_invalid_iv_size(self):
        """Test error handling for invalid IV sizes."""
        invalid_iv = os.urandom(8)  # Wrong size (8 instead of 16)
        
        with self.assertRaises(ValueError):
            aes_encrypt(self.test_message, self.test_key, invalid_iv)
        
        with self.assertRaises(ValueError):
            aes_decrypt(b"dummy", self.test_key, invalid_iv)
    
    def test_empty_message(self):
        """Test encryption/decryption of empty message."""
        empty_message = ""
        ciphertext, iv = aes_encrypt(empty_message, self.test_key)
        decrypted = aes_decrypt(ciphertext, self.test_key, iv)
        
        self.assertEqual(decrypted, empty_message)
    
    def test_long_message(self):
        """Test encryption/decryption of long message."""
        long_message = "A" * 10000  # 10KB message
        ciphertext, iv = aes_encrypt(long_message, self.test_key)
        decrypted = aes_decrypt(ciphertext, self.test_key, iv)
        
        self.assertEqual(decrypted, long_message)
    
    def test_unicode_message(self):
        """Test encryption/decryption of Unicode message."""
        unicode_message = "Hello 世界! 🔐 Testing unicode encryption"
        ciphertext, iv = aes_encrypt(unicode_message, self.test_key)
        decrypted = aes_decrypt(ciphertext, self.test_key, iv)
        
        self.assertEqual(decrypted, unicode_message)
    
    def test_wrong_key_decryption(self):
        """Test that decryption with wrong key fails."""
        ciphertext, iv = aes_encrypt(self.test_message, self.test_key)
        wrong_key = generate_aes_key()
        
        # Should raise an exception due to padding error
        with self.assertRaises(Exception):
            aes_decrypt(ciphertext, wrong_key, iv)

if __name__ == '__main__':
    unittest.main()
