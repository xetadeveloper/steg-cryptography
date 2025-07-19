"""
Unit tests for the RSA encryption/decryption module.
"""

import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.rsa_module import (
    generate_rsa_keypair, load_private_key_from_pem, load_public_key_from_pem,
    rsa_encrypt, rsa_decrypt, get_public_key_from_private, get_key_size
)

class TestRSAModule(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a secret message for RSA testing!"
        self.private_key_pem, self.public_key_pem = generate_rsa_keypair()
    
    def test_generate_rsa_keypair(self):
        """Test RSA keypair generation."""
        private_pem, public_pem = generate_rsa_keypair()
        
        # Check that keys are strings
        self.assertIsInstance(private_pem, str)
        self.assertIsInstance(public_pem, str)
        
        # Check PEM format headers
        self.assertIn("BEGIN PRIVATE KEY", private_pem)
        self.assertIn("END PRIVATE KEY", private_pem)
        self.assertIn("BEGIN PUBLIC KEY", public_pem)
        self.assertIn("END PUBLIC KEY", public_pem)
        
        # Test different key sizes
        private_1024, public_1024 = generate_rsa_keypair(1024)
        self.assertIsInstance(private_1024, str)
        self.assertIsInstance(public_1024, str)
    
    def test_load_keys_from_pem(self):
        """Test loading keys from PEM format."""
        # Test loading private key
        private_key_obj = load_private_key_from_pem(self.private_key_pem)
        self.assertTrue(hasattr(private_key_obj, 'private_bytes'))
        
        # Test loading public key
        public_key_obj = load_public_key_from_pem(self.public_key_pem)
        self.assertTrue(hasattr(public_key_obj, 'public_bytes'))
    
    def test_rsa_encrypt_decrypt_string(self):
        """Test RSA encryption and decryption with string input."""
        # Encrypt with public key
        ciphertext = rsa_encrypt(self.test_message, self.public_key_pem)
        self.assertIsInstance(ciphertext, bytes)
        self.assertNotEqual(ciphertext, self.test_message.encode())
        
        # Decrypt with private key
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        self.assertEqual(decrypted.decode('utf-8'), self.test_message)
    
    def test_rsa_encrypt_decrypt_bytes(self):
        """Test RSA encryption and decryption with bytes input."""
        message_bytes = self.test_message.encode('utf-8')
        
        ciphertext = rsa_encrypt(message_bytes, self.public_key_pem)
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        
        self.assertEqual(decrypted, message_bytes)
    
    def test_get_public_key_from_private(self):
        """Test extracting public key from private key."""
        extracted_public = get_public_key_from_private(self.private_key_pem)
        
        # Should be valid PEM format
        self.assertIn("BEGIN PUBLIC KEY", extracted_public)
        self.assertIn("END PUBLIC KEY", extracted_public)
        
        # Should be able to encrypt with extracted public key
        ciphertext = rsa_encrypt(self.test_message, extracted_public)
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        
        self.assertEqual(decrypted.decode('utf-8'), self.test_message)
    
    def test_get_key_size(self):
        """Test getting key size from PEM."""
        # Test with private key
        private_size = get_key_size(self.private_key_pem)
        self.assertEqual(private_size, 2048)  # Default size
        
        # Test with public key
        public_size = get_key_size(self.public_key_pem)
        self.assertEqual(public_size, 2048)
        
        # Test with different key size
        private_1024, public_1024 = generate_rsa_keypair(1024)
        size_1024 = get_key_size(private_1024)
        self.assertEqual(size_1024, 1024)
    
    def test_encryption_with_different_keys(self):
        """Test that encryption with different keys produces different results."""
        _, public_key_2 = generate_rsa_keypair()
        
        ciphertext_1 = rsa_encrypt(self.test_message, self.public_key_pem)
        ciphertext_2 = rsa_encrypt(self.test_message, public_key_2)
        
        self.assertNotEqual(ciphertext_1, ciphertext_2)
    
    def test_wrong_key_decryption(self):
        """Test that decryption with wrong private key fails."""
        wrong_private, _ = generate_rsa_keypair()
        ciphertext = rsa_encrypt(self.test_message, self.public_key_pem)
        
        with self.assertRaises(Exception):
            rsa_decrypt(ciphertext, wrong_private)
    
    def test_empty_message(self):
        """Test encryption/decryption of empty message."""
        empty_message = ""
        ciphertext = rsa_encrypt(empty_message, self.public_key_pem)
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        
        self.assertEqual(decrypted.decode('utf-8'), empty_message)
    
    def test_large_message_handling(self):
        """Test handling of messages that are too large for RSA."""
        # RSA with 2048-bit key can encrypt at most 190 bytes with OAEP padding
        large_message = "A" * 500  # Too large
        
        with self.assertRaises(Exception):
            rsa_encrypt(large_message, self.public_key_pem)
    
    def test_unicode_message(self):
        """Test encryption/decryption of Unicode message."""
        unicode_message = "Hello 世界! 🔐"
        ciphertext = rsa_encrypt(unicode_message, self.public_key_pem)
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        
        self.assertEqual(decrypted.decode('utf-8'), unicode_message)
    
    def test_binary_data_encryption(self):
        """Test encryption/decryption of binary data."""
        binary_data = os.urandom(50)  # Random binary data
        ciphertext = rsa_encrypt(binary_data, self.public_key_pem)
        decrypted = rsa_decrypt(ciphertext, self.private_key_pem)
        
        self.assertEqual(decrypted, binary_data)
    
    def test_invalid_pem_format(self):
        """Test error handling for invalid PEM format."""
        invalid_pem = "This is not a valid PEM key"
        
        with self.assertRaises(Exception):
            load_private_key_from_pem(invalid_pem)
        
        with self.assertRaises(Exception):
            load_public_key_from_pem(invalid_pem)
    
    def test_key_pair_consistency(self):
        """Test that generated key pairs are consistent."""
        # Generate multiple key pairs and verify they work
        for _ in range(5):
            private, public = generate_rsa_keypair()
            
            # Test encryption/decryption
            ciphertext = rsa_encrypt("test", public)
            decrypted = rsa_decrypt(ciphertext, private)
            self.assertEqual(decrypted.decode('utf-8'), "test")
            
            # Test public key extraction
            extracted_public = get_public_key_from_private(private)
            ciphertext2 = rsa_encrypt("test", extracted_public)
            decrypted2 = rsa_decrypt(ciphertext2, private)
            self.assertEqual(decrypted2.decode('utf-8'), "test")

if __name__ == '__main__':
    unittest.main()
