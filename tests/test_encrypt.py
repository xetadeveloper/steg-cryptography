"""
Unit tests for the full encryption pipeline.
"""

import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encrypt_full import (
    encrypt_full_pipeline, encrypt_with_existing_keys, get_pipeline_info
)
from core.stego_module import create_test_image
from core.aes_module import generate_aes_key
from core.rsa_module import generate_rsa_keypair

class TestEncryptFullPipeline(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a secret message for full pipeline testing!"
        self.test_image = create_test_image(600, 400)  # Large enough for our tests
        self.hmac_key = "test_hmac_key"
    
    def test_encrypt_full_pipeline_basic(self):
        """Test basic full encryption pipeline."""
        result = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        # Check result structure
        expected_keys = [
            'encrypted_message', 'aes_key', 'iv', 'encrypted_aes_key',
            'hmac_signature', 'stego_image_data', 'rsa_private_key_pem',
            'rsa_public_key_pem', 'hmac_key_used', 'payload_length',
            'original_message'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # Check types
        self.assertIsInstance(result['encrypted_message'], bytes)
        self.assertIsInstance(result['aes_key'], bytes)
        self.assertIsInstance(result['iv'], bytes)
        self.assertIsInstance(result['encrypted_aes_key'], bytes)
        self.assertIsInstance(result['hmac_signature'], bytes)
        self.assertIsInstance(result['stego_image_data'], bytes)
        self.assertIsInstance(result['rsa_private_key_pem'], str)
        self.assertIsInstance(result['rsa_public_key_pem'], str)
        
        # Check sizes
        self.assertEqual(len(result['aes_key']), 32)  # 256-bit AES key
        self.assertEqual(len(result['iv']), 16)       # 128-bit IV
        self.assertEqual(len(result['hmac_signature']), 32)  # SHA-256 HMAC
        
        # Check that stego image is different from original
        self.assertNotEqual(result['stego_image_data'], self.test_image)
        
        # Check that original message is preserved for verification
        self.assertEqual(result['original_message'], self.test_message)
    
    def test_encrypt_with_provided_public_key(self):
        """Test encryption pipeline with provided RSA public key."""
        # Generate RSA keypair
        private_key, public_key = generate_rsa_keypair()
        
        result = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            rsa_public_key_pem=public_key,
            hmac_key=self.hmac_key
        )
        
        # Should use provided public key
        self.assertEqual(result['rsa_public_key_pem'], public_key)
        
        # Private key should be None since we only provided public key
        self.assertIsNone(result['rsa_private_key_pem'])
        
        # Other components should still be present
        self.assertIsInstance(result['encrypted_aes_key'], bytes)
        self.assertIsInstance(result['stego_image_data'], bytes)
    
    def test_encrypt_with_existing_keys(self):
        """Test encryption with pre-existing keys."""
        # Generate keys
        aes_key = generate_aes_key()
        private_key, public_key = generate_rsa_keypair()
        
        result = encrypt_with_existing_keys(
            message=self.test_message,
            image_data=self.test_image,
            aes_key=aes_key,
            rsa_public_key_pem=public_key,
            hmac_key=self.hmac_key
        )
        
        # Check that provided keys are used
        self.assertEqual(result['aes_key'], aes_key)
        self.assertEqual(result['rsa_public_key_pem'], public_key)
        
        # Check result structure
        expected_keys = [
            'encrypted_message', 'aes_key', 'iv', 'encrypted_aes_key',
            'hmac_signature', 'stego_image_data', 'rsa_public_key_pem',
            'hmac_key_used', 'payload_length', 'original_message'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
    
    def test_encrypt_empty_message(self):
        """Test encryption of empty message."""
        empty_message = ""
        
        result = encrypt_full_pipeline(
            message=empty_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['original_message'], empty_message)
        self.assertIsInstance(result['encrypted_message'], bytes)
        self.assertIsInstance(result['stego_image_data'], bytes)
    
    def test_encrypt_unicode_message(self):
        """Test encryption of Unicode message."""
        unicode_message = "Hello 世界! 🔐 Full pipeline test"
        
        result = encrypt_full_pipeline(
            message=unicode_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['original_message'], unicode_message)
        self.assertIsInstance(result['encrypted_message'], bytes)
    
    def test_encrypt_long_message(self):
        """Test encryption of long message."""
        long_message = "A" * 2000  # Long message
        
        # Create larger image to accommodate long message
        large_image = create_test_image(1000, 800)
        
        result = encrypt_full_pipeline(
            message=long_message,
            image_data=large_image,
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['original_message'], long_message)
        self.assertIsInstance(result['stego_image_data'], bytes)
    
    def test_encrypt_different_hmac_keys(self):
        """Test encryption with different HMAC keys."""
        hmac_key1 = "key1"
        hmac_key2 = "key2"
        
        result1 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=hmac_key1
        )
        
        result2 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=hmac_key2
        )
        
        # HMAC signatures should be different
        self.assertNotEqual(result1['hmac_signature'], result2['hmac_signature'])
        
        # Check that keys are recorded correctly
        self.assertEqual(result1['hmac_key_used'], hmac_key1)
        self.assertEqual(result2['hmac_key_used'], hmac_key2)
    
    def test_encrypt_message_too_large_for_image(self):
        """Test encryption with message too large for image."""
        # Create very small image
        small_image = create_test_image(50, 50)
        
        # Try to encrypt long message
        long_message = "A" * 1000
        
        with self.assertRaises(Exception) as context:
            encrypt_full_pipeline(
                message=long_message,
                image_data=small_image,
                hmac_key=self.hmac_key
            )
        
        # Should mention that message is too long or pipeline failed
        error_msg = str(context.exception).lower()
        self.assertTrue(
            "too long" in error_msg or 
            "pipeline failed" in error_msg or
            "capacity" in error_msg
        )
    
    def test_encrypt_invalid_image(self):
        """Test encryption with invalid image data."""
        invalid_image = b"This is not valid image data"
        
        with self.assertRaises(Exception):
            encrypt_full_pipeline(
                message=self.test_message,
                image_data=invalid_image,
                hmac_key=self.hmac_key
            )
    
    def test_encrypt_different_rsa_key_sizes(self):
        """Test encryption with different RSA key sizes."""
        # Test with 1024-bit key
        private_1024, public_1024 = generate_rsa_keypair(1024)
        
        result = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            rsa_public_key_pem=public_1024,
            hmac_key=self.hmac_key
        )
        
        # Should work with 1024-bit key
        self.assertIsInstance(result['encrypted_aes_key'], bytes)
        
        # Test with 4096-bit key
        private_4096, public_4096 = generate_rsa_keypair(4096)
        
        result_4096 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            rsa_public_key_pem=public_4096,
            hmac_key=self.hmac_key
        )
        
        # Should work with 4096-bit key
        self.assertIsInstance(result_4096['encrypted_aes_key'], bytes)
        
        # Encrypted AES keys should be different sizes
        self.assertNotEqual(
            len(result['encrypted_aes_key']), 
            len(result_4096['encrypted_aes_key'])
        )
    
    def test_get_pipeline_info(self):
        """Test getting pipeline information."""
        info = get_pipeline_info()
        
        # Check structure
        expected_keys = [
            'pipeline_steps', 'algorithms_used', 'security_features', 'key_sizes'
        ]
        
        for key in expected_keys:
            self.assertIn(key, info)
        
        # Check content types
        self.assertIsInstance(info['pipeline_steps'], list)
        self.assertIsInstance(info['algorithms_used'], dict)
        self.assertIsInstance(info['security_features'], list)
        self.assertIsInstance(info['key_sizes'], dict)
        
        # Check that we have expected number of steps
        self.assertEqual(len(info['pipeline_steps']), 4)
    
    def test_encrypt_multiple_messages_same_setup(self):
        """Test encrypting multiple different messages with same setup."""
        messages = [
            "First message",
            "Second message with different content",
            "Third message 🔐",
            "",  # Empty message
            "Final message with special chars: !@#$%"
        ]
        
        # Use same image and key for all
        for i, message in enumerate(messages):
            with self.subTest(message_index=i):
                result = encrypt_full_pipeline(
                    message=message,
                    image_data=self.test_image,
                    hmac_key=self.hmac_key
                )
                
                self.assertEqual(result['original_message'], message)
                self.assertIsInstance(result['stego_image_data'], bytes)
                
                # Each encryption should produce different results
                if i > 0:
                    # Compare with previous result (stored in closure)
                    self.assertNotEqual(
                        result['encrypted_message'], 
                        previous_result['encrypted_message']
                    )
                
                previous_result = result
    
    def test_encrypt_deterministic_components(self):
        """Test that some components are deterministic while others are random."""
        # Same message and keys should produce same HMAC but different AES results
        result1 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        result2 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        # AES keys and encrypted messages should be different (due to randomness)
        self.assertNotEqual(result1['aes_key'], result2['aes_key'])
        self.assertNotEqual(result1['encrypted_message'], result2['encrypted_message'])
        self.assertNotEqual(result1['iv'], result2['iv'])
        
        # RSA keys should be different (newly generated)
        self.assertNotEqual(result1['rsa_private_key_pem'], result2['rsa_private_key_pem'])

if __name__ == '__main__':
    unittest.main()
