"""
Unit tests for the full decryption pipeline.
"""

import sys
import os
import unittest

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encrypt_full import encrypt_full_pipeline
from core.decrypt_full import (
    decrypt_full_pipeline, decrypt_from_stego_only, 
    verify_pipeline_integrity, get_decryption_info
)
from core.stego_module import create_test_image
from core.rsa_module import generate_rsa_keypair

class TestDecryptFullPipeline(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a secret message for full pipeline testing!"
        self.test_image = create_test_image(600, 400)
        self.hmac_key = "test_hmac_key"
        
        # Create encrypted data for testing
        self.encrypted_result = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
    
    def test_decrypt_full_pipeline_basic(self):
        """Test basic full decryption pipeline."""
        result = decrypt_full_pipeline(
            stego_image_data=self.encrypted_result['stego_image_data'],
            encrypted_aes_key=self.encrypted_result['encrypted_aes_key'],
            hmac_signature=self.encrypted_result['hmac_signature'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        # Check result structure
        expected_keys = [
            'decrypted_message', 'hmac_verified', 'aes_key', 'iv',
            'encrypted_message', 'extracted_data'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # Check decryption success
        self.assertEqual(result['decrypted_message'], self.test_message)
        self.assertTrue(result['hmac_verified'])
        
        # Check types
        self.assertIsInstance(result['decrypted_message'], str)
        self.assertIsInstance(result['hmac_verified'], bool)
        self.assertIsInstance(result['aes_key'], bytes)
        self.assertIsInstance(result['iv'], bytes)
    
    def test_decrypt_from_stego_only(self):
        """Test decryption when all data is embedded in steganographic image."""
        result = decrypt_from_stego_only(
            stego_image_data=self.encrypted_result['stego_image_data'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        # Check decryption success
        self.assertEqual(result['decrypted_message'], self.test_message)
        self.assertTrue(result['hmac_verified'])
        self.assertEqual(result['extraction_method'], 'steganography_only')
    
    def test_decrypt_empty_message(self):
        """Test decryption of empty message."""
        empty_message = ""
        
        # Encrypt empty message
        encrypted_empty = encrypt_full_pipeline(
            message=empty_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        # Decrypt
        result = decrypt_from_stego_only(
            stego_image_data=encrypted_empty['stego_image_data'],
            rsa_private_key_pem=encrypted_empty['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['decrypted_message'], empty_message)
        self.assertTrue(result['hmac_verified'])
    
    def test_decrypt_unicode_message(self):
        """Test decryption of Unicode message."""
        unicode_message = "Hello 世界! 🔐 Full pipeline test"
        
        # Encrypt Unicode message
        encrypted_unicode = encrypt_full_pipeline(
            message=unicode_message,
            image_data=self.test_image,
            hmac_key=self.hmac_key
        )
        
        # Decrypt
        result = decrypt_from_stego_only(
            stego_image_data=encrypted_unicode['stego_image_data'],
            rsa_private_key_pem=encrypted_unicode['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['decrypted_message'], unicode_message)
        self.assertTrue(result['hmac_verified'])
    
    def test_decrypt_long_message(self):
        """Test decryption of long message."""
        long_message = "A" * 1000
        large_image = create_test_image(800, 600)
        
        # Encrypt long message
        encrypted_long = encrypt_full_pipeline(
            message=long_message,
            image_data=large_image,
            hmac_key=self.hmac_key
        )
        
        # Decrypt
        result = decrypt_from_stego_only(
            stego_image_data=encrypted_long['stego_image_data'],
            rsa_private_key_pem=encrypted_long['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['decrypted_message'], long_message)
        self.assertTrue(result['hmac_verified'])
    
    def test_decrypt_wrong_rsa_key(self):
        """Test decryption with wrong RSA private key."""
        # Generate different RSA keypair
        wrong_private, _ = generate_rsa_keypair()
        
        with self.assertRaises(Exception):
            decrypt_from_stego_only(
                stego_image_data=self.encrypted_result['stego_image_data'],
                rsa_private_key_pem=wrong_private,
                hmac_key=self.hmac_key
            )
    
    def test_decrypt_wrong_hmac_key(self):
        """Test decryption with wrong HMAC key."""
        wrong_hmac_key = "wrong_key"
        
        result = decrypt_from_stego_only(
            stego_image_data=self.encrypted_result['stego_image_data'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=wrong_hmac_key
        )
        
        # Message should still decrypt, but HMAC verification should fail
        self.assertEqual(result['decrypted_message'], self.test_message)
        self.assertFalse(result['hmac_verified'])
    
    def test_decrypt_corrupted_stego_image(self):
        """Test decryption with corrupted steganographic image."""
        # Corrupt the stego image data
        corrupted_image = bytearray(self.encrypted_result['stego_image_data'])
        corrupted_image[100:200] = b'\x00' * 100  # Zero out some bytes
        
        with self.assertRaises(Exception):
            decrypt_from_stego_only(
                stego_image_data=bytes(corrupted_image),
                rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
                hmac_key=self.hmac_key
            )
    
    def test_decrypt_non_stego_image(self):
        """Test decryption with regular image (no hidden data)."""
        regular_image = create_test_image(400, 300)
        
        with self.assertRaises(Exception):
            decrypt_from_stego_only(
                stego_image_data=regular_image,
                rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
                hmac_key=self.hmac_key
            )
    
    def test_verify_pipeline_integrity(self):
        """Test pipeline integrity verification."""
        result = verify_pipeline_integrity(
            stego_image_data=self.encrypted_result['stego_image_data'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key,
            expected_message=self.test_message
        )
        
        # Check result structure
        expected_keys = [
            'decryption_successful', 'hmac_verified', 'decrypted_message',
            'message_length', 'pipeline_integrity', 'expected_message_match'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)
        
        # Check success
        self.assertTrue(result['decryption_successful'])
        self.assertTrue(result['hmac_verified'])
        self.assertTrue(result['expected_message_match'])
        self.assertEqual(result['pipeline_integrity'], 'PASS')
        self.assertEqual(result['decrypted_message'], self.test_message)
    
    def test_verify_pipeline_integrity_wrong_expected_message(self):
        """Test pipeline integrity verification with wrong expected message."""
        result = verify_pipeline_integrity(
            stego_image_data=self.encrypted_result['stego_image_data'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key,
            expected_message="Wrong expected message"
        )
        
        # Decryption should succeed but message match should fail
        self.assertTrue(result['decryption_successful'])
        self.assertTrue(result['hmac_verified'])
        self.assertFalse(result['expected_message_match'])
        self.assertEqual(result['pipeline_integrity'], 'FAIL (MESSAGE_MISMATCH)')
    
    def test_verify_pipeline_integrity_wrong_hmac(self):
        """Test pipeline integrity verification with wrong HMAC key."""
        result = verify_pipeline_integrity(
            stego_image_data=self.encrypted_result['stego_image_data'],
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key="wrong_hmac_key",
            expected_message=self.test_message
        )
        
        # Decryption should succeed but HMAC verification should fail
        self.assertTrue(result['decryption_successful'])
        self.assertFalse(result['hmac_verified'])
        self.assertTrue(result['expected_message_match'])
        self.assertEqual(result['pipeline_integrity'], 'FAIL (HMAC)')
    
    def test_verify_pipeline_integrity_corrupted_data(self):
        """Test pipeline integrity verification with corrupted data."""
        corrupted_image = bytearray(self.encrypted_result['stego_image_data'])
        corrupted_image[100] = (corrupted_image[100] + 1) % 256
        
        result = verify_pipeline_integrity(
            stego_image_data=bytes(corrupted_image),
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key,
            expected_message=self.test_message
        )
        
        # Should fail to decrypt
        self.assertFalse(result['decryption_successful'])
        self.assertEqual(result['pipeline_integrity'], 'FAIL (DECRYPTION_ERROR)')
        self.assertIn('error', result)
    
    def test_get_decryption_info(self):
        """Test getting decryption pipeline information."""
        info = get_decryption_info()
        
        # Check structure
        expected_keys = [
            'pipeline_steps', 'required_inputs', 'verification_levels', 'error_handling'
        ]
        
        for key in expected_keys:
            self.assertIn(key, info)
        
        # Check content types
        self.assertIsInstance(info['pipeline_steps'], list)
        self.assertIsInstance(info['required_inputs'], list)
        self.assertIsInstance(info['verification_levels'], list)
        self.assertIsInstance(info['error_handling'], list)
        
        # Check that we have expected number of steps
        self.assertEqual(len(info['pipeline_steps']), 5)
    
    def test_decrypt_mixed_parameters(self):
        """Test decryption using mixed parameter sources."""
        # Test using some parameters from steganographic data and some provided
        result = decrypt_full_pipeline(
            stego_image_data=self.encrypted_result['stego_image_data'],
            encrypted_aes_key=None,  # Should extract from stego image
            hmac_signature=self.encrypted_result['hmac_signature'],  # Provided
            rsa_private_key_pem=self.encrypted_result['rsa_private_key_pem'],
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result['decrypted_message'], self.test_message)
        self.assertTrue(result['hmac_verified'])
    
    def test_decrypt_roundtrip_multiple_messages(self):
        """Test encrypt-decrypt roundtrip with multiple messages."""
        messages = [
            "First test message",
            "Second message with numbers 123",
            "Third message with special chars !@#$%",
            "Fourth message with unicode 🔐 世界",
            ""  # Empty message
        ]
        
        for i, message in enumerate(messages):
            with self.subTest(message_index=i):
                # Encrypt
                encrypted = encrypt_full_pipeline(
                    message=message,
                    image_data=self.test_image,
                    hmac_key=f"hmac_key_{i}"
                )
                
                # Decrypt
                decrypted = decrypt_from_stego_only(
                    stego_image_data=encrypted['stego_image_data'],
                    rsa_private_key_pem=encrypted['rsa_private_key_pem'],
                    hmac_key=f"hmac_key_{i}"
                )
                
                self.assertEqual(decrypted['decrypted_message'], message)
                self.assertTrue(decrypted['hmac_verified'])
    
    def test_decrypt_with_different_rsa_key_sizes(self):
        """Test decryption with different RSA key sizes."""
        # Test with 1024-bit key
        private_1024, public_1024 = generate_rsa_keypair(1024)
        
        encrypted_1024 = encrypt_full_pipeline(
            message=self.test_message,
            image_data=self.test_image,
            rsa_public_key_pem=public_1024,
            hmac_key=self.hmac_key
        )
        
        result_1024 = decrypt_full_pipeline(
            stego_image_data=encrypted_1024['stego_image_data'],
            encrypted_aes_key=encrypted_1024['encrypted_aes_key'],
            hmac_signature=encrypted_1024['hmac_signature'],
            rsa_private_key_pem=private_1024,
            hmac_key=self.hmac_key
        )
        
        self.assertEqual(result_1024['decrypted_message'], self.test_message)
        self.assertTrue(result_1024['hmac_verified'])

if __name__ == '__main__':
    unittest.main()
