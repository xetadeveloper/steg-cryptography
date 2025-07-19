"""
Unit tests for the steganography module.
"""

import sys
import os
import unittest
import io

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.stego_module import (
    text_to_binary, binary_to_text, encode_message_in_image, 
    decode_message_from_image, get_image_capacity, create_test_image,
    validate_image_for_steganography
)

class TestStegoModule(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures."""
        self.test_message = "This is a secret message hidden in the image!"
        self.test_image_data = create_test_image(400, 300)
    
    def test_text_to_binary(self):
        """Test text to binary conversion."""
        text = "Hello"
        binary = text_to_binary(text)
        
        # "Hello" should be 5 chars * 8 bits = 40 bits
        self.assertEqual(len(binary), 40)
        
        # Should be all 0s and 1s
        for char in binary:
            self.assertIn(char, '01')
        
        # Test known conversion
        # 'A' is ASCII 65, which is 01000001 in binary
        binary_A = text_to_binary('A')
        self.assertEqual(binary_A, '01000001')
    
    def test_binary_to_text(self):
        """Test binary to text conversion."""
        # 'A' is 01000001
        binary = '01000001'
        text = binary_to_text(binary)
        self.assertEqual(text, 'A')
        
        # Test with multiple characters
        binary_hello = '0100100001100101011011000110110001101111'  # "Hello"
        text_hello = binary_to_text(binary_hello)
        self.assertEqual(text_hello, 'Hello')
    
    def test_text_binary_roundtrip(self):
        """Test text to binary and back conversion."""
        original_text = "Hello World! 🔐 Test 123"
        binary = text_to_binary(original_text)
        converted_back = binary_to_text(binary)
        
        self.assertEqual(converted_back, original_text)
    
    def test_create_test_image(self):
        """Test test image creation."""
        image_data = create_test_image(200, 150, (255, 0, 0))  # Red image
        
        self.assertIsInstance(image_data, bytes)
        self.assertGreater(len(image_data), 100)  # Should be substantial PNG data
        
        # Verify it's a PNG by checking header
        self.assertEqual(image_data[:8], b'\x89PNG\r\n\x1a\n')
    
    def test_get_image_capacity(self):
        """Test image capacity calculation."""
        capacity = get_image_capacity(self.test_image_data)
        
        # Check result structure
        expected_keys = ['width', 'height', 'total_pixels', 'total_bits_capacity', 
                        'max_characters', 'max_characters_with_delimiter']
        for key in expected_keys:
            self.assertIn(key, capacity)
        
        # Check values make sense
        self.assertEqual(capacity['width'], 400)
        self.assertEqual(capacity['height'], 300)
        self.assertEqual(capacity['total_pixels'], 400 * 300)
        self.assertEqual(capacity['total_bits_capacity'], 400 * 300 * 3)
        self.assertEqual(capacity['max_characters'], capacity['total_bits_capacity'] // 8)
    
    def test_encode_decode_message_basic(self):
        """Test basic message encoding and decoding."""
        # Encode message
        stego_image = encode_message_in_image(self.test_image_data, self.test_message)
        
        self.assertIsInstance(stego_image, bytes)
        self.assertNotEqual(stego_image, self.test_image_data)  # Should be different
        
        # Decode message
        decoded_message = decode_message_from_image(stego_image)
        
        self.assertEqual(decoded_message, self.test_message)
    
    def test_encode_decode_empty_message(self):
        """Test encoding and decoding empty message."""
        empty_message = ""
        
        stego_image = encode_message_in_image(self.test_image_data, empty_message)
        decoded_message = decode_message_from_image(stego_image)
        
        self.assertEqual(decoded_message, empty_message)
    
    def test_encode_decode_unicode_message(self):
        """Test encoding and decoding Unicode message."""
        unicode_message = "Hello 世界! 🔐 Steganography test"
        
        stego_image = encode_message_in_image(self.test_image_data, unicode_message)
        decoded_message = decode_message_from_image(stego_image)
        
        self.assertEqual(decoded_message, unicode_message)
    
    def test_encode_decode_long_message(self):
        """Test encoding and decoding long message."""
        long_message = "A" * 1000  # 1000 character message
        
        # Check if image has enough capacity
        capacity = get_image_capacity(self.test_image_data)
        if len(long_message) > capacity['max_characters_with_delimiter']:
            # Create larger image
            large_image = create_test_image(800, 600)
            stego_image = encode_message_in_image(large_image, long_message)
        else:
            stego_image = encode_message_in_image(self.test_image_data, long_message)
        
        decoded_message = decode_message_from_image(stego_image)
        self.assertEqual(decoded_message, long_message)
    
    def test_encode_message_too_large(self):
        """Test encoding message that's too large for image."""
        # Create very small image
        small_image = create_test_image(10, 10)  # Only 300 bits capacity
        
        # Try to encode a message that's too large
        large_message = "A" * 100  # Should be too large for small image
        
        with self.assertRaises(Exception) as context:
            encode_message_in_image(small_image, large_message)
        
        self.assertIn("too long", str(context.exception).lower())
    
    def test_custom_delimiter(self):
        """Test encoding and decoding with custom delimiter."""
        custom_delimiter = "###CUSTOM_END###"
        message = "Test message with custom delimiter"
        
        stego_image = encode_message_in_image(
            self.test_image_data, message, delimiter=custom_delimiter
        )
        decoded_message = decode_message_from_image(
            stego_image, delimiter=custom_delimiter
        )
        
        self.assertEqual(decoded_message, message)
    
    def test_decode_wrong_delimiter(self):
        """Test decoding with wrong delimiter."""
        stego_image = encode_message_in_image(
            self.test_image_data, self.test_message, delimiter="###END###"
        )
        
        # Try to decode with wrong delimiter
        with self.assertRaises(Exception):
            decode_message_from_image(stego_image, delimiter="###WRONG###")
    
    def test_decode_non_stego_image(self):
        """Test decoding image that doesn't contain hidden message."""
        # Try to decode original image (no hidden message)
        with self.assertRaises(Exception):
            decode_message_from_image(self.test_image_data)
    
    def test_validate_image_for_steganography(self):
        """Test image validation for steganography."""
        validation = validate_image_for_steganography(self.test_image_data)
        
        # Check result structure
        expected_keys = ['is_suitable', 'issues', 'recommendations', 
                        'capacity_info', 'image_info']
        for key in expected_keys:
            self.assertIn(key, validation)
        
        # Should be suitable for our test image
        self.assertTrue(validation['is_suitable'])
        
        # Test with very small image
        small_image = create_test_image(50, 50)
        small_validation = validate_image_for_steganography(small_image)
        
        # Might have issues due to small size
        self.assertIsInstance(small_validation['issues'], list)
    
    def test_validate_invalid_image(self):
        """Test validation with invalid image data."""
        invalid_data = b"This is not an image"
        
        validation = validate_image_for_steganography(invalid_data)
        
        self.assertFalse(validation['is_suitable'])
        self.assertGreater(len(validation['issues']), 0)
        self.assertIsNone(validation['capacity_info'])
    
    def test_encode_decode_binary_like_message(self):
        """Test encoding and decoding message that looks like binary."""
        binary_like_message = "01010101 11110000 Message with binary patterns"
        
        stego_image = encode_message_in_image(self.test_image_data, binary_like_message)
        decoded_message = decode_message_from_image(stego_image)
        
        self.assertEqual(decoded_message, binary_like_message)
    
    def test_multiple_encode_decode_cycles(self):
        """Test multiple encoding/decoding cycles."""
        messages = [
            "First message",
            "Second message with different content",
            "Third message 🔐",
            "",  # Empty message
            "Final message"
        ]
        
        for message in messages:
            with self.subTest(message=message[:20]):
                stego_image = encode_message_in_image(self.test_image_data, message)
                decoded_message = decode_message_from_image(stego_image)
                self.assertEqual(decoded_message, message)
    
    def test_image_format_handling(self):
        """Test that different image formats are handled correctly."""
        # Test with different color modes by creating and testing
        test_messages = ["RGB test", "Format test"]
        
        for message in test_messages:
            # Our create_test_image creates RGB images, which should work
            stego_image = encode_message_in_image(self.test_image_data, message)
            decoded_message = decode_message_from_image(stego_image)
            self.assertEqual(decoded_message, message)
    
    def test_special_characters_in_message(self):
        """Test encoding messages with special characters."""
        special_message = "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?\n\t"
        
        stego_image = encode_message_in_image(self.test_image_data, special_message)
        decoded_message = decode_message_from_image(stego_image)
        
        self.assertEqual(decoded_message, special_message)

if __name__ == '__main__':
    unittest.main()
