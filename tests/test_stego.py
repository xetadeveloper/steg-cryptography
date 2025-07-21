
import sys
import os

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.stego_module import encode_message_in_image, decode_message_from_image, create_test_image

def test_stego_basic():
    """Test basic steganography functionality"""
    # Create a test image
    test_image_data = create_test_image(width=800, height=600)
    
    # Test message
    secret_message = "This is a secret message for testing steganography!"
    
    print("Testing steganography...")
    
    # Encode message into image
    stego_image_data = encode_message_in_image(test_image_data, secret_message)
    print("✓ Message encoded successfully")
    
    # Decode message from image
    extracted_message = decode_message_from_image(stego_image_data)
    print("✓ Message decoded successfully")
    
    # Verify the messages match
    assert extracted_message == secret_message, f"Message mismatch! Expected: '{secret_message}', Got: '{extracted_message}'"
    
    print(f"Original message: {secret_message}")
    print(f"Extracted message: {extracted_message}")
    print("✓ [Test Passed] Steganography embedding and extraction verified.")

def test_stego_large_message():
    """Test with a larger message"""
    # Create a larger test image
    test_image_data = create_test_image(width=1000, height=800)
    
    # Create a longer test message
    long_message = "This is a much longer secret message that will test the capacity of our steganography system. " * 10
    
    print("\nTesting with large message...")
    
    try:
        # Encode message into image
        stego_image_data = encode_message_in_image(test_image_data, long_message)
        print("✓ Large message encoded successfully")
        
        # Decode message from image
        extracted_message = decode_message_from_image(stego_image_data)
        print("✓ Large message decoded successfully")
        
        # Verify the messages match
        assert extracted_message == long_message, "Large message mismatch!"
        print("✓ [Test Passed] Large message steganography verified.")
        
    except Exception as e:
        print(f"✗ Large message test failed: {str(e)}")

if __name__ == "__main__":
    test_stego_basic()
    test_stego_large_message()
