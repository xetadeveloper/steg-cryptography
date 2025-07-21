
import os
import sys

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0,
                os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import aes_module  # Make sure core/ is a module (has __init__.py)


def test_aes_encrypt_decrypt():
    # Define a plaintext message
    message = "This is a test message for AES encryption."

    # Generate a random 256-bit (32-byte) AES key
    aes_key = os.urandom(32)

    # Encrypt the message - aes_encrypt returns (ciphertext, iv)
    ciphertext, iv = aes_module.aes_encrypt(message, aes_key)

    # Decrypt the message using the ciphertext, IV, and AES key
    # aes_decrypt returns bytes
    decrypted_bytes = aes_module.aes_decrypt(ciphertext, iv, aes_key)
    
    # Convert decrypted bytes back to string
    decrypted_message = decrypted_bytes.decode('utf-8')

    # Compare the decrypted result with the original message
    assert decrypted_message == message, "Decryption failed: messages do not match!"

    # Print confirmation
    print("AES encryption and decryption test passed.")
    print("Original Message:", message)
    print("Decrypted Message:", decrypted_message)


def test_aes_text_functions():
    """Test the convenience text functions"""
    message = "Hello, secure world!"
    
    # Test encryption with auto-generated key
    encrypted_data = aes_module.aes_encrypt_text(message)
    
    # Test decryption
    decrypted_text = aes_module.aes_decrypt_text(
        encrypted_data['ciphertext'], 
        encrypted_data['iv'], 
        encrypted_data['key']
    )
    
    assert decrypted_text == message, "Text encryption/decryption failed!"
    print("AES text functions test passed.")


def test_secure_message():
    """Test password-based encryption"""
    message = "This is a secret message"
    password = "my_secure_password"
    
    # Create secure message
    encrypted_data = aes_module.create_secure_message(message, password)
    
    # Decrypt secure message
    decrypted_message = aes_module.decrypt_secure_message(encrypted_data, password=password)
    
    assert decrypted_message == message, "Secure message encryption/decryption failed!"
    print("Secure message test passed.")


# Runs test directly if executed as a script
if __name__ == "__main__":
    print("🔍 Running AES tests...\n")
    test_aes_encrypt_decrypt()
    test_aes_text_functions()
    test_secure_message()
    print("\n✅ All AES tests passed!")
