import os
import sys

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import aes_module  # Make sure core/ is a module (has __init__.py)

def test_aes_encrypt_decrypt():
    # Define a plaintext message
    message = b"This is a test message for AES encryption."

    # Generate a random 256-bit (32-byte) AES key
    aes_key = os.urandom(32)

    # Encrypt the message
    encrypt_result = aes_module.aes_encrypt(message, aes_key)
    ciphertext = encrypt_result["ciphertext"]
    iv = encrypt_result["iv"]

    # Decrypt the message using the ciphertext, IV, and AES key
    decrypt_result = aes_module.aes_decrypt(
        ciphertext=ciphertext,
        iv=iv,
        aes_key=aes_key
    )

    # Compare the decrypted result with the original message
    assert decrypt_result["plaintext"] == message, "Decryption failed: messages do not match!"

    # Print confirmation
    print("AES encryption and decryption test passed.")
    print("Original Message:", message)
    print("Decrypted Message:", decrypt_result["plaintext"])

# Runs test directly if executed as a script
if __name__ == "__main__":
    test_aes_encrypt_decrypt()
