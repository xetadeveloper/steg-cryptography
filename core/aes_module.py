"""
AES Encryption and Decryption Module

This module provides AES-256 encryption and decryption functionality
using CBC mode with PKCS7 padding for secure message encryption.
"""

import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def generate_aes_key(key_size=32):
    """
    Generate a secure AES key.
    
    Args:
        key_size (int): Key size in bytes (16, 24, or 32 for AES-128, AES-192, AES-256)
    
    Returns:
        bytes: Cryptographically secure random AES key
    """
    return os.urandom(key_size)


def aes_encrypt(plaintext, aes_key):
    """
    Encrypts a message using AES in CBC mode.
    
    Args:
        plaintext (str or bytes): The message to encrypt
        aes_key (bytes): A 16-, 24-, or 32-byte AES key
    
    Returns:
        tuple: (ciphertext, iv) - encrypted data and initialization vector
    """
    # Convert string to bytes if necessary
    if isinstance(plaintext, str):
        plaintext = plaintext.encode('utf-8')
    
    # Generate a secure 16-byte random IV (initialization vector)
    iv = os.urandom(16)
    
    # Create the AES cipher object with CBC mode
    cipher = Cipher(
        algorithms.AES(aes_key),  # Set the AES key
        modes.CBC(iv),  # Use CBC mode with the generated IV
        backend=default_backend(),  # Use default cryptographic backend
    )
    
    # Create an encryptor from the cipher
    encryptor = cipher.encryptor()
    
    # Pad the plaintext to a multiple of the AES block size (128 bits = 16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    
    # Encrypt the padded plaintext
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    return ciphertext, iv


def aes_decrypt(ciphertext, iv, aes_key):
    """
    Decrypts a message encrypted with AES in CBC mode.
    
    Args:
        ciphertext (bytes): The encrypted data
        iv (bytes): The IV used during encryption
        aes_key (bytes): The AES key used for encryption
    
    Returns:
        bytes: The decrypted plaintext
    """
    # Recreate the AES cipher using the same key and IV
    cipher = Cipher(
        algorithms.AES(aes_key),  # Use the same AES key
        modes.CBC(iv),  # Use the same IV
        backend=default_backend(),
    )
    
    # Create a decryptor from the cipher
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext to get padded plaintext
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding from the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext


def aes_encrypt_text(message, key=None):
    """
    Convenience function to encrypt a text message.
    
    Args:
        message (str): Text message to encrypt
        key (bytes, optional): AES key. If None, generates a new key
    
    Returns:
        dict: Contains encrypted data, key, and IV
    """
    if key is None:
        key = generate_aes_key()
    
    ciphertext, iv = aes_encrypt(message, key)
    
    return {
        'ciphertext': ciphertext,
        'iv': iv,
        'key': key,
        'original_message': message
    }


def aes_decrypt_text(ciphertext, iv, key):
    """
    Convenience function to decrypt text data.
    
    Args:
        ciphertext (bytes): Encrypted data
        iv (bytes): Initialization vector
        key (bytes): AES key
    
    Returns:
        str: Decrypted text message
    """
    plaintext_bytes = aes_decrypt(ciphertext, iv, key)
    return plaintext_bytes.decode('utf-8')


def create_secure_message(message, password=None):
    """
    Create a securely encrypted message with password-based key derivation.
    
    Args:
        message (str): Message to encrypt
        password (str, optional): Password for key derivation
    
    Returns:
        dict: Contains encrypted message and metadata
    """
    # Generate random key if no password provided
    if password is None:
        key = generate_aes_key()
        key_method = "random"
    else:
        # Simple password-based key (in production, use PBKDF2 or similar)
        import hashlib
        key = hashlib.sha256(password.encode()).digest()
        key_method = "password_derived"
    
    ciphertext, iv = aes_encrypt(message, key)
    
    return {
        'ciphertext': ciphertext,
        'iv': iv,
        'key': key if password is None else None,  # Don't return key if password-derived
        'key_method': key_method,
        'message_length': len(message)
    }


def decrypt_secure_message(encrypted_data, password=None, key=None):
    """
    Decrypt a message created with create_secure_message.
    
    Args:
        encrypted_data (dict): Data from create_secure_message
        password (str, optional): Password if message was password-encrypted
        key (bytes, optional): Key if message was key-encrypted
    
    Returns:
        str: Decrypted message
    """
    if encrypted_data['key_method'] == 'password_derived':
        if password is None:
            raise ValueError("Password required for password-encrypted message")
        import hashlib
        key = hashlib.sha256(password.encode()).digest()
    elif encrypted_data['key_method'] == 'random':
        if key is None and 'key' in encrypted_data:
            key = encrypted_data['key']
        elif key is None:
            raise ValueError("Key required for key-encrypted message")
    
    return aes_decrypt_text(encrypted_data['ciphertext'], encrypted_data['iv'], key)