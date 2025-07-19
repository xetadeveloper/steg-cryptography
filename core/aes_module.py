"""
AES Encryption/Decryption Module

This module provides AES-256 encryption and decryption functionality using
the cryptography library with CBC mode and PKCS7 padding.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

def generate_aes_key():
    """
    Generate a random 256-bit (32 byte) AES key.
    
    Returns:
        bytes: 32-byte AES key
    """
    return os.urandom(32)

def generate_iv():
    """
    Generate a random 128-bit (16 byte) initialization vector for AES CBC mode.
    
    Returns:
        bytes: 16-byte IV
    """
    return os.urandom(16)

def aes_encrypt(plaintext, key, iv=None):
    """
    Encrypt plaintext using AES-256 in CBC mode with PKCS7 padding.
    
    Args:
        plaintext (str or bytes): The data to encrypt
        key (bytes): 32-byte AES key
        iv (bytes, optional): 16-byte initialization vector. If None, generates random IV.
    
    Returns:
        tuple: (ciphertext, iv) where both are bytes
        
    Raises:
        ValueError: If key is not 32 bytes
        TypeError: If inputs are not proper types
    """
    if not isinstance(plaintext, bytes):
        plaintext = plaintext.encode('utf-8')
    
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (256 bits)")
    
    if iv is None:
        iv = generate_iv()
    elif len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext)
    padded_data += padder.finalize()
    
    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    
    return ciphertext, iv

def aes_decrypt(ciphertext, key, iv):
    """
    Decrypt ciphertext using AES-256 in CBC mode with PKCS7 padding.
    
    Args:
        ciphertext (bytes): The encrypted data
        key (bytes): 32-byte AES key
        iv (bytes): 16-byte initialization vector
    
    Returns:
        str: Decrypted plaintext as UTF-8 string
        
    Raises:
        ValueError: If key/IV are wrong size or decryption fails
        TypeError: If inputs are not bytes
    """
    if len(key) != 32:
        raise ValueError("AES key must be 32 bytes (256 bits)")
    
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes")
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode('utf-8')

def encrypt_with_key_generation(plaintext):
    """
    Convenience function that generates a key and encrypts plaintext.
    
    Args:
        plaintext (str or bytes): Data to encrypt
    
    Returns:
        dict: Contains 'ciphertext', 'key', and 'iv' as bytes
    """
    key = generate_aes_key()
    ciphertext, iv = aes_encrypt(plaintext, key)
    
    return {
        'ciphertext': ciphertext,
        'key': key,
        'iv': iv
    }
