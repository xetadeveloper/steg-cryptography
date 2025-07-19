"""
HMAC Signing and Verification Module

This module provides HMAC (Hash-based Message Authentication Code) functionality
using SHA-256 for message authentication and integrity verification.
"""

import hmac
import hashlib

def generate_hmac(message, key):
    """
    Generate HMAC signature for a message using SHA-256.
    
    Args:
        message (str or bytes): Message to sign
        key (str or bytes): Secret key for HMAC generation
    
    Returns:
        bytes: HMAC signature
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Generate HMAC using SHA-256
    signature = hmac.new(
        key, 
        message, 
        hashlib.sha256
    ).digest()
    
    return signature

def verify_hmac(message, signature, key):
    """
    Verify HMAC signature for a message.
    
    Args:
        message (str or bytes): Original message
        signature (bytes): HMAC signature to verify
        key (str or bytes): Secret key used for HMAC generation
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    if isinstance(key, str):
        key = key.encode('utf-8')
    
    # Generate expected signature
    expected_signature = hmac.new(
        key, 
        message, 
        hashlib.sha256
    ).digest()
    
    # Use hmac.compare_digest for timing-safe comparison
    return hmac.compare_digest(signature, expected_signature)

def generate_hmac_hex(message, key):
    """
    Generate HMAC signature and return as hexadecimal string.
    
    Args:
        message (str or bytes): Message to sign
        key (str or bytes): Secret key for HMAC generation
    
    Returns:
        str: HMAC signature as hex string
    """
    signature = generate_hmac(message, key)
    return signature.hex()

def verify_hmac_hex(message, signature_hex, key):
    """
    Verify HMAC signature provided as hexadecimal string.
    
    Args:
        message (str or bytes): Original message
        signature_hex (str): HMAC signature as hex string
        key (str or bytes): Secret key used for HMAC generation
    
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        signature = bytes.fromhex(signature_hex)
        return verify_hmac(message, signature, key)
    except ValueError:
        # Invalid hex string
        return False

def sign_data_with_key(data, key_string="default_key"):
    """
    Convenience function to sign arbitrary data with a key string.
    
    Args:
        data (str or bytes): Data to sign
        key_string (str): Key string (default: "default_key")
    
    Returns:
        dict: Contains 'signature' (bytes) and 'signature_hex' (str)
    """
    signature = generate_hmac(data, key_string)
    
    return {
        'signature': signature,
        'signature_hex': signature.hex(),
        'key_used': key_string
    }

def create_authenticated_message(message, key):
    """
    Create a message with embedded HMAC for integrity verification.
    
    Args:
        message (str or bytes): Original message
        key (str or bytes): HMAC key
    
    Returns:
        dict: Contains 'message', 'hmac', and combined 'authenticated_message'
    """
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    signature = generate_hmac(message, key)
    
    # Combine message and signature (signature first, then message)
    authenticated = signature + message
    
    return {
        'message': message,
        'hmac': signature,
        'authenticated_message': authenticated
    }

def extract_and_verify_message(authenticated_message, key):
    """
    Extract and verify a message from an authenticated message format.
    
    Args:
        authenticated_message (bytes): Combined signature + message
        key (str or bytes): HMAC key
    
    Returns:
        dict: Contains 'message', 'verified' (bool), and 'hmac'
    """
    # HMAC-SHA256 produces 32-byte signatures
    hmac_size = 32
    
    if len(authenticated_message) < hmac_size:
        return {
            'message': None,
            'verified': False,
            'hmac': None,
            'error': 'Message too short to contain HMAC'
        }
    
    # Extract HMAC and message
    signature = authenticated_message[:hmac_size]
    message = authenticated_message[hmac_size:]
    
    # Verify signature
    is_valid = verify_hmac(message, signature, key)
    
    return {
        'message': message,
        'verified': is_valid,
        'hmac': signature
    }
