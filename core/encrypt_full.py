"""
Full Encryption Pipeline

This module combines AES encryption, RSA key exchange, HMAC signing,
and steganography to create a complete secure communication pipeline.
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes_module import generate_aes_key, aes_encrypt
from core.rsa_module import generate_rsa_keypair, rsa_encrypt, get_public_key_from_private
from core.hmac_module import generate_hmac
from core.stego_module import encode_message_in_image

def encrypt_full_pipeline(message, image_data, rsa_public_key_pem=None, hmac_key="default_hmac_key"):
    """
    Complete encryption pipeline that:
    1. Generates AES key and encrypts the message
    2. Encrypts AES key with RSA (generates keypair if no public key provided)
    3. Signs the encrypted message with HMAC
    4. Hides all encrypted data in the provided image using steganography
    
    Args:
        message (str): The plaintext message to encrypt
        image_data (bytes): Image data to use for steganography
        rsa_public_key_pem (str, optional): RSA public key. If None, generates new keypair
        hmac_key (str): Key for HMAC signing
    
    Returns:
        dict: Contains all encrypted components and keys needed for decryption
        
    Raises:
        Exception: If any step in the pipeline fails
    """
    try:
        # Step 1: Generate AES key and encrypt message
        print("Step 1: AES encryption...")
        aes_key = generate_aes_key()
        encrypted_message, iv = aes_encrypt(message, aes_key)
        
        # Combine IV and encrypted message for storage
        aes_data = iv + encrypted_message
        
        # Step 2: RSA encryption of AES key
        print("Step 2: RSA key exchange...")
        rsa_private_key_pem = None
        
        if rsa_public_key_pem is None:
            # Generate new RSA keypair
            rsa_private_key_pem, rsa_public_key_pem = generate_rsa_keypair()
        else:
            # If only public key provided, we can't decrypt later without private key
            # This is intentional for scenarios where you only have recipient's public key
            pass
        
        # Encrypt AES key with RSA public key
        encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key_pem)
        
        # Step 3: HMAC signing
        print("Step 3: HMAC signing...")
        # Sign the encrypted message data (IV + encrypted message)
        hmac_signature = generate_hmac(aes_data, hmac_key)
        
        # Step 4: Combine all data for steganography
        print("Step 4: Preparing data for steganography...")
        
        # Create a structured payload
        # Format: [encrypted_aes_key_length][encrypted_aes_key][hmac_signature][aes_data]
        encrypted_aes_key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
        
        payload = (encrypted_aes_key_length + encrypted_aes_key + 
                  hmac_signature + aes_data)
        
        # Convert payload to string for steganography (using base64-like encoding)
        import base64
        payload_str = base64.b64encode(payload).decode('utf-8')
        
        # Step 5: Steganography
        print("Step 5: Hiding data in image...")
        stego_image_data = encode_message_in_image(image_data, payload_str)
        
        # Prepare result
        result = {
            'encrypted_message': encrypted_message,
            'aes_key': aes_key,
            'iv': iv,
            'encrypted_aes_key': encrypted_aes_key,
            'hmac_signature': hmac_signature,
            'stego_image_data': stego_image_data,
            'rsa_private_key_pem': rsa_private_key_pem,
            'rsa_public_key_pem': rsa_public_key_pem,
            'hmac_key_used': hmac_key,
            'payload_length': len(payload),
            'original_message': message  # For verification purposes
        }
        
        print("Encryption pipeline completed successfully!")
        return result
        
    except Exception as e:
        raise Exception(f"Encryption pipeline failed: {str(e)}")

def encrypt_with_existing_keys(message, image_data, aes_key, rsa_public_key_pem, hmac_key="default_hmac_key"):
    """
    Encryption pipeline using pre-existing keys.
    
    Args:
        message (str): The plaintext message to encrypt
        image_data (bytes): Image data to use for steganography
        aes_key (bytes): Pre-generated AES key
        rsa_public_key_pem (str): RSA public key
        hmac_key (str): Key for HMAC signing
    
    Returns:
        dict: Contains all encrypted components
    """
    try:
        # Step 1: AES encryption with provided key
        encrypted_message, iv = aes_encrypt(message, aes_key)
        aes_data = iv + encrypted_message
        
        # Step 2: RSA encryption of AES key
        encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key_pem)
        
        # Step 3: HMAC signing
        hmac_signature = generate_hmac(aes_data, hmac_key)
        
        # Step 4: Prepare payload for steganography
        encrypted_aes_key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
        payload = (encrypted_aes_key_length + encrypted_aes_key + 
                  hmac_signature + aes_data)
        
        import base64
        payload_str = base64.b64encode(payload).decode('utf-8')
        
        # Step 5: Steganography
        stego_image_data = encode_message_in_image(image_data, payload_str)
        
        return {
            'encrypted_message': encrypted_message,
            'aes_key': aes_key,
            'iv': iv,
            'encrypted_aes_key': encrypted_aes_key,
            'hmac_signature': hmac_signature,
            'stego_image_data': stego_image_data,
            'rsa_public_key_pem': rsa_public_key_pem,
            'hmac_key_used': hmac_key,
            'payload_length': len(payload),
            'original_message': message
        }
        
    except Exception as e:
        raise Exception(f"Encryption with existing keys failed: {str(e)}")

def get_pipeline_info():
    """
    Get information about the encryption pipeline.
    
    Returns:
        dict: Pipeline information and capabilities
    """
    return {
        'pipeline_steps': [
            '1. AES-256 encryption of message',
            '2. RSA encryption of AES key',
            '3. HMAC-SHA256 signing for integrity',
            '4. Steganographic hiding in image'
        ],
        'algorithms_used': {
            'symmetric_encryption': 'AES-256-CBC',
            'asymmetric_encryption': 'RSA-2048-OAEP',
            'message_authentication': 'HMAC-SHA256',
            'steganography': 'LSB (Least Significant Bit)'
        },
        'security_features': [
            'Forward secrecy (if new keypairs generated)',
            'Message integrity verification',
            'Confidentiality through multiple layers',
            'Covert communication via steganography'
        ],
        'key_sizes': {
            'aes_key': '256 bits (32 bytes)',
            'rsa_key': '2048 bits (default)',
            'hmac_key': 'Variable length string',
            'iv': '128 bits (16 bytes)'
        }
    }
