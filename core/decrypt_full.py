"""
Full Decryption Pipeline

This module reverses the encryption pipeline to decrypt messages that were
encrypted using the full encryption pipeline (AES + RSA + HMAC + Steganography).
"""

import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes_module import aes_decrypt
from core.rsa_module import rsa_decrypt
from core.hmac_module import verify_hmac
from core.stego_module import decode_message_from_image

def decrypt_full_pipeline(stego_image_data, encrypted_aes_key, hmac_signature, 
                         rsa_private_key_pem, hmac_key="default_hmac_key"):
    """
    Complete decryption pipeline that:
    1. Extracts hidden data from steganographic image
    2. Decrypts AES key using RSA private key
    3. Verifies HMAC signature for integrity
    4. Decrypts the original message using AES
    
    Args:
        stego_image_data (bytes): Image containing hidden encrypted data
        encrypted_aes_key (bytes): RSA-encrypted AES key
        hmac_signature (bytes): HMAC signature for integrity verification
        rsa_private_key_pem (str): RSA private key for AES key decryption
        hmac_key (str): Key for HMAC verification
    
    Returns:
        dict: Contains decrypted message and verification status
        
    Raises:
        Exception: If any step in the pipeline fails
    """
    try:
        # Step 1: Extract data from steganographic image
        print("Step 1: Extracting data from steganographic image...")
        payload_str = decode_message_from_image(stego_image_data)
        
        # Decode base64 payload
        import base64
        payload = base64.b64decode(payload_str.encode('utf-8'))
        
        # Step 2: Parse the payload structure
        print("Step 2: Parsing extracted payload...")
        # Format: [encrypted_aes_key_length][encrypted_aes_key][hmac_signature][aes_data]
        
        # Read encrypted AES key length (first 4 bytes)
        if len(payload) < 4:
            raise ValueError("Payload too short - corrupted data")
        
        encrypted_aes_key_length = int.from_bytes(payload[:4], byteorder='big')
        
        # Validate length
        if encrypted_aes_key_length <= 0 or encrypted_aes_key_length > len(payload):
            raise ValueError("Invalid encrypted AES key length")
        
        # Extract encrypted AES key
        start_idx = 4
        end_idx = start_idx + encrypted_aes_key_length
        extracted_encrypted_aes_key = payload[start_idx:end_idx]
        
        # Extract HMAC signature (32 bytes for SHA-256)
        hmac_size = 32
        start_idx = end_idx
        end_idx = start_idx + hmac_size
        
        if end_idx > len(payload):
            raise ValueError("Payload too short for HMAC signature")
        
        extracted_hmac_signature = payload[start_idx:end_idx]
        
        # Extract AES data (IV + encrypted message)
        aes_data = payload[end_idx:]
        
        if len(aes_data) < 16:  # At least IV length
            raise ValueError("Insufficient AES data")
        
        # Step 3: Decrypt AES key using RSA private key
        print("Step 3: Decrypting AES key with RSA...")
        
        # Use provided encrypted key or extracted one (prefer provided for flexibility)
        key_to_decrypt = encrypted_aes_key if encrypted_aes_key else extracted_encrypted_aes_key
        aes_key = rsa_decrypt(key_to_decrypt, rsa_private_key_pem)
        
        # Step 4: Verify HMAC signature
        print("Step 4: Verifying HMAC signature...")
        
        # Use provided signature or extracted one
        sig_to_verify = hmac_signature if hmac_signature else extracted_hmac_signature
        hmac_verified = verify_hmac(aes_data, sig_to_verify, hmac_key)
        
        if not hmac_verified:
            print("WARNING: HMAC verification failed - data may be corrupted or tampered with")
        
        # Step 5: Decrypt message using AES
        print("Step 5: Decrypting message with AES...")
        
        # Extract IV and encrypted message from AES data
        iv = aes_data[:16]  # First 16 bytes are IV
        encrypted_message = aes_data[16:]  # Rest is encrypted message
        
        # Decrypt the message
        decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)
        
        # Prepare result
        result = {
            'decrypted_message': decrypted_message,
            'hmac_verified': hmac_verified,
            'aes_key': aes_key,
            'iv': iv,
            'encrypted_message': encrypted_message,
            'extracted_data': {
                'encrypted_aes_key': extracted_encrypted_aes_key,
                'hmac_signature': extracted_hmac_signature,
                'payload_length': len(payload)
            }
        }
        
        print("Decryption pipeline completed successfully!")
        return result
        
    except Exception as e:
        raise Exception(f"Decryption pipeline failed: {str(e)}")

def decrypt_from_stego_only(stego_image_data, rsa_private_key_pem, hmac_key="default_hmac_key"):
    """
    Decrypt when all necessary data is embedded in the steganographic image.
    
    Args:
        stego_image_data (bytes): Image containing all encrypted data
        rsa_private_key_pem (str): RSA private key for AES key decryption
        hmac_key (str): Key for HMAC verification
    
    Returns:
        dict: Contains decrypted message and verification status
    """
    try:
        # Extract and parse payload from image
        payload_str = decode_message_from_image(stego_image_data)
        
        import base64
        payload = base64.b64decode(payload_str.encode('utf-8'))
        
        # Parse payload structure
        encrypted_aes_key_length = int.from_bytes(payload[:4], byteorder='big')
        
        start_idx = 4
        encrypted_aes_key = payload[start_idx:start_idx + encrypted_aes_key_length]
        
        start_idx += encrypted_aes_key_length
        hmac_signature = payload[start_idx:start_idx + 32]
        
        aes_data = payload[start_idx + 32:]
        
        # Decrypt AES key
        aes_key = rsa_decrypt(encrypted_aes_key, rsa_private_key_pem)
        
        # Verify HMAC
        hmac_verified = verify_hmac(aes_data, hmac_signature, hmac_key)
        
        # Decrypt message
        iv = aes_data[:16]
        encrypted_message = aes_data[16:]
        decrypted_message = aes_decrypt(encrypted_message, aes_key, iv)
        
        return {
            'decrypted_message': decrypted_message,
            'hmac_verified': hmac_verified,
            'extraction_method': 'steganography_only'
        }
        
    except Exception as e:
        raise Exception(f"Steganography-only decryption failed: {str(e)}")

def verify_pipeline_integrity(stego_image_data, rsa_private_key_pem, 
                            hmac_key="default_hmac_key", expected_message=None):
    """
    Verify the integrity of the entire encryption/decryption pipeline.
    
    Args:
        stego_image_data (bytes): Image containing encrypted data
        rsa_private_key_pem (str): RSA private key
        hmac_key (str): HMAC key
        expected_message (str, optional): Expected message for validation
    
    Returns:
        dict: Comprehensive verification results
    """
    try:
        # Attempt full decryption
        result = decrypt_from_stego_only(stego_image_data, rsa_private_key_pem, hmac_key)
        
        verification_result = {
            'decryption_successful': True,
            'hmac_verified': result['hmac_verified'],
            'decrypted_message': result['decrypted_message'],
            'message_length': len(result['decrypted_message']),
            'pipeline_integrity': 'PASS' if result['hmac_verified'] else 'FAIL (HMAC)',
        }
        
        # If expected message provided, compare
        if expected_message:
            message_match = result['decrypted_message'] == expected_message
            verification_result['expected_message_match'] = message_match
            verification_result['pipeline_integrity'] = (
                'PASS' if (result['hmac_verified'] and message_match) else 
                'FAIL (HMAC)' if not result['hmac_verified'] else 
                'FAIL (MESSAGE_MISMATCH)'
            )
        
        return verification_result
        
    except Exception as e:
        return {
            'decryption_successful': False,
            'error': str(e),
            'pipeline_integrity': 'FAIL (DECRYPTION_ERROR)'
        }

def get_decryption_info():
    """
    Get information about the decryption pipeline.
    
    Returns:
        dict: Pipeline information and requirements
    """
    return {
        'pipeline_steps': [
            '1. Extract steganographic data from image',
            '2. Parse encrypted payload structure',
            '3. Decrypt AES key using RSA private key',
            '4. Verify HMAC signature for integrity',
            '5. Decrypt message using AES key'
        ],
        'required_inputs': [
            'Steganographic image (or separate components)',
            'RSA private key (PEM format)',
            'HMAC key (string)',
            'Encrypted AES key (if not in image)',
            'HMAC signature (if not in image)'
        ],
        'verification_levels': [
            'Steganographic extraction success',
            'RSA decryption success',
            'HMAC signature verification',
            'AES decryption success',
            'Message integrity confirmation'
        ],
        'error_handling': [
            'Corrupted steganographic data',
            'Invalid RSA keys',
            'HMAC verification failures',
            'Malformed payload structure'
        ]
    }
