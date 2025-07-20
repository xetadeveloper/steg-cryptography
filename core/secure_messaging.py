"""
Secure Messaging Pipeline with Cloudinary Integration

This module handles the complete secure messaging workflow:
1. Encrypt message with random AES key
2. Encrypt AES key with recipient's RSA public key
3. Hide encrypted data in image using steganography
4. Upload to Cloudinary
5. Store message metadata in database
"""

import os
import sys
import secrets
import base64
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aes_module import encrypt_aes, decrypt_aes
from core.rsa_module import encrypt_rsa, decrypt_rsa
from core.hmac_module import generate_hmac, verify_hmac
from core.stego_module import encode_message_in_image, decode_message_from_image
from core.cloudinary_manager import cloudinary_manager

class SecureMessagingPipeline:
    """Handles secure messaging with steganography and cloud storage."""
    
    def __init__(self):
        self.hmac_key = "cryptostego_app_default_key"  # Use consistent HMAC key
    
    def send_message(self, sender_user, recipient_user, message_text, cover_image_data):
        """
        Send an encrypted message using steganography.
        
        Args:
            sender_user: Sender User object
            recipient_user: Recipient User object  
            message_text (str): Plain text message
            cover_image_data (bytes): Cover image data
            
        Returns:
            dict: Result with success status and message details
        """
        try:
            # Step 1: Generate random AES key for this message
            message_bytes = message_text.encode('utf-8')
            aes_result = encrypt_aes(message_bytes)
            aes_key = aes_result['aes_key']
            encrypted_message = aes_result['encrypted_data']
            iv = aes_result['iv']
            
            # Step 2: Encrypt AES key with recipient's RSA public key
            encrypted_aes_key = encrypt_rsa(aes_key, recipient_user.public_key_pem)
            
            # Step 3: Create payload for steganography
            payload = {
                'encrypted_message': base64.b64encode(encrypted_message).decode(),
                'iv': base64.b64encode(iv).decode(),
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode(),
                'sender_id': sender_user.id,
                'recipient_id': recipient_user.id,
                'timestamp': datetime.now().isoformat()
            }
            payload_json = str(payload).replace("'", '"')  # Convert to JSON-like string
            
            # Step 4: Generate HMAC for integrity
            hmac_signature = generate_hmac(payload_json, self.hmac_key)
            
            # Step 5: Hide encrypted data in image using steganography
            stego_image_data = encode_message_in_image(payload_json, cover_image_data)
            
            # Step 6: Upload to Cloudinary
            message_id = secrets.token_urlsafe(16)
            cloudinary_result = cloudinary_manager.upload_stego_image(
                stego_image_data,
                sender_user.id,
                recipient_user.id,
                message_id
            )
            
            if not cloudinary_result['success']:
                return {
                    'success': False,
                    'error': f"Failed to upload image: {cloudinary_result['error']}"
                }
            
            # Step 7: Store message metadata in database
            from models import Message
            message = Message.create_message(
                sender_id=sender_user.id,
                recipient_id=recipient_user.id,
                cloudinary_public_id=cloudinary_result['public_id'],
                cloudinary_url=cloudinary_result['url'],
                encrypted_aes_key=base64.b64encode(encrypted_aes_key).decode(),
                hmac_signature=hmac_signature,
                cover_image_name=f"message_{message_id}.png"
            )
            
            return {
                'success': True,
                'message_id': message.id,
                'cloudinary_url': cloudinary_result['url'],
                'public_id': cloudinary_result['public_id']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def decrypt_message(self, message_obj, recipient_user):
        """
        Decrypt a message from Cloudinary steganographic image.
        
        Args:
            message_obj: Message object from database
            recipient_user: User object of the recipient
            
        Returns:
            dict: Result with success status and decrypted message
        """
        try:
            # Step 1: Download image from Cloudinary
            stego_image_data = cloudinary_manager.download_stego_image(
                message_obj.cloudinary_public_id
            )
            
            if not stego_image_data:
                return {
                    'success': False,
                    'error': 'Failed to download image from Cloudinary'
                }
            
            # Step 2: Extract hidden data from steganographic image
            hidden_data = decode_message_from_image(stego_image_data)
            
            if not hidden_data:
                return {
                    'success': False,
                    'error': 'Failed to extract hidden data from image'
                }
            
            # Step 3: Parse payload (convert string back to dict)
            import ast
            try:
                payload = ast.literal_eval(hidden_data.replace('"', "'"))
            except:
                return {
                    'success': False,
                    'error': 'Failed to parse hidden payload'
                }
            
            # Step 4: Verify HMAC integrity
            payload_json = str(payload).replace("'", '"')
            if not verify_hmac(payload_json, message_obj.hmac_signature, self.hmac_key):
                return {
                    'success': False,
                    'error': 'Message integrity verification failed'
                }
            
            # Step 5: Decrypt AES key using recipient's RSA private key
            encrypted_aes_key = base64.b64decode(payload['encrypted_aes_key'])
            aes_key = decrypt_rsa(encrypted_aes_key, recipient_user.private_key_pem)
            
            # Step 6: Decrypt message using AES key
            encrypted_message = base64.b64decode(payload['encrypted_message'])
            iv = base64.b64decode(payload['iv'])
            decrypted_message = decrypt_aes(encrypted_message, aes_key, iv)
            
            # Step 7: Mark message as read
            message_obj.mark_as_read()
            
            return {
                'success': True,
                'message': decrypted_message.decode('utf-8'),
                'sender_id': payload['sender_id'],
                'timestamp': payload['timestamp']
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def get_message_preview(self, message_obj):
        """
        Get a preview of the message without decrypting it.
        
        Args:
            message_obj: Message object from database
            
        Returns:
            dict: Message preview information
        """
        from models import User
        sender = User.find_by_id(message_obj.sender_id)
        
        return {
            'id': message_obj.id,
            'sender_name': sender.display_name if sender else 'Unknown',
            'sender_username': sender.username if sender else 'unknown',
            'timestamp': message_obj.timestamp,
            'is_read': message_obj.is_read,
            'cloudinary_url': message_obj.cloudinary_url,
            'cover_image_name': message_obj.cover_image_name
        }

# Global instance
secure_messaging = SecureMessagingPipeline()