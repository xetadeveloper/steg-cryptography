"""
Cloudinary Integration for Cryptographic Steganography App

This module handles uploading and downloading steganographic images to/from Cloudinary.
"""

import cloudinary
import cloudinary.uploader
import cloudinary.api
import os
import io
import base64
from PIL import Image

class CloudinaryManager:
    """Manages Cloudinary operations for steganographic images."""
    
    def __init__(self):
        """Initialize Cloudinary configuration."""
        # Use environment variables for security
        cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME")
        api_key = os.environ.get("CLOUDINARY_API_KEY")
        api_secret = os.environ.get("CLOUDINARY_API_SECRET")
        
        if not cloud_name or not api_key or not api_secret:
            raise ValueError("Missing CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, or CLOUDINARY_API_SECRET environment variables")
        
        cloudinary.config(
            cloud_name=cloud_name,
            api_key=api_key,
            api_secret=api_secret,
            secure=True
        )
        
        # Test the configuration
        self._test_connection()
    
    def _test_connection(self):
        """Test Cloudinary connection by checking API credentials."""
        try:
            # Test with a simple upload to validate credentials
            test_result = cloudinary.uploader.upload(
                "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                public_id="test_connection",
                folder="test",
                overwrite=True
            )
            # Clean up test image
            cloudinary.uploader.destroy("test/test_connection")
            print("✓ Cloudinary connection successful")
        except Exception as e:
            print(f"✗ Cloudinary connection failed: {e}")
            # Don't raise exception here, let it fail during actual upload
    
    def upload_stego_image(self, image_data, sender_id, recipient_id, message_id):
        """
        Upload steganographic image to Cloudinary.
        
        Args:
            image_data (bytes): The steganographic image data
            sender_id (str): ID of the message sender
            recipient_id (str): ID of the message recipient
            message_id (str): Unique message identifier
            
        Returns:
            dict: Upload result with public_id, url, etc.
        """
        try:
            # Create unique filename
            filename = f"msg_{message_id}_{sender_id}_to_{recipient_id}"
            
            # Upload to Cloudinary in cryptostego folder
            result = cloudinary.uploader.upload(
                image_data,
                folder="cryptostego",
                public_id=filename,
                resource_type="image",
                format="png",  # Ensure PNG format for steganography
                tags=["cryptostego", f"sender_{sender_id}", f"recipient_{recipient_id}"]
            )
            
            return {
                'success': True,
                'public_id': result['public_id'],
                'url': result['secure_url'],
                'cloudinary_id': result['public_id'],
                'file_size': result.get('bytes', 0),
                'format': result.get('format', 'png')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def download_stego_image(self, public_id):
        """
        Download steganographic image from Cloudinary.
        
        Args:
            public_id (str): Cloudinary public ID of the image
            
        Returns:
            bytes: Image data or None if failed
        """
        try:
            # Get the image URL
            url = cloudinary.utils.cloudinary_url(public_id, format="png")[0]
            
            # Download the image
            import requests
            response = requests.get(url)
            response.raise_for_status()
            
            return response.content
            
        except Exception as e:
            print(f"Error downloading image from Cloudinary: {e}")
            return None
    
    def delete_stego_image(self, public_id):
        """
        Delete steganographic image from Cloudinary.
        
        Args:
            public_id (str): Cloudinary public ID of the image
            
        Returns:
            bool: Success status
        """
        try:
            result = cloudinary.uploader.destroy(public_id)
            return result.get('result') == 'ok'
        except Exception as e:
            print(f"Error deleting image from Cloudinary: {e}")
            return False
    
    def get_user_images(self, user_id, limit=50):
        """
        Get list of steganographic images for a user.
        
        Args:
            user_id (str): User ID
            limit (int): Maximum number of images to return
            
        Returns:
            list: List of image metadata
        """
        try:
            # Search for images by tag
            result = cloudinary.api.resources_by_tag(
                f"sender_{user_id}",
                resource_type="image",
                max_results=limit
            )
            
            # Also get images where user is recipient
            recipient_result = cloudinary.api.resources_by_tag(
                f"recipient_{user_id}",
                resource_type="image", 
                max_results=limit
            )
            
            # Combine and deduplicate
            all_images = result.get('resources', []) + recipient_result.get('resources', [])
            unique_images = {img['public_id']: img for img in all_images}.values()
            
            return list(unique_images)
            
        except Exception as e:
            print(f"Error fetching user images from Cloudinary: {e}")
            return []
    
    def get_image_url(self, public_id, transformation=None):
        """
        Get Cloudinary URL for an image.
        
        Args:
            public_id (str): Cloudinary public ID
            transformation (dict): Optional transformations
            
        Returns:
            str: Image URL
        """
        try:
            url, _ = cloudinary.utils.cloudinary_url(
                public_id,
                format="png",
                transformation=transformation or {}
            )
            return url
        except Exception as e:
            print(f"Error generating image URL: {e}")
            return None
    
    def upload_image(self, image_data, filename=None, folder="default_images"):
        """
        Upload a default user image to Cloudinary.
        
        Args:
            image_data (bytes): The image data to upload
            filename (str): Optional filename for the image
            folder (str): Cloudinary folder to store the image
            
        Returns:
            dict: Upload result with success status, public_id, url, etc.
        """
        try:
            # Create unique filename if not provided
            if not filename:
                import time
                filename = f"image_{int(time.time())}"
            
            # Upload to Cloudinary
            result = cloudinary.uploader.upload(
                image_data,
                folder=folder,
                public_id=filename,
                resource_type="image",
                format="png",
                overwrite=True,
                tags=["default_image"]
            )
            
            return {
                'success': True,
                'public_id': result['public_id'],
                'url': result['secure_url'],
                'cloudinary_id': result['public_id'],
                'file_size': result.get('bytes', 0),
                'format': result.get('format', 'png')
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def delete_image(self, public_id):
        """
        Delete an image from Cloudinary.
        
        Args:
            public_id (str): Cloudinary public ID of the image to delete
            
        Returns:
            bool: True if deletion was successful, False otherwise
        """
        try:
            result = cloudinary.uploader.destroy(public_id)
            return result.get('result') == 'ok'
        except Exception as e:
            print(f"Error deleting image from Cloudinary: {e}")
            return False

# Global instance
cloudinary_manager = CloudinaryManager()