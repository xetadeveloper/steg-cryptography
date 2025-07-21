"""
Steganography Module for Image-based Message Hiding

This module provides functionality to hide and extract text messages in images
using LSB (Least Significant Bit) steganography techniques.
"""

from PIL import Image
import io
import base64

def text_to_binary(text):
    """
    Convert text to binary representation.

    Args:
        text (str): Text to convert

    Returns:
        str: Binary representation of text
    """
    binary = ''.join(format(ord(char), '08b') for char in text)
    return binary

def binary_to_text(binary):
    """
    Convert binary representation back to text.

    Args:
        binary (str): Binary string

    Returns:
        str: Decoded text
    """
    text = ''
    for i in range(0, len(binary), 8):
        byte = binary[i:i+8]
        if len(byte) == 8:
            text += chr(int(byte, 2))
    return text

def encode_message_in_image(image_data, message, delimiter="###END###"):
    """
    Hide a text message in an image using LSB steganography.

    Args:
        image_data (bytes): Original image data
        message (str): Message to hide
        delimiter (str): End delimiter for the message

    Returns:
        bytes: Modified image data with hidden message

    Raises:
        ValueError: If image is too small to hold the message
        Exception: If image processing fails
    """
    try:
        # Load image from bytes
        image = Image.open(io.BytesIO(image_data))

        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Prepare message with delimiter
        message_with_delimiter = message + delimiter
        binary_message = text_to_binary(message_with_delimiter)

        # Get image dimensions
        width, height = image.size
        max_capacity = width * height * 3  # 3 channels (RGB)

        if len(binary_message) > max_capacity:
            raise ValueError(f"Message too long for image. Max capacity: {max_capacity} bits, message: {len(binary_message)} bits")

        # Get pixel data
        pixels = list(image.getdata())
        binary_index = 0

        # Modify pixels to embed message
        for i in range(len(pixels)):
            if binary_index < len(binary_message):
                pixel = list(pixels[i])

                # Modify each color channel (R, G, B)
                for j in range(3):
                    if binary_index < len(binary_message):
                        # Modify LSB of color channel
                        pixel[j] = (pixel[j] & 0xFE) | int(binary_message[binary_index])
                        binary_index += 1

                pixels[i] = tuple(pixel)
            else:
                break

        # Create new image with modified pixels
        stego_image = Image.new('RGB', (width, height))
        stego_image.putdata(pixels)

        # Convert back to bytes
        output_buffer = io.BytesIO()
        stego_image.save(output_buffer, format='PNG')
        return output_buffer.getvalue()

    except Exception as e:
        raise Exception(f"Failed to encode message in image: {str(e)}")

def decode_message_from_image(stego_image_data, delimiter="###END###"):
    """
    Extract a hidden message from a steganographic image.

    Args:
        stego_image_data (bytes): Image data with hidden message
        delimiter (str): End delimiter for the message

    Returns:
        str: Extracted message

    Raises:
        ValueError: If no message found or image processing fails
        Exception: If extraction fails
    """
    try:
        # Load image from bytes
        image = Image.open(io.BytesIO(stego_image_data))

        # Convert to RGB if necessary
        if image.mode != 'RGB':
            image = image.convert('RGB')

        # Get pixel data
        pixels = list(image.getdata())
        binary_message = ""

        # Extract LSBs from pixels
        for pixel in pixels:
            for color_value in pixel:
                # Extract LSB
                binary_message += str(color_value & 1)

        # Convert binary to text and look for delimiter
        text_message = ""
        for i in range(0, len(binary_message), 8):
            byte = binary_message[i:i+8]
            if len(byte) == 8:
                char = chr(int(byte, 2))
                text_message += char

                # Check if we've reached the delimiter
                if text_message.endswith(delimiter):
                    # Remove delimiter and return message
                    return text_message[:-len(delimiter)]

        # If we get here, delimiter was not found
        raise ValueError("No message delimiter found in image")

    except Exception as e:
        raise Exception(f"Failed to decode message from image: {str(e)}")

def get_image_capacity(image_data):
    """
    Calculate the maximum message capacity of an image in characters.

    Args:
        image_data (bytes): Image data

    Returns:
        dict: Contains capacity information
    """
    try:
        image = Image.open(io.BytesIO(image_data))
        width, height = image.size

        # Each pixel has 3 color channels, each can hide 1 bit
        total_bits = width * height * 3
        max_chars = total_bits // 8  # 8 bits per character

        return {
            'width': width,
            'height': height,
            'total_pixels': width * height,
            'total_bits_capacity': total_bits,
            'max_characters': max_chars,
            'max_characters_with_delimiter': max_chars - len("###END###")
        }

    except Exception as e:
        raise Exception(f"Failed to analyze image capacity: {str(e)}")

def create_test_image(width=800, height=600, color=(100, 150, 200)):
    """
    Create a test image for steganography demonstrations.

    Args:
        width (int): Image width
        height (int): Image height
        color (tuple): RGB color tuple

    Returns:
        bytes: PNG image data
    """
    # Create a solid color image
    image = Image.new('RGB', (width, height), color)

    # Convert to bytes
    output_buffer = io.BytesIO()
    image.save(output_buffer, format='PNG')
    return output_buffer.getvalue()

def validate_image_for_steganography(image_data):
    """
    Validate if an image is suitable for steganography.

    Args:
        image_data (bytes): Image data to validate

    Returns:
        dict: Validation results and recommendations
    """
    try:
        image = Image.open(io.BytesIO(image_data))
        width, height = image.size
        mode = image.mode

        capacity_info = get_image_capacity(image_data)

        # Determine suitability
        is_suitable = True
        issues = []
        recommendations = []

        if width < 100 or height < 100:
            issues.append("Image is very small, limited message capacity")

        if capacity_info['max_characters'] < 100:
            issues.append("Very low message capacity")
            is_suitable = False

        if mode not in ['RGB', 'RGBA']:
            issues.append(f"Image mode '{mode}' will be converted to RGB")
            recommendations.append("Use RGB images for best results")

        return {
            'is_suitable': is_suitable,
            'issues': issues,
            'recommendations': recommendations,
            'capacity_info': capacity_info,
            'image_info': {
                'width': width,
                'height': height,
                'mode': mode
            }
        }

    except Exception as e:
        return {
            'is_suitable': False,
            'issues': [f"Failed to process image: {str(e)}"],
            'recommendations': ["Ensure the file is a valid image format"],
            'capacity_info': None,
            'image_info': None
        }

import cv2
import os
import datetime
from core.steganography import Stego

def embed_in_image(input_image: str, ciphertext: bytes, iv: bytes, rsa_encrypted_key: bytes, hmac_tag: bytes) -> dict:
    """
    Embed encryption data into an image using steganography. Output filename auto-generated based on timestamp to seconds.

    Args:
        input_image (str): Path to the source image.
        ciphertext (bytes): AES-encrypted message.
        iv (bytes): Initialization vector.
        rsa_encrypted_key (bytes): RSA-encrypted AES key.
        hmac_tag (bytes): HMAC tag.

    Returns:
        dict: Includes output filename (stego_image) and encryption components.
    """
    image = cv2.imread(input_image)
    if image is None:
        raise FileNotFoundError(f"Cannot read input image: {input_image}")

    steg = Stego(image)

    combined_data = ciphertext + iv + rsa_encrypted_key + hmac_tag
    combined_data_str = combined_data.decode('latin1')

    encoded_image = steg.encode_text(combined_data_str)

    # Generate output filename with timestamp to seconds
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    input_dir, input_filename = os.path.split(input_image)
    base_name, _ = os.path.splitext(input_filename)
    output_filename = f"{base_name}_stego_{timestamp}.png"
    output_path = os.path.join(input_dir, output_filename)

    cv2.imwrite(output_path, encoded_image)

    return {
        "stego_image": output_filename,
        "output_path": output_path,
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": rsa_encrypted_key,
        "hmac_tag": hmac_tag
    }


def extract_from_image(stego_image_path: str) -> dict:
    """
    Extract ciphertext, iv, rsa_encrypted_key, and hmac_tag from the stego image.

    Args:
        stego_image_path (str): Path to the stego image containing hidden data.

    Returns:
        dict: Extracted encryption components.
    """
    image = cv2.imread(stego_image_path)
    if image is None:
        raise FileNotFoundError(f"Cannot read stego image: {stego_image_path}")

    steg = Stego(image)

    hidden_data_str = steg.decode_text()
    hidden_data_bytes = hidden_data_str.encode('latin1')

    iv_length = 16
    rsa_key_length = 256
    hmac_length = 32

    if len(hidden_data_bytes) < (iv_length + rsa_key_length + hmac_length):
        raise ValueError("Extracted data is incomplete or corrupted.")

    ciphertext = hidden_data_bytes[:- (iv_length + rsa_key_length + hmac_length)]
    iv = hidden_data_bytes[- (iv_length + rsa_key_length + hmac_length):- (rsa_key_length + hmac_length)]
    rsa_encrypted_key = hidden_data_bytes[- (rsa_key_length + hmac_length):- hmac_length]
    hmac_tag = hidden_data_bytes[- hmac_length:]

    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": rsa_encrypted_key,
        "hmac_tag": hmac_tag
    }