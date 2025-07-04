import cv2
import os
import datetime


class Stego:
    """
    LSB Steganography handler for encoding and decoding messages in images.
    """

    def __init__(self, image):
        self.image = image.copy()

    def encode_text(self, text):
        """
        Hide text message inside the image using LSB method.
        """
        message = text + chr(0)  # Null terminator to indicate message end
        message_bin = ''.join([format(ord(c), '08b') for c in message])

        if len(message_bin) > self.image.size:
            raise ValueError("Message is too large to hide in the image.")

        flat_image = self.image.flatten()

        for i in range(len(message_bin)):
            flat_image[i] = (int(flat_image[i]) & 0b11111110) | int(message_bin[i])

        return flat_image.reshape(self.image.shape)

    def decode_text(self):
        """
        Extract hidden text message from the image.
        """
        flat_image = self.image.flatten()
        bits = [str(flat_image[i] & 1) for i in range(flat_image.size)]

        chars = []
        for i in range(0, len(bits), 8):
            byte = bits[i:i + 8]
            char = chr(int(''.join(byte), 2))
            if char == chr(0):
                break
            chars.append(char)

        return ''.join(chars)


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
