import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def aes_encrypt(plaintext: bytes, aes_key: bytes) -> dict:
    """
    Encrypts a message using AES in CBC mode.

    Parameters:
        plaintext (bytes): The message to encrypt.
        aes_key (bytes): A 16-, 24-, or 32-byte AES key.

    Returns:
        dict: Contains the ciphertext, IV, AES key, and original plaintext.
    """

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

    # Return all relevant data
    return {
        "ciphertext": ciphertext,  # Encrypted output
        "iv": iv,  # IV used (needed for decryption)
        "aes_key": aes_key,  # AES key used (symmetric key)
        "plaintext": plaintext,  # Original plaintext (for testing or chaining)
    }


def aes_decrypt(
    ciphertext: bytes, iv: bytes, aes_key: bytes, hmac_tag=None, hmac_key=None
) -> dict:
    """
    Decrypts a message encrypted with AES in CBC mode.

    Parameters:
        ciphertext (bytes): The encrypted data.
        iv (bytes): The IV used during encryption.
        aes_key (bytes): The AES key used for encryption.
        hmac_tag (optional): Included for interface consistency.
        hmac_key (optional): Included for interface consistency.

    Returns:
        dict: Contains the decrypted plaintext and all parameters.
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

    # Unpad the plaintext to get the original message
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    # Return all relevant data
    return {
        "plaintext": plaintext,  # Decrypted original message
        "ciphertext": ciphertext,  # Same ciphertext input
        "iv": iv,  # IV used
        "aes_key": aes_key,  # AES key used
        "hmac_tag": hmac_tag,  # Optional HMAC values for chaining
        "hmac_key": hmac_key,
    }
