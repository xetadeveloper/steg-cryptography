# aes_utils.py

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

# Encrypt the message with AES-GCM
def aes_encrypt(message: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, message, None)
    return nonce, ciphertext

# Decrypt the message
def aes_decrypt(nonce: bytes, ciphertext: bytes, aes_key: bytes):
    aesgcm = AESGCM(aes_key)
    decrypted_message = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted_message
