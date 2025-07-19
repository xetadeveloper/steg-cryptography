"""
RSA Keypair Generation and Encryption/Decryption Module

This module provides RSA key generation, encryption, and decryption functionality
using the cryptography library with OAEP padding.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

def generate_rsa_keypair(key_size=2048):
    """
    Generate an RSA key pair.
    
    Args:
        key_size (int): Size of the RSA key in bits (default: 2048)
    
    Returns:
        tuple: (private_key_pem, public_key_pem) as strings
    """
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Serialize private key to PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Serialize public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def load_private_key_from_pem(private_key_pem):
    """
    Load an RSA private key from PEM string.
    
    Args:
        private_key_pem (str): Private key in PEM format
    
    Returns:
        RSAPrivateKey: Cryptography library private key object
    """
    return serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )

def load_public_key_from_pem(public_key_pem):
    """
    Load an RSA public key from PEM string.
    
    Args:
        public_key_pem (str): Public key in PEM format
    
    Returns:
        RSAPublicKey: Cryptography library public key object
    """
    return serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )

def rsa_encrypt(data, public_key_pem):
    """
    Encrypt data using RSA public key with OAEP padding.
    
    Args:
        data (bytes or str): Data to encrypt
        public_key_pem (str): Public key in PEM format
    
    Returns:
        bytes: Encrypted data
        
    Raises:
        ValueError: If data is too large for RSA key size
    """
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    public_key = load_public_key_from_pem(public_key_pem)
    
    # Encrypt with OAEP padding
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return ciphertext

def rsa_decrypt(ciphertext, private_key_pem):
    """
    Decrypt data using RSA private key with OAEP padding.
    
    Args:
        ciphertext (bytes): Encrypted data
        private_key_pem (str): Private key in PEM format
    
    Returns:
        bytes: Decrypted data
        
    Raises:
        ValueError: If decryption fails
    """
    private_key = load_private_key_from_pem(private_key_pem)
    
    # Decrypt with OAEP padding
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return plaintext

def get_public_key_from_private(private_key_pem):
    """
    Extract the public key from a private key PEM.
    
    Args:
        private_key_pem (str): Private key in PEM format
    
    Returns:
        str: Public key in PEM format
    """
    private_key = load_private_key_from_pem(private_key_pem)
    public_key = private_key.public_key()
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return public_pem

def get_key_size(key_pem):
    """
    Get the size of an RSA key in bits.
    
    Args:
        key_pem (str): RSA key in PEM format (public or private)
    
    Returns:
        int: Key size in bits
    """
    try:
        # Try as private key first
        key = load_private_key_from_pem(key_pem)
        return key.key_size
    except:
        # Try as public key
        key = load_public_key_from_pem(key_pem)
        return key.key_size
