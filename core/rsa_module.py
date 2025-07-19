# rsa_utils.py

# from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA Key Pair
# def generate_rsa_keypair():
#     private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#     public_key = private_key.public_key()
#     return private_key, public_key

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


# Save private key to a file
def save_private_key(private_key, filename):
    with open(filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()))


# Save public key to a file
def save_public_key(public_key, filename):
    with open(filename, "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))


# Load public key from a file
def load_public_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_public_key(f.read())


# Load private key from a file
def load_private_key(filename):
    with open(filename, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


# Encrypt AES key using the recipient's public RSA key
def encrypt_aes_key(aes_key, public_key):
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return encrypted_aes_key


# Decrypt AES key using the private RSA key
def decrypt_aes_key(encrypted_key, private_key):
    decrypted_aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
    return decrypted_aes_key


def rsa_encrypt(data, public_key_pem):
    """
    Encrypt data using RSA public key.
    
    Args:
        data (bytes): Data to encrypt
        public_key_pem (str): PEM-encoded public key
    
    Returns:
        bytes: Encrypted data
    """
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    return encrypt_aes_key(data, public_key)


def rsa_decrypt(encrypted_data, private_key_pem):
    """
    Decrypt data using RSA private key.
    
    Args:
        encrypted_data (bytes): Data to decrypt
        private_key_pem (str): PEM-encoded private key
    
    Returns:
        bytes: Decrypted data
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    return decrypt_aes_key(encrypted_data, private_key)


def get_public_key_from_private(private_key_pem):
    """
    Extract public key from private key.
    
    Args:
        private_key_pem (str): PEM-encoded private key
    
    Returns:
        str: PEM-encoded public key
    """
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    public_key = private_key.public_key()
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return public_key_pem.decode('utf-8')


def generate_rsa_keypair_pem():
    """
    Generate RSA keypair and return as PEM strings.
    
    Returns:
        tuple: (private_key_pem, public_key_pem)
    """
    private_key, public_key = generate_rsa_keypair()
    
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_key_pem, public_key_pem
