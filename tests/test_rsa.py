import sys
import os


sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core import rsa_module


def test_rsa_key_generation():
    private_key, public_key = rsa_module.generate_rsa_keypair()
    rsa_module.save_private_key(private_key, "test_private.pem")
    rsa_module.save_public_key(public_key, "test_public.pem")
    assert os.path.exists("test_private.pem") and os.path.exists("test_public.pem")
    print("✅ RSA key generation and saving test passed.")

def test_rsa_aes_key_encryption_decryption():
    aes_key = os.urandom(32)

    public_key = rsa_module.load_public_key("test_public.pem")
    encrypted_key = rsa_module.encrypt_aes_key(aes_key, public_key)

    private_key = rsa_module.load_private_key("test_private.pem")
    decrypted_key = rsa_module.decrypt_aes_key(encrypted_key, private_key)

    assert aes_key == decrypted_key
    print("✅ RSA-based AES key encryption/decryption test passed.")

if __name__ == "__main__":
    print("🔍 Running RSA tests...\n")
    test_rsa_key_generation()
    test_rsa_aes_key_encryption_decryption()
