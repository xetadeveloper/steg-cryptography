# from core import rsa_module, aes_module

# import os

# def main():
#     print("🔐 Secure Message Concealment Test: RSA + AES Key")

#     # Generate RSA keypair
#     print("📁 Generating RSA Key Pair...")
#     private_key, public_key = rsa_module.generate_rsa_keypair()
#     rsa_module.save_private_key(private_key, "private.pem")
#     rsa_module.save_public_key(public_key, "public.pem")
#     print("✅ RSA keys saved as private.pem and public.pem\n")

#     # Generate AES key
#     aes_key = os.urandom(32)
#     print(f"🔑 Generated AES Key: {aes_key.hex()}\n")

#     # Encrypt AES key with public key
#     print("🔒 Encrypting AES key with RSA public key...")
#     loaded_public = rsa_module.load_public_key("public.pem")
#     encrypted_aes_key = rsa_module.encrypt_aes_key(aes_key, loaded_public)
#     print(f"✅ Encrypted AES Key (hex): {encrypted_aes_key.hex()}\n")

#     # Decrypt AES key with private key
#     print("🔓 Decrypting AES key with RSA private key...")
#     loaded_private = rsa_module.load_private_key("private.pem")
#     decrypted_aes_key = rsa_module.decrypt_aes_key(encrypted_aes_key, loaded_private)
#     print(f"✅ Decrypted AES Key: {decrypted_aes_key.hex()}\n")

#     if aes_key == decrypted_aes_key:
#         print("✅ SUCCESS: AES key encryption/decryption via RSA is correct.")
#     else:
#         print("❌ ERROR: AES key mismatch!")

#     # ✅ AES Message Encryption/Decryption
#     print("\n🧪 Testing AES encryption/decryption with a real message")
#     message = b"This is a top secret message from Yashika."

#     print("🔐 Encrypting message with AES...")
#     nonce, ciphertext = aes_module.aes_encrypt(message, aes_key)
#     print(f"Nonce: {nonce.hex()}")
#     print(f"Ciphertext: {ciphertext.hex()}")

#     print("🔓 Decrypting message...")
#     decrypted_message = aes_module.aes_decrypt(nonce, ciphertext, aes_key)
#     print(f"Decrypted: {decrypted_message.decode()}")

#     if decrypted_message == message:
#         print("✅ SUCCESS: AES encryption/decryption works correctly.")
#     else:
#         print("❌ ERROR: AES message mismatch!")

# if __name__ == "__main__":
#     main()
