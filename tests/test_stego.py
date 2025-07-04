import sys
import os

# Add the project root to sys.path so 'core' module is found
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.stego_module import embed_in_image, extract_from_image


# Add your test function below here and use "python tests/test_stego.py" to run the test


def test_stego_basic():
    input_image = "static/test_input.png"
    secret_ciphertext = b"Hidden encrypted message."
    iv = b"1234567890abcdef"  # 16 bytes IV
    rsa_encrypted_key = b"A" * 256  # Simulated 256 bytes RSA encrypted key
    hmac_tag = b"B" * 32  # Simulated 32 bytes HMAC

    # Embed data into image
    result = embed_in_image(input_image, secret_ciphertext, iv, rsa_encrypted_key, hmac_tag)

    print(f"Generated stego image: {result['stego_image']}")

    # Extract data from generated image
    extracted = extract_from_image(result["output_path"])
    print("\n[Extracted Data]:")
    for k, v in extracted.items():
        print(f"{k}: {v}")

    # Assertions to verify integrity
    assert extracted["ciphertext"] == secret_ciphertext, "Ciphertext mismatch!"
    assert extracted["iv"] == iv, "IV mismatch!"
    assert extracted["rsa_encrypted_key"] == rsa_encrypted_key, "RSA encrypted key mismatch!"
    assert extracted["hmac_tag"] == hmac_tag, "HMAC tag mismatch!"

    print("[Test Passed] Steganography embedding and extraction verified.")

if __name__ == "__main__":
    test_stego_basic()
