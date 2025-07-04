## 🗂 Project Structure & Contribution Guide

This project is designed to support modular development of cryptographic components, testing, and Flask integration. Please follow the structure below when adding your code.

### 📁 Folder Overview

```text
steg-cryptography/
│
├── app/                        # (Optional) Flask web app components
│   ├── __init__.py             # Initializes the Flask app
│   └── routes.py               # HTTP endpoints will go here
│
├── core/                       # Core cryptographic logic (each component in its own file)
│   ├── __init__.py
│   ├── aes_module.py           # AES encryption/decryption logic
│   ├── rsa_module.py           # RSA keypair generation, encryption/decryption
│   ├── hmac_module.py          # HMAC signing and verification
│   ├── stego_module.py         # Steganography encoding and decoding
│   ├── encrypt_full.py         # Full encryption pipeline (AES + RSA + HMAC + Stego)
│   └── decrypt_full.py         # Full decryption pipeline
│
├── tests/                      # Unit tests for each module
│   ├── __init__.py
│   ├── test_aes.py
│   ├── test_rsa.py
│   ├── test_hmac.py
│   ├── test_stego.py
│   ├── test_encrypt.py         # Tests the full encryption pipeline
│   └── test_decrypt.py         # Tests the full decryption pipeline
│
├── static/                     # (Optional) Image/media files for web app and steganography process
├── templates/                  # (Optional) HTML templates for Flask
│
├── cli_demo.py                 # Script to run demo from the command line
├── run.py                      # Entry point to start Flask app (if needed)
├── requirements.txt            # Python dependencies
└── README.md                   # Project documentation (you're reading this!)
```


### 👩‍💻 Where to Put Your Code

| Contributor Role        | Add Code To                   | Description |
|-------------------------|-------------------------------|-------------|
| AES Encryption/Decryption | `core/aes_module.py`         | Implement AES logic and helper functions |
| RSA Keypair & Encryption | `core/rsa_module.py`         | RSA key generation, encryption, decryption |
| HMAC Signing             | `core/hmac_module.py`        | Sign/verify messages with HMAC |
| Steganography            | `core/stego_module.py`       | Embed and extract messages from images |
| CLI Demo Integration     | `cli_demo.py`                | Combine all modules in a linear CLI workflow |
| Testing Your Code        | `tests/test_*.py`            | Create test cases for your module (use assertions) |
| Flask API (Optional)     | `app/routes.py`              | If we go web-based, API endpoints will be created here |

---

### 🧪 Running Tests

You can run any test script directly using:

```bash
# Example, use your own test module
python tests/test_aes.py 
```

Each script handles Python path resolution internally, so there's no need to set PYTHONPATH manually.

**🛠️ Make sure you're running from the project root directory so relative imports work correctly.**
