# Secure Steganographic Messaging - Module Interface Guide

This document defines the function interfaces and data flow for the encryption and decryption modules of our secure steganographic messaging system. Each function is designed to be independent and passes along all relevant variables to ensure modularity and testability.


## 🔐 Encryption Flow

### 1. AES Encryption

Encrypts the plaintext using AES-CBC mode.

```python
def aes_encrypt(plaintext: bytes, aes_key: bytes) -> dict:
    """
    Encrypt plaintext using AES-CBC.
    Returns a dictionary with ciphertext, IV, AES key, and original plaintext.
    """
    return {
        "ciphertext": <bytes>,    # AES encrypted message
        "iv": <bytes>,            # Initialization vector
        "aes_key": aes_key,       # AES symmetric key
        "plaintext": plaintext    # Original message (for testing/demo)
    }
```

### 2. RSA Encryption of AES Key

Encrypts the AES key using the recipient's RSA public key.

```python
def rsa_encrypt_key(aes_key: bytes, rsa_public_key: RSAPublicKey, iv: bytes, ciphertext: bytes, plaintext: bytes) -> dict:
    """
    Encrypt AES key with RSA public key.
    Returns the RSA encrypted AES key along with other parameters unchanged.
    """
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": <bytes>,  # AES key encrypted with RSA
        "aes_key": aes_key,
        "plaintext": plaintext
    }


```

### 3. HMAC Generation

Generates an HMAC tag for integrity verification over the ciphertext, IV, and encrypted AES key.

```python
def generate_hmac(ciphertext: bytes, iv: bytes, rsa_encrypted_key: bytes, hmac_key: bytes, aes_key: bytes, plaintext: bytes) -> dict:
    """
    Create HMAC tag using HMAC key over iv + ciphertext + rsa_encrypted_key.
    Returns all parameters plus the HMAC tag.
    """
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": rsa_encrypted_key,
        "hmac_tag": <bytes>,       # HMAC tag for integrity
        "hmac_key": hmac_key,
        "aes_key": aes_key,
        "plaintext": plaintext
    }

    
---

```
### 4. Steganography Embedding

Embeds the encrypted data and HMAC tag into a cover image.

```python
def embed_in_image(ciphertext: bytes, iv: bytes, rsa_encrypted_key: bytes, hmac_tag: bytes, cover_image_path: str, aes_key: bytes, plaintext: bytes, hmac_key: bytes) -> dict:
    """
    Embed ciphertext, iv, rsa_encrypted_key, and hmac_tag into the cover image.
    Returns the stego image along with all parameters.
    """
    return {
        "stego_image": <bytes_or_str>,  # Image with embedded payload
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": rsa_encrypted_key,
        "hmac_tag": hmac_tag,
        "aes_key": aes_key,
        "plaintext": plaintext,
        "hmac_key": hmac_key
    }


---

```
## 🔓 Decryption Flow

### 1. Steganography Extraction

Extracts the embedded data from the stego image.

```python
def extract_from_image(stego_image_path: str) -> dict:
    """
    Extract ciphertext, iv, rsa_encrypted_key, and hmac_tag from the stego image.
    """
    return {
        "ciphertext": <bytes>,
        "iv": <bytes>,
        "rsa_encrypted_key": <bytes>,
        "hmac_tag": <bytes>
    }


---

```
### 2. HMAC Verification

Verifies the integrity of the extracted data using the HMAC key.

```python
def verify_hmac(ciphertext: bytes, iv: bytes, rsa_encrypted_key: bytes, hmac_tag: bytes, hmac_key: bytes) -> dict:
    """
    Verify the HMAC tag.
    Returns parameters plus boolean indicating validity of HMAC.
    """
    return {
        "ciphertext": ciphertext,
        "iv": iv,
        "rsa_encrypted_key": rsa_encrypted_key,
        "hmac_tag": hmac_tag,
        "hmac_key": hmac_key,
        "hmac_valid": <bool>
    }
```
### 3. RSA Decryption of AES Key

Decrypts the AES key using the RSA private key.

```python
def rsa_decrypt_key(rsa_encrypted_key: bytes, rsa_private_key: RSAPrivateKey, ciphertext: bytes, iv: bytes, hmac_tag: bytes, hmac_key: bytes) -> dict:
    """
    Decrypt AES key using RSA private key.
    Returns AES key along with other parameters.
    """
    return {
        "aes_key": <bytes>,  # Decrypted AES key
        "ciphertext": ciphertext,
        "iv": iv,
        "hmac_tag": hmac_tag,
        "hmac_key": hmac_key
    }

```
### 4. AES Decryption

Decrypts the ciphertext to recover the original plaintext.

```python
def aes_decrypt(ciphertext: bytes, iv: bytes, aes_key: bytes, hmac_tag: bytes, hmac_key: bytes) -> dict:
    """
    Decrypt ciphertext using AES key and iv.
    Returns the recovered plaintext along with other parameters.
    """
    return {
        "plaintext": <bytes>,  # Decrypted original message
        "ciphertext": ciphertext,
        "iv": iv,
        "aes_key": aes_key,
        "hmac_tag": hmac_tag,
        "hmac_key": hmac_key
    }
```
## 📝 Notes

- All functions pass forward all variables to maintain modularity and allow for independent testing.
- Sensitive keys (AES key, HMAC key) must be handled securely.
- This structure supports flexible integration via JSON, dictionaries, or files.
- Also try to use secure keys (randomized keys etc.)
