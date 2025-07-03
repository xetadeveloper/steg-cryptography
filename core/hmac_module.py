# core/hmac_module.py

from Crypto.Hash import HMAC, SHA256

def generate_hmac(key: bytes, data: bytes) -> bytes:
    """
    Generate an HMAC for the given data using the provided key.

    Args:
        key (bytes): The secret key (typically the AES key).
        data (bytes): The data to authenticate (usually the ciphertext).

    Returns:
        bytes: The HMAC tag.
    """
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.digest()


def verify_hmac(key: bytes, data: bytes, received_tag: bytes) -> bool:
    """
    Verify that the received HMAC tag matches the expected one for the given data.

    Args:
        key (bytes): The secret key used to generate the HMAC.
        data (bytes): The data to validate.
        received_tag (bytes): The HMAC received alongside the data.

    Returns:
        bool: True if verification passes, False otherwise.
    """
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    try:
        h.verify(received_tag)
        return True
    except ValueError:
        return False
