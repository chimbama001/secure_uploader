# crypto_utils.py
import os, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_key_from_env(base64_key: str):
    """Accepts a URL-safe base64 key string and returns bytes (32 bytes expected)."""
    key = base64.urlsafe_b64decode(base64_key)
    if len(key) != 32:
        raise ValueError("Encryption key must be 32 bytes (base64 of 32 bytes).")
    return key


def encrypt_bytes(plaintext: bytes, key_bytes: bytes) -> bytes:
    """
    Returns: nonce(12) + ciphertext + tag (AESGCM includes tag in ciphertext output)
    We'll prefix the nonce so we can store them together.
    """
    aesgcm = AESGCM(key_bytes)
    nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
    ct = aesgcm.encrypt(nonce, plaintext, None)  # no associated data
    return nonce + ct


def decrypt_bytes(blob: bytes, key_bytes: bytes) -> bytes:
    """
    Input blob is nonce(12) || ciphertext_with_tag
    """
    if len(blob) < 13:
        raise ValueError("Blob too short to contain nonce+ct")
    nonce = blob[:12]
    ct = blob[12:]
    aesgcm = AESGCM(key_bytes)
    return aesgcm.decrypt(nonce, ct, None)
