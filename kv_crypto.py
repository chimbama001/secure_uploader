import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient, KeyWrapAlgorithm


KEY_VAULT_URL = os.getenv("AZURE_KEY_VAULT_URL")
KEY_NAME = os.getenv("AZURE_KEY_NAME")

credential = DefaultAzureCredential()
key_client = KeyClient(vault_url=KEY_VAULT_URL, credential=credential)
key = key_client.get_key(KEY_NAME)
crypto_client = CryptographyClient(key, credential=credential)


def encrypt_file_with_keyvault(plaintext: bytes) -> dict:
    """
    Encrypts file bytes using AES-GCM with a random per-file DEK.
    Then wraps the DEK using Azure Key Vault KEK.
    """

    # Per-file data encryption key
    dek = AESGCM.generate_key(bit_length=256)

    aesgcm = AESGCM(dek)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Wrap DEK using Key Vault key
    wrapped = crypto_client.wrap_key(
        KeyWrapAlgorithm.rsa_oaep_256,
        dek
    )

    return {
        "ciphertext": ciphertext,
        "nonce_b64": base64.b64encode(nonce).decode(),
        "wrapped_dek_b64": base64.b64encode(wrapped.encrypted_key).decode(),
        "key_id": key.id,
        "algorithm": "AES-256-GCM + KeyVault RSA-OAEP-256"
    }


def decrypt_file_with_keyvault(ciphertext: bytes, nonce_b64: str, wrapped_dek_b64: str) -> bytes:
    """
    Unwraps DEK using Key Vault, then decrypts file bytes.
    """

    nonce = base64.b64decode(nonce_b64)
    wrapped_dek = base64.b64decode(wrapped_dek_b64)

    unwrapped = crypto_client.unwrap_key(
        KeyWrapAlgorithm.rsa_oaep_256,
        wrapped_dek
    )

    dek = unwrapped.key

    aesgcm = AESGCM(dek)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return plaintext
