import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.keys import KeyClient
from azure.keyvault.keys.crypto import CryptographyClient

vault_url = os.environ["AZURE_KEY_VAULT_URL"]
key_name = os.environ["AZURE_KEY_NAME"]

cred = DefaultAzureCredential()
client = KeyClient(vault_url=vault_url, credential=cred)

key = client.get_key(key_name)
print("KEY:", key.id)

crypto = CryptographyClient(key, credential=cred)

dek = os.urandom(32)

wrapped = crypto.wrap_key("RSA-OAEP-256", dek)
unwrapped = crypto.unwrap_key("RSA-OAEP-256", wrapped.encrypted_key)

print("MATCH:", dek == unwrapped.key)

