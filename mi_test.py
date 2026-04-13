import os
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from dotenv import load_dotenv

load_dotenv("/home/secureuploader/secure_uploader/.env")

storage_account_name = os.getenv("AZURE_STORAGE_ACCOUNT")
container_name = os.getenv("AZURE_STORAGE_CONTAINER", "securevault-files")

if not storage_account_name:
    raise RuntimeError("Missing AZURE_STORAGE_ACCOUNT")

account_url = f"https://{storage_account_name}.blob.core.windows.net"
credential = DefaultAzureCredential()
service = BlobServiceClient(account_url=account_url, credential=credential)
container = service.get_container_client(container_name)

print("Connected. Listing blobs:")
for blob in container.list_blobs():
    print(blob.name)
