#!/usr/bin/env bash

echo "=== SC.L2-3.13.10 TEST START ==="

echo "Checking .env for insecure key..."
if grep -q "UPLOAD_ENC_KEY" .env; then
  echo "[FAIL] Plaintext key still in .env"
else
  echo "[PASS] No plaintext key in .env"
fi

echo
echo "Checking Key Vault config..."
grep "AZURE_KEY_VAULT_URL" .env
grep "AZURE_KEY_NAME" .env

echo
echo "Testing Managed Identity..."
curl -s -H Metadata:true \
"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net" \
| grep access_token >/dev/null

if [ $? -eq 0 ]; then
  echo "[PASS] Managed Identity working"
else
  echo "[FAIL] Managed Identity NOT working"
fi

echo
echo "Testing Python Key Vault access..."

python3 - <<EOF
import os
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.keys import KeyClient

    vault = os.getenv("AZURE_KEY_VAULT_URL")
    key = os.getenv("AZURE_KEY_NAME")

    cred = DefaultAzureCredential()
    client = KeyClient(vault_url=vault, credential=cred)
    k = client.get_key(key)

    print("[PASS] Key Vault access working")
except Exception as e:
    print("[FAIL] Key Vault access failed:", e)
EOF

echo
echo "=== TEST COMPLETE ==="
