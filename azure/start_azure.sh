#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 <resource-group> <app-name> [env-path] [location]

Creates Resource Group, App Service Plan (Linux), Web App (Python), applies app settings
from an optional .env file and zip-deploys the current repository.

Examples:
  ./azure/start_azure.sh rg-students secure-uploader-myid .env eastus
  ./azure/start_azure.sh rg-students secure-uploader-myid

The script expects `az` and `python` on PATH.
EOF
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -lt 2 ]]; then
  usage
  exit 1
fi

RG="$1"
APP_NAME="$2"
ENV_PATH="${3:-}"
LOCATION="${4:-eastus}"
PLAN_NAME="asp-students-plan"
SKU="B1"
PYTHON_VERSION="3.11"
DATA_DIR="/home/data"

if ! command -v az >/dev/null 2>&1; then
  echo "az CLI not found; please install and run 'az login' first." >&2
  exit 1
fi

if ! command -v python >/dev/null 2>&1; then
  echo "python not found; please install Python and ensure it's on PATH." >&2
  exit 1
fi

echo "Creating resource group $RG in $LOCATION..."
az group create --name "$RG" --location "$LOCATION" >/dev/null

echo "Creating App Service plan $PLAN_NAME (Linux, SKU $SKU)..."
az appservice plan create --name "$PLAN_NAME" --resource-group "$RG" --is-linux --sku "$SKU" >/dev/null

echo "Creating Web App $APP_NAME with Python $PYTHON_VERSION..."
az webapp create --resource-group "$RG" --plan "$PLAN_NAME" --name "$APP_NAME" --runtime "PYTHON:$PYTHON_VERSION" >/dev/null

# Read .env if provided
declare -A envmap
if [[ -n "$ENV_PATH" && -f "$ENV_PATH" ]]; then
  echo "Loading environment variables from $ENV_PATH"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%$'\r'}"  # strip CR if present
    [[ -z "$line" ]] && continue
    [[ ${line:0:1} == '#' ]] && continue
    if [[ "$line" == *"="* ]]; then
      key="${line%%=*}"
      val="${line#*=}"
      key="${key// /}"
      envmap["$key"]="$val"
    fi
  done < "$ENV_PATH"
fi

# Ensure UPLOAD_ENC_KEY exists (generate if missing)
if [[ -n "${envmap[UPLOAD_ENC_KEY]:-}" ]]; then
  ENC_KEY="${envmap[UPLOAD_ENC_KEY]}"
else
  echo "Generating UPLOAD_ENC_KEY (base64 of 32 random bytes)..."
  ENC_KEY=$(python -c 'import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())')
fi

# Defaults that env can override
FILESTORE_PASSPHRASE="student-passphrase-please-change"
FLASK_SECRET="change-this-secret"

if [[ -n "${envmap[FILESTORE_PASSPHRASE]:-}" ]]; then
  FILESTORE_PASSPHRASE="${envmap[FILESTORE_PASSPHRASE]}"
fi
if [[ -n "${envmap[FLASK_SECRET]:-}" ]]; then
  FLASK_SECRET="${envmap[FLASK_SECRET]}"
fi
if [[ -n "${envmap[DATA_DIR]:-}" ]]; then
  DATA_DIR="${envmap[DATA_DIR]}"
fi

echo "Applying app settings to web app..."
settings=(
  "UPLOAD_ENC_KEY=$ENC_KEY"
  "FILESTORE_PASSPHRASE=$FILESTORE_PASSPHRASE"
  "FLASK_SECRET=$FLASK_SECRET"
  "DATA_DIR=$DATA_DIR"
  "WEBSITES_PORT=8000"
)

# include any other keys from envmap not explicitly handled
for k in "${!envmap[@]}"; do
  case "$k" in
    UPLOAD_ENC_KEY|FILESTORE_PASSPHRASE|FLASK_SECRET|DATA_DIR) ;;
    *) settings+=("$k=${envmap[$k]}") ;;
  esac
done

az webapp config appsettings set --resource-group "$RG" --name "$APP_NAME" --settings "${settings[@]}" >/dev/null

echo "Configuring startup command to run Gunicorn..."
az webapp config set --resource-group "$RG" --name "$APP_NAME" --startup-file "gunicorn --bind=0.0.0.0:8000 --timeout 120 main:app" >/dev/null

echo "Creating deploy.zip (excluding .venv and deploy.zip)..."
python - <<'PY'
import zipfile,os
z=zipfile.ZipFile('deploy.zip','w',zipfile.ZIP_DEFLATED)
for root,dirs,files in os.walk('.'):
    # skip .venv folder
    if '.venv' in root.split(os.sep):
        continue
    for f in files:
        if f=='deploy.zip':
            continue
        path=os.path.join(root,f)
        arcname=os.path.relpath(path,'.')
        z.write(path,arcname)
z.close()
print('Created deploy.zip')
PY

echo "Deploying deploy.zip to $APP_NAME..."
az webapp deployment source config-zip --resource-group "$RG" --name "$APP_NAME" --src deploy.zip >/dev/null

echo "Enabling Always On..."
az webapp config appsettings set --resource-group "$RG" --name "$APP_NAME" --settings WEBSITES_ALWAYS_ON=true >/dev/null

url=$(az webapp show --resource-group "$RG" --name "$APP_NAME" --query defaultHostName -o tsv)
echo "Deployment complete. Browse to: https://$url"
echo "Tip: tail logs with: az webapp log tail --resource-group $RG --name $APP_NAME"

exit 0
