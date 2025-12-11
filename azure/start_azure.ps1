<#
start_azure.ps1
Creates an Azure Resource Group, App Service Plan (Linux), Web App (Python), sets required
app settings for the `secure_uploader` flask app, then zip-deploys the current repo.

Usage (from repo root):
  pwsh .\azure\start_azure.ps1 -ResourceGroup "rg-students" -AppName "secure-uploader-xyz" -Location "eastus"

Requirements:
- Azure CLI installed and you are logged in (`az login`)
- PowerShell (Windows PowerShell or PowerShell Core)
- `python` available in PATH to generate an encryption key

This script is intended for student / dev usage. For production, manage secrets via Key Vault
and use a more robust deployment pipeline.
#>

param(
    [Parameter(Mandatory=$true)]
    [string] $ResourceGroup,

    [Parameter(Mandatory=$true)]
    [string] $AppName,

    [string] $Location = "eastus",
    [string] $PlanName = "asp-students-plan",
    [string] $Sku = "B1",
    [string] $PythonVersion = "3.11",
    [string] $DataDir = "/home/data",
    [string] $EnvPath = "",
    [switch] $ForceOverwriteZip
)

function Ensure-AzCliAvailable {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Write-Error "Azure CLI 'az' not found in PATH. Install it and run 'az login' before running this script."
        exit 1
    }
}

Ensure-AzCliAvailable

Write-Host "Creating resource group '$ResourceGroup' in '$Location'..."
az group create --name $ResourceGroup --location $Location | Out-Null

Write-Host "Creating App Service plan '$PlanName' (Linux, SKU $Sku)..."
az appservice plan create --name $PlanName --resource-group $ResourceGroup --is-linux --sku $Sku | Out-Null

Write-Host "Creating Web App '$AppName' with Python $PythonVersion..."
az webapp create --resource-group $ResourceGroup --plan $PlanName --name $AppName --runtime "PYTHON:$PythonVersion" | Out-Null

# Generate or reuse an upload encryption key
Write-Host "Generating UPLOAD_ENC_KEY (base64 of 32 random bytes)..."
try {
    # Use a PowerShell-friendly one-line Python invocation instead of a POSIX heredoc
    $encKey = & python -c "import base64,os;print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
    if ($null -eq $encKey -or $encKey.Trim() -eq '') {
        throw "Empty key"
    }
    $encKey = $encKey.Trim()
}
catch {
    Write-Error "Failed to generate UPLOAD_ENC_KEY. Ensure 'python' is available in PATH. Error: $_"
    exit 1
}

Write-Host "Preparing app settings (UPLOAD_ENC_KEY, FILESTORE_PASSPHRASE, FLASK_SECRET, DATA_DIR)..."
# defaults
$passphrase = "student-passphrase-please-change"
$flaskSecret = "change-this-secret"

# build a settings map so we can optionally override from an env file
$appSettings = @{}
$appSettings["UPLOAD_ENC_KEY"] = $encKey
$appSettings["FILESTORE_PASSPHRASE"] = $passphrase
$appSettings["FLASK_SECRET"] = $flaskSecret
$appSettings["DATA_DIR"] = $DataDir
$appSettings["WEBSITES_PORT"] = "8000"

if ($EnvPath -and (Test-Path $EnvPath)) {
    Write-Host "Loading additional settings from $EnvPath"
    Get-Content $EnvPath | ForEach-Object {
        $line = $_.Trim()
        if (-not [string]::IsNullOrWhiteSpace($line) -and -not $line.StartsWith('#')) {
            $parts = $line -split '=', 2
            if ($parts.Length -ge 1) {
                $k = $parts[0].Trim()
                $v = ''
                if ($parts.Length -ge 2) { $v = $parts[1].Trim() }
                if ($k) { $appSettings[$k] = $v }
            }
        }
    }
}

# Convert to an array of key=value strings for az CLI
$settingsArgs = @()
foreach ($k in $appSettings.Keys) { $settingsArgs += "$k=$($appSettings[$k])" }

Write-Host "Applying app settings to web app..."
az webapp config appsettings set --resource-group $ResourceGroup --name $AppName --settings $settingsArgs | Out-Null

Write-Host "Configuring startup command to run Gunicorn (production WSGI)..."
# The app exposes 'app' in main.py so we point gunicorn to main:app
az webapp config set --resource-group $ResourceGroup --name $AppName --startup-file "gunicorn --bind=0.0.0.0:8000 --timeout 120 main:app" | Out-Null

Write-Host "Packaging repository into deploy.zip (excluding .venv). This may include your .git; remove sensitive files before deploying."
$zipPath = Join-Path -Path (Get-Location) -ChildPath "deploy.zip"
if (Test-Path $zipPath) {
    if ($ForceOverwriteZip) { Remove-Item $zipPath -Force }
    else { Write-Host "deploy.zip already exists. Use -ForceOverwriteZip to overwrite." }
}

# Create zip excluding the .venv folder if present
$items = Get-ChildItem -Path . -Force | Where-Object { $_.Name -ne ".venv" -and $_.Name -ne "deploy.zip" }
Compress-Archive -Path $items.FullName -DestinationPath $zipPath -Force

Write-Host "Deploying $zipPath to $AppName via zip-deploy..."
az webapp deployment source config-zip --resource-group $ResourceGroup --name $AppName --src $zipPath | Out-Null

Write-Host "Enabling Always On..."
az webapp config appsettings set --resource-group $ResourceGroup --name $AppName --settings WEBSITES_ALWAYS_ON=true | Out-Null

$url = az webapp show --resource-group $ResourceGroup --name $AppName --query defaultHostName -o tsv
Write-Host "Deployment complete. Browse to: https://$url"

Write-Host "You can tail logs with: az webapp log tail --resource-group $ResourceGroup --name $AppName"
