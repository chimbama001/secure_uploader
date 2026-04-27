#!/usr/bin/env bash

# SecureVault / SecureUploader CMMC Level 2 Evidence Check Script
# Run from the Azure VM.
# Recommended path:
# /home/secureuploader/secure_uploader/securevault_cmmc_audit.sh

APP_DIR="/home/secureuploader/secure_uploader"
MAIN_FILE="$APP_DIR/main.py"
CRYPTO_FILE="$APP_DIR/crypto_utils.py"
ENV_FILE="$APP_DIR/.env"
DB_FILE="$APP_DIR/files.db"
SERVICE_FILE="/etc/systemd/system/secureuploader.service"
NGINX_DIR="/etc/nginx/sites-enabled"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

green="\033[0;32m"
red="\033[0;31m"
yellow="\033[1;33m"
blue="\033[0;34m"
reset="\033[0m"

pass() {
    echo -e "${green}[PASS]${reset} $1"
    PASS_COUNT=$((PASS_COUNT+1))
}

fail() {
    echo -e "${red}[FAIL]${reset} $1"
    FAIL_COUNT=$((FAIL_COUNT+1))
}

warn() {
    echo -e "${yellow}[WARN]${reset} $1"
    WARN_COUNT=$((WARN_COUNT+1))
}

section() {
    echo
    echo -e "${blue}============================================================${reset}"
    echo -e "${blue}$1${reset}"
    echo -e "${blue}============================================================${reset}"
}

check_file_exists() {
    local file="$1"
    local description="$2"

    if [ -f "$file" ]; then
        pass "$description exists: $file"
    else
        fail "$description missing: $file"
    fi
}

check_grep() {
    local pattern="$1"
    local file="$2"
    local description="$3"

    if [ -f "$file" ] && grep -Eiq "$pattern" "$file"; then
        pass "$description"
    else
        fail "$description"
    fi
}

check_grep_warn() {
    local pattern="$1"
    local file="$2"
    local description="$3"

    if [ -f "$file" ] && grep -Eiq "$pattern" "$file"; then
        pass "$description"
    else
        warn "$description"
    fi
}

section "0. BASELINE FILE AND SERVICE CHECKS"

check_file_exists "$APP_DIR" "Application directory"
check_file_exists "$MAIN_FILE" "main.py"
check_file_exists "$CRYPTO_FILE" "crypto_utils.py"
check_file_exists "$ENV_FILE" ".env configuration file"
check_file_exists "$SERVICE_FILE" "systemd service file"

if systemctl is-active --quiet secureuploader; then
    pass "secureuploader systemd service is active"
else
    fail "secureuploader systemd service is not active"
fi

python3 -m py_compile "$MAIN_FILE" 2>/tmp/securevault_pycompile_error.txt
if [ $? -eq 0 ]; then
    pass "main.py passes Python syntax check"
else
    fail "main.py has syntax errors"
    cat /tmp/securevault_pycompile_error.txt
fi

section "1. ACCESS CONTROL REQUIREMENTS"

check_grep "role|is_admin|admin" "$MAIN_FILE" "AC.L2-3.1.1 / AC.L2-3.1.2: Application contains role/admin access control logic"
check_grep "login_required|session.*user|user_id" "$MAIN_FILE" "AC.L2-3.1.1: Routes appear to require authenticated user/session"
check_grep "owner_id|uploaded_by|created_by" "$MAIN_FILE" "AC.L2-3.1.1: File ownership logic appears present"
check_grep "admin_required|role.*admin|is_admin" "$MAIN_FILE" "AC.L2-3.1.5 / AC.L2-3.1.7: Privileged/admin function restriction appears present"
check_grep "share|shared|file_access" "$MAIN_FILE" "AC.L2-3.1.2 / AC.L2-3.1.3: File sharing/access-control functionality appears present"

section "2. IDENTIFICATION AND AUTHENTICATION REQUIREMENTS"

check_grep "username|email" "$MAIN_FILE" "IA.L2-3.5.1: User identifier logic appears present"
check_grep "verify_password|check_password|argon2|PasswordHasher" "$MAIN_FILE" "IA.L2-3.5.2 / IA.L2-3.5.10: Password verification/hash logic appears present"
check_grep "argon2|PasswordHasher" "$MAIN_FILE" "IA.L2-3.5.10: Argon2 password hashing appears used in main.py"
check_grep "argon2|PasswordHasher" "$CRYPTO_FILE" "IA.L2-3.5.10: Argon2/password hashing evidence appears in crypto_utils.py"

check_grep "MFA|multi-factor|msal|azure|otp|totp|authenticator" "$MAIN_FILE" "IA.L2-3.5.3: MFA-related logic appears present"
check_grep "_csrf|csrf|secrets.token|compare_digest" "$MAIN_FILE" "IA.L2-3.5.4: CSRF/replay-resistant token logic appears present"
check_grep "failed_login|locked_until|MAX_FAILED_ATTEMPTS|LOCKOUT_MINUTES" "$MAIN_FILE" "AC.L2-3.1.8: Failed login and lockout logic appears present"
check_grep "MAX_FAILED_ATTEMPTS" "$ENV_FILE" "AC.L2-3.1.8: MAX_FAILED_ATTEMPTS configured in .env"
check_grep "LOCKOUT_MINUTES" "$ENV_FILE" "AC.L2-3.1.8: LOCKOUT_MINUTES configured in .env"

check_grep "password.*length|len\\(password\\)|uppercase|lowercase|digit|special|regex" "$MAIN_FILE" "IA.L2-3.5.7: Password complexity checks appear present"
check_grep "password_history|previous_password|reuse" "$MAIN_FILE" "IA.L2-3.5.8: Password reuse prevention evidence appears present"
check_grep "temporary_password|force_password_change|must_change_password" "$MAIN_FILE" "IA.L2-3.5.9: Temporary password handling evidence appears present"
check_grep "password.*\\*|type=.password.|obscure" "$MAIN_FILE" "IA.L2-3.5.11: Password obscuring evidence appears present"

section "3. SESSION SECURITY REQUIREMENTS"

check_grep "SESSION_COOKIE_HTTPONLY.*True|HTTPONLY.*True" "$MAIN_FILE" "Session cookies configured as HTTPOnly"
check_grep "SESSION_COOKIE_SECURE.*True|COOKIE_SECURE.*True" "$MAIN_FILE" "Session cookies configured as Secure"
check_grep "SESSION_COOKIE_SAMESITE|SameSite|samesite" "$MAIN_FILE" "Session cookie SameSite protection appears configured"
check_grep "PERMANENT_SESSION_LIFETIME|session.permanent|timedelta" "$MAIN_FILE" "AC.L2-3.1.10 / AC.L2-3.1.11: Session lifetime/termination logic appears present"
check_grep "logout|session.clear|pop\\('user" "$MAIN_FILE" "AC.L2-3.1.11: Logout/session termination logic appears present"

section "4. ENCRYPTION AND CRYPTOGRAPHIC PROTECTION"

check_grep "AESGCM|AES-GCM|cryptography.hazmat.primitives.ciphers.aead" "$CRYPTO_FILE" "SC.L2-3.13.16 / SC.L2-3.13.11: AES-GCM encryption appears implemented"
check_grep "nonce|iv" "$CRYPTO_FILE" "Encryption nonce/IV handling appears present"
check_grep "dek|data encryption key|wrapped|wrap|unwrap" "$CRYPTO_FILE" "SC.L2-3.13.10: Envelope encryption / DEK wrapping evidence appears present"
check_grep "KeyVault|key vault|azure.keyvault|CryptographyClient|DefaultAzureCredential|ManagedIdentityCredential" "$CRYPTO_FILE" "SC.L2-3.13.10: Azure Key Vault / Managed Identity evidence appears in crypto_utils.py"
check_grep "KeyVault|key vault|azure.keyvault|DefaultAzureCredential|ManagedIdentityCredential" "$MAIN_FILE" "SC.L2-3.13.10: Azure Key Vault / Managed Identity evidence appears in main.py"
check_grep "AZURE_STORAGE_ACCOUNT|AZURE_STORAGE_CONTAINER" "$ENV_FILE" "Azure Blob Storage configuration exists in .env"
check_grep "AZURE_KEY_VAULT|KEY_VAULT|KEYVAULT|KV" "$ENV_FILE" "Azure Key Vault configuration appears in .env"

section "5. HTTPS, NETWORK, AND COMMUNICATION PROTECTION"

if grep -R "ssl_certificate" "$NGINX_DIR" >/dev/null 2>&1; then
    pass "SC.L2-3.13.8: Nginx TLS certificate configuration found"
else
    fail "SC.L2-3.13.8: Nginx TLS certificate configuration not found"
fi

if grep -R "return 301 https" "$NGINX_DIR" >/dev/null 2>&1 || grep -R "https://\$host" "$NGINX_DIR" >/dev/null 2>&1; then
    pass "SC.L2-3.13.8: HTTP to HTTPS redirect appears configured"
else
    fail "SC.L2-3.13.8: HTTP to HTTPS redirect not found"
fi

if grep -R "proxy_pass http://127.0.0.1:8000" "$NGINX_DIR" >/dev/null 2>&1; then
    pass "SC.L2-3.13.1 / SC.L2-3.13.5: Nginx reverse proxy forwards to localhost backend"
else
    fail "Nginx proxy_pass to 127.0.0.1:8000 not found"
fi

if grep -q "127.0.0.1:8000" "$SERVICE_FILE"; then
    pass "SC.L2-3.13.1: Gunicorn bound to localhost only"
else
    fail "Gunicorn may not be bound to localhost in systemd service"
fi

if ss -ltnp | grep -q "127.0.0.1:8000"; then
    pass "Runtime check: App is listening on 127.0.0.1:8000"
else
    fail "Runtime check: App is not listening on 127.0.0.1:8000"
fi

section "6. SSH AND REMOTE ACCESS HARDENING"

SSHD_EFFECTIVE="$(sudo sshd -T 2>/dev/null)"

echo "$SSHD_EFFECTIVE" | grep -qi "^passwordauthentication no"
if [ $? -eq 0 ]; then
    pass "AC.L2-3.1.12 / IA.L2-3.5.2: SSH password authentication disabled"
else
    fail "SSH password authentication may still be enabled"
fi

echo "$SSHD_EFFECTIVE" | grep -qi "^pubkeyauthentication yes"
if [ $? -eq 0 ]; then
    pass "IA.L2-3.5.4: SSH public key authentication enabled"
else
    fail "SSH public key authentication not confirmed"
fi

if systemctl is-active --quiet fail2ban; then
    pass "AC.L2-3.1.8: Fail2Ban service is active"
else
    warn "Fail2Ban service is not active or not installed"
fi

if sudo fail2ban-client status sshd >/dev/null 2>&1; then
    pass "AC.L2-3.1.8: Fail2Ban sshd jail exists"
else
    warn "Fail2Ban sshd jail not confirmed"
fi

section "7. AUDIT AND ACCOUNTABILITY REQUIREMENTS"

check_grep "audit|log|security_audit|event" "$MAIN_FILE" "AU.L2-3.3.1: Application audit logging logic appears present"
check_grep "user_id|username|actor|ip_address|timestamp|created_at" "$MAIN_FILE" "AU.L2-3.3.2: Logs appear to associate activity with users/time/IP"
check_grep "login|logout|upload|download|delete|share" "$MAIN_FILE" "AU.L2-3.3.1 / AU.L2-3.3.2: Security-relevant events appear logged"
check_grep "admin.*log|view.*log|audit.*admin" "$MAIN_FILE" "AU.L2-3.3.3 / AU.L2-3.3.9: Admin log review functionality appears present"

if journalctl -u secureuploader -n 5 --no-pager >/dev/null 2>&1; then
    pass "Systemd journal logs are available for secureuploader"
else
    warn "Could not read secureuploader journal logs"
fi

section "8. DATABASE SCHEMA EVIDENCE"

if [ -f "$DB_FILE" ]; then
    pass "SQLite database exists"

    sudo -u secureuploader sqlite3 "$DB_FILE" ".tables" >/tmp/securevault_tables.txt 2>/tmp/securevault_sql_error.txt

    if [ $? -eq 0 ]; then
        pass "Database readable as secureuploader user"
        echo "Database tables:"
        cat /tmp/securevault_tables.txt
    else
        fail "Database could not be read as secureuploader user"
        cat /tmp/securevault_sql_error.txt
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema users" 2>/dev/null | grep -Eiq "failed_login|locked_until"; then
        pass "AC.L2-3.1.8: users table contains failed login / lockout fields"
    else
        fail "users table missing failed login / lockout fields"
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema users" 2>/dev/null | grep -Eiq "role|is_admin"; then
        pass "AC.L2-3.1.2 / AC.L2-3.1.5: users table contains role/admin field"
    else
        fail "users table missing role/admin field"
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema files" 2>/dev/null | grep -Eiq "owner_id|uploaded_by"; then
        pass "AC.L2-3.1.1: files table contains ownership field"
    else
        fail "files table missing ownership field"
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema files" 2>/dev/null | grep -Eiq "dek|wrapped|nonce|enc|encryption"; then
        pass "SC.L2-3.13.16: files table contains encryption metadata fields"
    else
        fail "files table missing encryption metadata fields"
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema file_access" 2>/dev/null | grep -Eiq "file_id|user_id|shared"; then
        pass "AC.L2-3.1.2: file_access table supports shared file authorization"
    else
        warn "file_access table not confirmed"
    fi

    if sudo -u secureuploader sqlite3 "$DB_FILE" ".schema" 2>/dev/null | grep -Eiq "audit|security_audit|logs"; then
        pass "AU.L2-3.3.1: audit/security log table appears present"
    else
        fail "No audit/security log table found"
    fi

else
    fail "SQLite database not found"
fi

section "9. MEDIA PROTECTION AND BACKUP EVIDENCE"

check_grep "backup|backup_records" "$MAIN_FILE" "MP.L2-3.8.9: Backup functionality appears present"
check_grep "backup_records" "$MAIN_FILE" "MP.L2-3.8.9: Backup records logic appears present"
check_grep "delete|remove|crypto.?shred|dek_wrapped|dek" "$MAIN_FILE" "MP.L2-3.8.3: Delete/crypto-shredding evidence appears present"
check_grep "blob|BlobServiceClient|azure.storage.blob" "$MAIN_FILE" "MP.L2-3.8.9 / SC.L2-3.13.16: Azure Blob backup/storage logic appears present"

section "10. CONFIGURATION MANAGEMENT AND LEAST FUNCTIONALITY"

if [ -f "$APP_DIR/.gitignore" ]; then
    pass ".gitignore exists"

    if grep -Eiq ".env|files.db|.venv|__pycache__|upload_enc_key" "$APP_DIR/.gitignore"; then
        pass "CM.L2-3.4.6 / SC.L2-3.13.10: .gitignore excludes secrets/local DB/venv artifacts"
    else
        warn ".gitignore may not exclude sensitive/local artifacts"
    fi
else
    warn ".gitignore not found"
fi

if command -v ufw >/dev/null 2>&1; then
    sudo ufw status | grep -qi "Status: active"
    if [ $? -eq 0 ]; then
        pass "SC.L2-3.13.1: UFW firewall is active"
    else
        warn "UFW firewall not active"
    fi
else
    warn "UFW not installed"
fi

section "11. LIVE APPLICATION SMOKE TESTS"

if curl -k -I https://localhost >/tmp/securevault_https_headers.txt 2>/dev/null; then
    pass "HTTPS endpoint responds locally"
    cat /tmp/securevault_https_headers.txt | head -n 10
else
    warn "Could not reach https://localhost"
fi

if curl -I http://127.0.0.1:8000 >/tmp/securevault_backend_headers.txt 2>/dev/null; then
    pass "Backend responds on localhost"
else
    fail "Backend does not respond on localhost"
fi

if curl -I http://localhost >/tmp/securevault_http_headers.txt 2>/dev/null && grep -Eiq "301|302|https" /tmp/securevault_http_headers.txt; then
    pass "HTTP endpoint redirects to HTTPS"
else
    warn "HTTP to HTTPS redirect not confirmed by curl"
fi

section "12. SUMMARY"

echo -e "${green}PASS:${reset} $PASS_COUNT"
echo -e "${yellow}WARN:${reset} $WARN_COUNT"
echo -e "${red}FAIL:${reset} $FAIL_COUNT"

echo
echo "Interpretation:"
echo "- PASS means the script found technical evidence."
echo "- WARN means the control may be partially implemented or needs manual verification."
echo "- FAIL means the expected evidence was not found."
echo
echo "Important:"
echo "This script cannot prove full CMMC Level 2 compliance by itself."
echo "CMMC still requires final policies, SSP, diagrams, procedures, screenshots, logs, interviews, and assessor judgment."
echo
echo "Recommended next step:"
echo "Save this output as evidence:"
echo
echo "  ./securevault_cmmc_audit.sh | tee securevault_cmmc_audit_results.txt"
echo
