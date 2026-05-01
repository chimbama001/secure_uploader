#!/usr/bin/env bash
# SecureVault CMMC L2 Objective-Based Audit Script
# Purpose: produce repeatable technical evidence for Mohammed's auditor role.
# Note: CMMC findings still require assessor judgment, final documentation, interviews, screenshots, SSP, and policies.

set +e

PASS=0; WARN=0; FAIL=0; INFO=0
START_TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
HOST="$(hostname 2>/dev/null || echo unknown)"
REPORT="securevault_cmmc_audit_report_${START_TS//[:]/-}.md"
RAW="securevault_cmmc_audit_raw_${START_TS//[:]/-}.txt"

# -----------------------------
# Path discovery
# -----------------------------
CANDIDATE_DIRS=(
  "$PWD"
  "/home/mohammed/secure_uploader"
  "/home/secureuploader/secure_uploader"
  "/srv/secure_uploader"
)
APP_DIR=""
for d in "${CANDIDATE_DIRS[@]}"; do
  if [[ -f "$d/main.py" ]]; then APP_DIR="$d"; break; fi
done
[[ -z "$APP_DIR" ]] && APP_DIR="$PWD"
MAIN="$APP_DIR/main.py"
CRYPTO="$APP_DIR/crypto_utils.py"
ENVFILE="$APP_DIR/.env"
SERVICE_FILE="/etc/systemd/system/secureuploader.service"
SERVICE_NAME="secureuploader.service"
DB_PATH=""
DATA_DIR=""

# Prefer env DATA_DIR, then common paths
if [[ -f "$ENVFILE" ]]; then
  DATA_DIR="$(grep -E '^DATA_DIR=' "$ENVFILE" | tail -1 | cut -d= -f2- | tr -d '"')"
fi
[[ -z "$DATA_DIR" && -d "/srv/secure_uploader_data" ]] && DATA_DIR="/srv/secure_uploader_data"
[[ -z "$DATA_DIR" && -d "$APP_DIR/instance" ]] && DATA_DIR="$APP_DIR/instance"
[[ -z "$DATA_DIR" ]] && DATA_DIR="$APP_DIR"

for db in "$DATA_DIR/files.db" "$APP_DIR/files.db" "/srv/secure_uploader_data/files.db"; do
  if [[ -f "$db" ]]; then DB_PATH="$db"; break; fi
done

# -----------------------------
# Output helpers
# -----------------------------
line(){ printf '%s\n' "$1" | tee -a "$RAW"; }
section(){ line ""; line "============================================================"; line "$1"; line "============================================================"; }
record(){
  local status="$1"; local control="$2"; local objective="$3"; local evidence="$4"; local method="$5"
  case "$status" in
    PASS) PASS=$((PASS+1));;
    WARN) WARN=$((WARN+1));;
    FAIL) FAIL=$((FAIL+1));;
    INFO) INFO=$((INFO+1));;
  esac
  printf '[%s] %-22s %-10s %s\n' "$status" "$control" "$objective" "$evidence" | tee -a "$RAW"
  printf '| %s | %s | %s | %s | %s |\n' "$control" "$objective" "$method" "$status" "${evidence//|/ }" >> "$REPORT"
}
exists(){ [[ -e "$1" ]]; }
contains(){ local file="$1"; local pattern="$2"; [[ -f "$file" ]] && grep -Eiq "$pattern" "$file"; }
cmd_ok(){ bash -lc "$1" >/tmp/sv_audit_cmd.out 2>/tmp/sv_audit_cmd.err; return $?; }
sql(){ [[ -n "$DB_PATH" ]] && sqlite3 "$DB_PATH" "$1" 2>/dev/null; }
has_table(){ sql ".tables" | tr ' ' '\n' | grep -qx "$1"; }
has_col(){ local table="$1"; local col_regex="$2"; sql "PRAGMA table_info($table);" | grep -Eiq "$col_regex"; }

# Initialize markdown report
cat > "$REPORT" <<HDR
# SecureVault CMMC Level 2 Objective-Based Audit Report

**Generated:** $START_TS  
**Host:** $HOST  
**Application Directory:** $APP_DIR  
**Database:** ${DB_PATH:-Not found}  
**Auditor:** Mohammed Alruwaili  

> This report is technical evidence for the Senior Design SecureVault project. It supports CMMC Level 2 style assessment using Examine, Interview, and Test methods. It does not claim official CMMC certification.

| Control / FR | Objective | Method | Finding | Evidence |
|---|---|---|---|---|
HDR

section "0. BASELINE SCOPE AND EVIDENCE SOURCES"
exists "$APP_DIR" && record PASS "BASELINE" "Scope" "Application directory detected: $APP_DIR" "Examine" || record FAIL "BASELINE" "Scope" "Application directory missing: $APP_DIR" "Examine"
exists "$MAIN" && record PASS "BASELINE" "File" "main.py exists" "Examine" || record FAIL "BASELINE" "File" "main.py missing" "Examine"
exists "$CRYPTO" && record PASS "BASELINE" "File" "crypto_utils.py exists" "Examine" || record WARN "BASELINE" "File" "crypto_utils.py not found; crypto may be inside main.py" "Examine"
exists "$ENVFILE" && record PASS "BASELINE" "Config" ".env file exists: $ENVFILE" "Examine" || record WARN "BASELINE" "Config" ".env not found in app dir; may be configured via systemd/Azure" "Examine"
exists "$SERVICE_FILE" && record PASS "BASELINE" "Service" "systemd unit exists: $SERVICE_FILE" "Examine" || record WARN "BASELINE" "Service" "systemd unit not found at expected path" "Examine"
if systemctl is-active --quiet "$SERVICE_NAME"; then record PASS "BASELINE" "Runtime" "$SERVICE_NAME is active" "Test"; else record WARN "BASELINE" "Runtime" "$SERVICE_NAME is not active or not named secureuploader.service" "Test"; fi
python3 -m py_compile "$MAIN" >/dev/null 2>&1 && record PASS "BASELINE" "Syntax" "main.py passes python syntax check" "Test" || record FAIL "BASELINE" "Syntax" "main.py syntax check failed" "Test"

section "1. ACCESS CONTROL (AC) OBJECTIVE CHECKS"
contains "$MAIN" "login_required|session\[['\"]user_id|@.*login" && record PASS "AC.L2-3.1.1" "a,d" "Authorized users are identified and protected routes require login/session" "Examine/Test" || record FAIL "AC.L2-3.1.1" "a,d" "Could not find authentication gate for protected routes" "Examine"
contains "$MAIN" "owner_id|file_access|user_can_access|can_read|can_delete|share" && record PASS "AC.L2-3.1.1" "c,f" "File/device/resource authorization logic appears present using owner/share/access fields" "Examine" || record FAIL "AC.L2-3.1.1" "c,f" "No ownership or resource authorization logic found" "Examine"
contains "$MAIN" "role|admin|UserRole|is_admin|admin_required" && record PASS "AC.L2-3.1.2" "a,b" "User roles/functions are defined and access appears role-restricted" "Examine/Test" || record FAIL "AC.L2-3.1.2" "a,b" "Role/function restriction evidence not found" "Examine"
contains "$MAIN" "share|file_access|can_read|can_delete|download|delete|preview" && record PASS "AC.L2-3.1.3" "a-e" "CUI/file flow is controlled through upload/download/share/delete routes and access checks" "Examine/Test" || record WARN "AC.L2-3.1.3" "a-e" "Need manual evidence of information flow policy and route tests" "Examine/Interview/Test"
contains "$MAIN" "admin|role.*user|UserRole|standard user|privileged" && record PASS "AC.L2-3.1.4" "a-c" "Separation of admin and standard user duties appears implemented" "Examine" || record WARN "AC.L2-3.1.4" "a-c" "Need policy/interview evidence for separation of duties" "Examine/Interview"
contains "$MAIN" "admin_required|role.*admin|can_delete|owner_id|least" && record PASS "AC.L2-3.1.5" "a-d" "Least privilege evidence found through admin/owner/share restrictions" "Examine/Test" || record FAIL "AC.L2-3.1.5" "a-d" "Least privilege enforcement not clearly found" "Examine"
contains "$MAIN" "role.*user|role.*admin|admin_required" && record PASS "AC.L2-3.1.6" "a,b" "Non-security/standard user role separation appears present" "Examine" || record WARN "AC.L2-3.1.6" "a,b" "Need manual evidence showing admins use non-privileged accounts for normal tasks" "Interview"
contains "$MAIN" "403|abort\(403\)|admin_required|audit.*privileged|log_event" && record PASS "AC.L2-3.1.7" "a-d" "Privileged functions appear blocked for non-privileged users and loggable" "Examine/Test" || record WARN "AC.L2-3.1.7" "a-d" "Need route test for non-admin attempting privileged action" "Test"
contains "$MAIN" "MAX_FAILED_ATTEMPTS|failed_login|lockout|Limiter|limiter\.limit|5 per" && record PASS "AC.L2-3.1.8" "a,b" "Failed login limitation/rate limiting evidence found" "Examine/Test" || record FAIL "AC.L2-3.1.8" "a,b" "No failed login threshold/rate limit evidence found" "Examine"
contains "$MAIN" "banner|notice|onboarding|privacy|security notice|authorized use" && record PASS "AC.L2-3.1.9" "a,b" "Privacy/security notice or onboarding banner evidence appears present" "Examine/Test" || record WARN "AC.L2-3.1.9" "a,b" "Need screenshot of login/onboarding security notice" "Examine/Test"
contains "$MAIN" "permanent_session_lifetime|session.*lifetime|timeout|inactive|timedelta\(minutes" && record PASS "AC.L2-3.1.10" "a-c" "Session inactivity lock/timeout configuration appears present" "Examine/Test" || record WARN "AC.L2-3.1.10" "a-c" "Need browser test showing lock/pattern hiding after inactivity" "Test"
contains "$MAIN" "permanent_session_lifetime|logout|session\.clear|timeout" && record PASS "AC.L2-3.1.11" "a,b" "Session termination condition and logout/session clear evidence found" "Examine/Test" || record FAIL "AC.L2-3.1.11" "a,b" "No automatic session termination evidence found" "Examine"
contains "$MAIN" "REMOTE_ADDR|request.remote_addr|ip_address|audit.*ip" && record PASS "AC.L2-3.1.12" "a-d" "Remote access/session activity appears monitored through IP/user audit logging" "Examine/Test" || record WARN "AC.L2-3.1.12" "a-d" "Need SSH/Azure/Nginx logs for remote access monitoring" "Test"
contains "$SERVICE_FILE" "bind 127.0.0.1:8000|127.0.0.1" && record PASS "AC.L2-3.1.14" "a,b" "Remote/app access routed through managed reverse proxy to localhost backend" "Examine/Test" || record WARN "AC.L2-3.1.14" "a,b" "Need Nginx/service evidence for managed access point" "Examine/Test"
contains "$MAIN" "admin_required|privileged|audit_logs|security" && record PASS "AC.L2-3.1.15" "a-d" "Privileged remote admin/security access appears role-restricted" "Examine" || record WARN "AC.L2-3.1.15" "a-d" "Need manual list of privileged remote commands and authorization" "Examine/Interview"
contains "$MAIN" "mobile|wireless|removable|external" && record WARN "AC.L2-3.1.16-19" "All" "Wireless/mobile controls require policy/N/A justification unless in scope" "Interview/SSP" || record WARN "AC.L2-3.1.16-19" "All" "No wireless/mobile app evidence; document N/A or inherited/not used in SSP" "Interview/SSP"
contains "$MAIN" "external|Azure|blob|Key Vault|storage" && record PASS "AC.L2-3.1.20" "a-f" "External/cloud service use appears identified through Azure Blob/Key Vault configuration" "Examine" || record WARN "AC.L2-3.1.20" "a-f" "Need external service inventory and Azure screenshots" "Examine"
contains "$MAIN" "public|published|CUI|download|share" && record WARN "AC.L2-3.1.22" "a,b" "Public information control needs manual content review and approval evidence" "Interview/Examine" || record WARN "AC.L2-3.1.22" "a,b" "Need public release review policy/evidence" "Interview/Examine"

section "2. IDENTIFICATION AND AUTHENTICATION (IA) OBJECTIVE CHECKS"
contains "$MAIN" "username|user_id|users\(|CREATE TABLE.*users|oid|sub" && record PASS "IA.L2-3.5.1" "a-d" "Users are uniquely identified by username/user_id/OIDC identifiers" "Examine/Test" || record FAIL "IA.L2-3.5.1" "a-d" "Unique user identifier evidence not found" "Examine"
contains "$MAIN" "verify\(|PasswordHasher|argon2|check_password|oauth|msal|oidc" && record PASS "IA.L2-3.5.2" "a,b" "Authentication mechanism/password verification/OIDC evidence found" "Examine/Test" || record FAIL "IA.L2-3.5.2" "a,b" "Authentication verification evidence not found" "Examine"
contains "$MAIN" "MFA|mfa|totp|pyotp|authenticator|Microsoft|OIDC|Entra" && record PASS "IA.L2-3.5.3" "a-d" "MFA/OIDC/Entra or TOTP evidence appears present" "Examine/Test" || record WARN "IA.L2-3.5.3" "a-d" "Need screenshot/config showing MFA for privileged/network access" "Examine/Test"
contains "$MAIN" "csrf|state|nonce|token|auth_state|SameSite" && record PASS "IA.L2-3.5.4" "a,b" "Replay-resistant token/state/CSRF/SameSite evidence found" "Examine/Test" || record WARN "IA.L2-3.5.4" "a,b" "Need evidence for CSRF/OIDC state replay protection" "Test"
contains "$MAIN" "password_history|reuse|previous_password|old_password" && record PASS "IA.L2-3.5.8" "a,b" "Password reuse prevention logic appears present" "Examine/Test" || record WARN "IA.L2-3.5.8" "a,b" "Password reuse prevention not found; document if handled by Entra or not implemented" "Examine"
contains "$MAIN" "temporary_password|must_change|reset_token|password_reset" && record PASS "IA.L2-3.5.9" "a-c" "Temporary password/password reset handling appears present" "Examine/Test" || record WARN "IA.L2-3.5.9" "a-c" "Temporary password handling not found; document as N/A if no temp passwords used" "Interview/SSP"
contains "$MAIN" "PasswordHasher|argon2|password_hash|ph\.hash|bcrypt|pbkdf2" && record PASS "IA.L2-3.5.10" "a,b" "Passwords appear cryptographically protected using hashing" "Examine/Test" || record FAIL "IA.L2-3.5.10" "a,b" "Password hashing evidence not found" "Examine"
contains "$MAIN" "type=['\"]password|password" && record PASS "IA.L2-3.5.11" "a,b" "Password input/obscuring evidence appears present in templates or inline HTML" "Examine" || record WARN "IA.L2-3.5.11" "a,b" "Need screenshot showing password fields are obscured" "Test"

section "3. AUDIT AND ACCOUNTABILITY (AU) OBJECTIVE CHECKS"
contains "$MAIN" "audit_log|audit_logs|log_event|security_event|INSERT INTO.*audit" && record PASS "AU.L2-3.3.1" "a-d" "Audit record generation logic found" "Examine/Test" || record FAIL "AU.L2-3.3.1" "a-d" "Audit record generation logic not found" "Examine"
contains "$MAIN" "user_id|username|ip|timestamp|created_at|datetime" && record PASS "AU.L2-3.3.2" "a,b" "Audit records appear linked to user/time/IP" "Examine/Test" || record FAIL "AU.L2-3.3.2" "a,b" "User accountability fields not found" "Examine"
contains "$MAIN" "audit.*review|admin.*logs|logs|audit_logs" && record PASS "AU.L2-3.3.3" "a,b" "Admin audit log review functionality appears present" "Examine/Test" || record WARN "AU.L2-3.3.3" "a,b" "Need screenshot of admin reviewing logs" "Test"
contains "$MAIN" "audit.*fail|logging.*fail|except.*log|alert" && record WARN "AU.L2-3.3.4" "a,b" "Audit failure handling/alerting may need manual validation" "Test" || record WARN "AU.L2-3.3.4" "a,b" "Need evidence for audit failure alert behavior" "Test/Interview"
contains "$MAIN" "correlat|user_id|ip|file_id|event_type" && record PASS "AU.L2-3.3.5" "a,b" "Audit fields support correlation by user/IP/file/event" "Examine" || record WARN "AU.L2-3.3.5" "a,b" "Need evidence of correlating logs across sources" "Test"
contains "$MAIN" "report|export|audit.*download|audit.*csv|logs" && record PASS "AU.L2-3.3.6" "a,b" "Audit review/reporting functionality appears present" "Examine/Test" || record WARN "AU.L2-3.3.6" "a,b" "Need exported audit report evidence" "Test"
if timedatectl status 2>/dev/null | grep -Eiq 'System clock synchronized: yes|NTP service: active'; then record PASS "AU.L2-3.3.7" "a,b" "System time synchronization is active" "Test"; else record WARN "AU.L2-3.3.7" "a,b" "Could not confirm NTP/time synchronization" "Test"; fi
[[ -n "$DB_PATH" ]] && record PASS "AU.L2-3.3.8" "a,b" "Audit DB located at $DB_PATH; check file permissions below" "Examine" || record FAIL "AU.L2-3.3.8" "a,b" "Audit database not found" "Examine"
contains "$MAIN" "admin.*audit|audit.*admin|logs" && record PASS "AU.L2-3.3.9" "a,b" "Audit management/review appears restricted to admin" "Examine/Test" || record WARN "AU.L2-3.3.9" "a,b" "Need screenshot/test showing only admin can manage logs" "Test"

section "4. CONFIGURATION MANAGEMENT (CM) OBJECTIVE CHECKS"
[[ -d "$APP_DIR/.git" ]] && record PASS "CM.L2-3.4.1" "a-c" "Git repository provides configuration baseline/history" "Examine" || record WARN "CM.L2-3.4.1" "a-c" "Git repo not found; provide baseline document manually" "Examine"
[[ -f "$APP_DIR/requirements.txt" || -f "$APP_DIR/pyproject.toml" ]] && record PASS "CM.L2-3.4.1" "a-c" "Dependency baseline file exists" "Examine" || record WARN "CM.L2-3.4.1" "a-c" "Dependency baseline file not found" "Examine"
[[ -f "$APP_DIR/.gitignore" ]] && grep -Eiq '\.env|files\.db|venv|__pycache__|uploads' "$APP_DIR/.gitignore" && record PASS "CM.L2-3.4.6" "a,b" ".gitignore excludes secrets/local DB/venv/uploads" "Examine" || record WARN "CM.L2-3.4.6" "a,b" ".gitignore missing or incomplete" "Examine"
[[ -d "$APP_DIR/.git" ]] && git -C "$APP_DIR" log --oneline -5 >/tmp/gitlog 2>/dev/null && record PASS "CM.L2-3.4.3" "a-e" "Recent git change history available" "Examine" || record WARN "CM.L2-3.4.3" "a-e" "Need change-management evidence/commits" "Examine"
contains "$MAIN" "pip|subprocess|exec\(|eval\(|os\.system" && record WARN "CM.L2-3.4.7" "a,b" "Potential execution/system functionality detected; review for necessity" "Examine" || record PASS "CM.L2-3.4.7" "a,b" "No obvious dangerous user-facing execution functions found" "Examine"
contains "$MAIN" "upload|allowed|secure_filename|MAX_CONTENT_LENGTH" && record PASS "CM.L2-3.4.8" "a,b" "Upload constraints/application behavior controls appear present" "Examine/Test" || record WARN "CM.L2-3.4.8" "a,b" "Need application execution/upload restriction evidence" "Test"
contains "$MAIN" "user-installed|software|admin.*install" && record WARN "CM.L2-3.4.9" "a,b" "User-installed software likely policy/OS-level; verify manually" "Interview" || record WARN "CM.L2-3.4.9" "a,b" "Need policy/OS evidence restricting user-installed software" "Interview/Examine"

section "5. CRYPTOGRAPHY, STORAGE, AND COMMUNICATION PROTECTION (SC)"
contains "$CRYPTO" "AESGCM|AES-GCM|Fernet|encrypt|decrypt|nonce|iv" || contains "$MAIN" "AESGCM|AES-GCM|encrypt_bytes|decrypt_bytes|nonce|iv" && record PASS "SC.L2-3.13.16" "a,b" "Data-at-rest encryption implementation appears present" "Examine/Test" || record FAIL "SC.L2-3.13.16" "a,b" "Data-at-rest encryption evidence not found" "Examine"
contains "$CRYPTO" "KeyVault|KeyClient|DefaultAzureCredential|wrap|unwrap|ManagedIdentity" || contains "$MAIN" "KeyVault|Key Vault|DefaultAzureCredential|AZURE_KEY|ManagedIdentity|UPLOAD_ENC_KEY" && record PASS "SC.L2-3.13.10" "a-c" "Key management evidence found through Key Vault/env key handling" "Examine/Test" || record WARN "SC.L2-3.13.10" "a-c" "Need Key Vault/env key evidence; do not expose secret value" "Examine"
contains "$CRYPTO" "AESGCM|cryptography" || contains "$MAIN" "AESGCM|cryptography|TLS|https" && record PASS "SC.L2-3.13.11" "a,b" "Cryptographic mechanism evidence appears present" "Examine" || record WARN "SC.L2-3.13.11" "a,b" "Need FIPS/crypto module explanation for academic scope" "Interview/SSP"
if grep -R "ssl_certificate\|return 301 https\|proxy_pass http://127.0.0.1" /etc/nginx/sites-enabled /etc/nginx/sites-available 2>/dev/null | grep -q .; then record PASS "SC.L2-3.13.8" "a,b" "Nginx TLS/HTTPS reverse proxy evidence found" "Examine/Test"; else record WARN "SC.L2-3.13.8" "a,b" "Nginx TLS evidence not found; provide Azure/HTTPS screenshot" "Examine/Test"; fi
contains "$SERVICE_FILE" "127.0.0.1:8000" && record PASS "SC.L2-3.13.1" "a,b" "Backend bound to localhost behind boundary/reverse proxy" "Examine/Test" || record WARN "SC.L2-3.13.1" "a,b" "Need firewall/reverse proxy boundary evidence" "Test"
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -Eiq "Status: active"; then record PASS "SC.L2-3.13.6" "a,b" "UFW firewall active" "Test"; else record WARN "SC.L2-3.13.6" "a,b" "UFW not confirmed; use Azure NSG screenshot if applicable" "Test"; fi
contains "$MAIN" "collaboration|camera|microphone|remote activation" && record PASS "SC.L2-3.13.12" "a,b" "Collaborative device control evidence found" "Examine" || record WARN "SC.L2-3.13.12" "a,b" "If no collaboration devices are used, document as N/A in SSP" "Interview/SSP"
contains "$MAIN" "mobile code|javascript upload|script" && record WARN "SC.L2-3.13.13" "a,b" "Mobile code requires policy/config evidence" "Interview" || record WARN "SC.L2-3.13.13" "a,b" "Need policy/N/A for mobile code" "Interview/SSP"
contains "$MAIN" "voip|voice" && record WARN "SC.L2-3.13.14" "a,b" "VoIP requires policy/config evidence" "Interview" || record WARN "SC.L2-3.13.14" "a,b" "Need N/A statement if VoIP not in scope" "Interview/SSP"
contains "$MAIN" "hmac|signature|csrf|state|nonce" && record PASS "SC.L2-3.13.15" "a,b" "Communication authenticity/token evidence appears present" "Examine/Test" || record WARN "SC.L2-3.13.15" "a,b" "Need evidence for communication authenticity" "Test"

section "6. DATABASE SCHEMA OBJECTIVE EVIDENCE"
if [[ -n "$DB_PATH" ]]; then
  record PASS "DB" "Source" "SQLite database exists: $DB_PATH" "Examine"
  line "Database tables:"; sql ".tables" | tee -a "$RAW"
  has_table users && record PASS "IA/AC" "Schema" "users table exists" "Examine" || record FAIL "IA/AC" "Schema" "users table missing" "Examine"
  has_col users "username|email|oid" && record PASS "IA.L2-3.5.1" "a" "users table contains unique identifier field" "Examine" || record FAIL "IA.L2-3.5.1" "a" "users identifier field missing" "Examine"
  has_col users "password_hash|hash" && record PASS "IA.L2-3.5.10" "a" "users table stores password hash, not plaintext" "Examine" || record WARN "IA.L2-3.5.10" "a" "password hash column not found; may use Entra/OIDC" "Examine"
  has_col users "role|admin" && record PASS "AC.L2-3.1.2" "a,b" "users table contains role/admin field" "Examine" || record FAIL "AC.L2-3.1.2" "a,b" "role/admin field missing" "Examine"
  has_col users "failed|lock" && record PASS "AC.L2-3.1.8" "a,b" "users table contains failed login/lockout fields" "Examine" || record WARN "AC.L2-3.1.8" "a,b" "failed login/lockout DB fields not found; maybe limiter-only" "Examine"
  has_table files && has_col files "owner_id|user_id" && record PASS "AC.L2-3.1.1" "a,d" "files table contains ownership field" "Examine" || record WARN "AC.L2-3.1.1" "a,d" "files ownership field missing or not found" "Examine"
  has_table file_access && record PASS "AC.L2-3.1.2" "b" "file_access table supports shared authorization" "Examine" || record WARN "AC.L2-3.1.2" "b" "file_access table not found" "Examine"
  (has_table audit_log || has_table audit_logs) && record PASS "AU.L2-3.3.1" "a-d" "audit log table exists" "Examine" || record FAIL "AU.L2-3.3.1" "a-d" "audit log table missing" "Examine"
  (has_table backup_records) && record PASS "MP.L2-3.8.9" "a,b" "backup_records table exists" "Examine" || record WARN "MP.L2-3.8.9" "a,b" "backup_records table not found" "Examine"
else
  record FAIL "DB" "Source" "No SQLite database found in expected locations" "Examine"
fi

section "7. MEDIA PROTECTION, BACKUP, MAINTENANCE, INCIDENT RESPONSE, RISK"
contains "$MAIN" "backup|backup_records|BlobServiceClient|container" && record PASS "MP.L2-3.8.9" "a-c" "Backup/storage functionality appears present" "Examine/Test" || record WARN "MP.L2-3.8.9" "a-c" "Need backup execution evidence" "Test"
contains "$MAIN" "delete|remove|os\.remove|crypto.?shred|destroy" && record PASS "MP.L2-3.8.3" "a,b" "Media/file disposal/delete logic appears present" "Examine/Test" || record WARN "MP.L2-3.8.3" "a,b" "Need delete test and evidence" "Test"
contains "$MAIN" "removable|usb|portable" && record WARN "MP.L2-3.8.7" "a,b" "Removable media control needs policy or N/A" "Interview/SSP" || record WARN "MP.L2-3.8.7" "a,b" "Document removable media as not used/N/A if true" "Interview/SSP"
contains "$MAIN" "incident|incident_reports|incident_actions" && record PASS "IR.L2-3.6.1" "a-c" "Incident handling/reporting workflow appears present" "Examine/Test" || record WARN "IR.L2-3.6.1" "a-c" "Need incident handling document or app evidence" "Examine"
contains "$MAIN" "incident_reports|report_incident|incident" && record PASS "IR.L2-3.6.2" "a,b" "Incident reporting evidence appears present" "Examine/Test" || record WARN "IR.L2-3.6.2" "a,b" "Need incident reporting process evidence" "Interview"
contains "$MAIN" "incident.*test|tabletop|training" && record WARN "IR.L2-3.6.3" "a,b" "Incident response testing requires tabletop/test record" "Interview/Examine" || record WARN "IR.L2-3.6.3" "a,b" "Attach tabletop or demo test record" "Examine"
contains "$MAIN" "maintenance|maintainer|maintenance_log" && record PASS "MA.L2-3.7.1" "a-d" "Maintenance activity evidence appears present" "Examine" || record WARN "MA.L2-3.7.1" "a-d" "Need maintenance log/procedure evidence" "Examine"
contains "$MAIN" "nonlocal|remote maintenance|mfa" && record WARN "MA.L2-3.7.5" "a-d" "Remote maintenance MFA requires SSH/Entra evidence" "Test" || record WARN "MA.L2-3.7.5" "a-d" "Provide SSH key-only + MFA/authorized admin explanation" "Interview/Test"
contains "$MAIN" "vulnerab|scan|remediation|risk" && record PASS "RA.L2-3.11.1-3" "All" "Risk/vulnerability scan/remediation evidence appears present" "Examine" || record WARN "RA.L2-3.11.1-3" "All" "Need vulnerability scan and remediation records" "Examine/Test"
contains "$MAIN" "screen|personnel|termination|transfer|disable" && record WARN "PS.L2-3.9.1-2" "All" "Personnel security is mostly policy/admin process evidence" "Interview/Examine" || record WARN "PS.L2-3.9.1-2" "All" "Need screening/termination access-change policy or academic N/A" "Interview/Examine"
contains "$MAIN" "physical|facility|Azure datacenter|visitor" && record WARN "PE.L2-3.10.1-6" "All" "Physical protection likely inherited from Azure; attach Azure responsibility statement" "SSP/Interview" || record WARN "PE.L2-3.10.1-6" "All" "Document physical protection as Azure inherited/shared responsibility" "SSP/Interview"

section "8. SECURITY ASSESSMENT (CA), AWARENESS/TRAINING (AT), AND SSP"
[[ -f "$APP_DIR/SSP.md" || -f "$APP_DIR/System_Security_Plan.md" || -f "$APP_DIR/docs/SSP.md" ]] && record PASS "CA.L2-3.12.4" "a,b" "System Security Plan file found" "Examine" || record WARN "CA.L2-3.12.4" "a,b" "SSP file not found in repo; attach final SSP document" "Examine"
[[ -f "$APP_DIR/SECURITY.md" || -f "$APP_DIR/docs/security_policy.md" ]] && record PASS "CA.L2-3.12.4" "a,b" "Security policy documentation found" "Examine" || record WARN "CA.L2-3.12.4" "a,b" "Security policy file not found; attach policy document" "Examine"
record PASS "CA.L2-3.12.1" "a,b" "This script executed a technical security-control assessment and generated findings" "Test"
[[ -f "$APP_DIR/POAM.md" || -f "$APP_DIR/docs/POAM.md" ]] && record PASS "CA.L2-3.12.2" "a,b" "Operational plan of action file found" "Examine" || record WARN "CA.L2-3.12.2" "a,b" "POA&M/operational plan not found; add if any gaps remain" "Examine"
contains "$MAIN" "training|awareness|role-based" && record PASS "AT.L2-3.2.1-3" "All" "Training/awareness evidence appears present in app/code" "Examine" || record WARN "AT.L2-3.2.1-3" "All" "Training controls need training records/slides/signoff" "Examine/Interview"

section "9. LIVE RUNTIME SMOKE TESTS"
if command -v ss >/dev/null 2>&1 && ss -ltnp 2>/dev/null | grep -q '127.0.0.1:8000'; then record PASS "Runtime" "Network" "App backend listening on 127.0.0.1:8000" "Test"; else record WARN "Runtime" "Network" "Could not confirm backend listening on 127.0.0.1:8000" "Test"; fi
if curl -k -I -s --max-time 5 https://localhost | head -n 1 | grep -Eiq 'HTTP/'; then record PASS "SC.L2-3.13.8" "Test" "HTTPS endpoint responds locally" "Test"; curl -k -I -s --max-time 5 https://localhost | head -n 8 | tee -a "$RAW"; else record WARN "SC.L2-3.13.8" "Test" "HTTPS localhost endpoint did not respond" "Test"; fi
if curl -I -s --max-time 5 http://127.0.0.1:8000 | head -n 1 | grep -Eiq 'HTTP/'; then record PASS "Runtime" "Backend" "Backend responds on localhost" "Test"; else record WARN "Runtime" "Backend" "Backend did not respond directly on localhost" "Test"; fi
if command -v fail2ban-client >/dev/null 2>&1 && sudo fail2ban-client status sshd >/dev/null 2>&1; then record PASS "AC.L2-3.1.8" "SSH" "Fail2Ban sshd jail active" "Test"; else record WARN "AC.L2-3.1.8" "SSH" "Fail2Ban sshd jail not confirmed" "Test"; fi
if [[ -f /etc/ssh/sshd_config ]] && grep -Eiq '^PasswordAuthentication no|PasswordAuthentication no' /etc/ssh/sshd_config; then record PASS "AC.L2-3.1.12" "SSH" "SSH password authentication disabled" "Examine/Test"; else record WARN "AC.L2-3.1.12" "SSH" "SSH password authentication setting not confirmed" "Examine/Test"; fi

section "10. OBJECTIVE-LEVEL MANUAL EVIDENCE REMINDERS"
record INFO "MANUAL" "Guide" "For every WARN, attach screenshot/policy/interview note before final submission" "Examine/Interview/Test"
record INFO "MANUAL" "Findings" "Mark MET only when all applicable objectives are satisfied; otherwise NOT MET or N/A with reason" "Assessment Judgment"
record INFO "MANUAL" "N/A" "Wireless/mobile/VoIP/physical/personnel controls may be N/A or inherited only if documented in SSP" "SSP"

section "11. SUMMARY"
line "PASS: $PASS"
line "WARN: $WARN"
line "FAIL: $FAIL"
line "INFO: $INFO"
line ""
line "Markdown report: $REPORT"
line "Raw output file: $RAW"
line ""
line "Recommended command for demo/submission:"
line "  ./securevault_cmmc_objective_audit.sh | tee final_terminal_evidence.txt"

cat >> "$REPORT" <<SUM

## Summary

- PASS: $PASS
- WARN: $WARN
- FAIL: $FAIL
- INFO: $INFO

## Interpretation

- **PASS** = technical evidence was found by the script.
- **WARN** = manual evidence, screenshot, policy, interview, SSP statement, or N/A justification is required.
- **FAIL** = expected technical evidence was not found and should be fixed or documented.

## Recommended Use

Run:

\`\`\`bash
./securevault_cmmc_objective_audit.sh | tee final_terminal_evidence.txt
\`\`\`

Attach this Markdown report, raw output, screenshots, SSP, and the FR-1 to FR-67 mapping table as the auditor evidence package.
SUM
