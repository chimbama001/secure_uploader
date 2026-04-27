#!/usr/bin/env bash
set -u

APP_DIR="/home/secureuploader/secure_uploader"
ENV_FILE="$APP_DIR/.env"
DB_FILE="$APP_DIR/files.db"
MAIN_FILE="$APP_DIR/main.py"

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

AO_A_PASS=0
AO_B_PASS=0

pass() {
  echo "[PASS] $1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  echo "[FAIL] $1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
  echo "[WARN] $1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

section() {
  echo
  echo "============================================================"
  echo "$1"
  echo "============================================================"
}

section "AC.L2-3.1.8 - UNSUCCESSFUL LOGON ATTEMPTS"

# ------------------------------------------------------------
# 1. Check defined threshold in .env
# ------------------------------------------------------------
section "1) CHECK DEFINED THRESHOLD"

if [[ -f "$ENV_FILE" ]]; then
  pass ".env exists"
else
  fail ".env missing"
fi

MAX_FAILED_ATTEMPTS=$(grep '^MAX_FAILED_ATTEMPTS=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)
LOCKOUT_MINUTES=$(grep '^LOCKOUT_MINUTES=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)

if [[ -n "${MAX_FAILED_ATTEMPTS:-}" ]]; then
  pass "MAX_FAILED_ATTEMPTS is defined: $MAX_FAILED_ATTEMPTS"
else
  fail "MAX_FAILED_ATTEMPTS is not defined"
fi

if [[ -n "${LOCKOUT_MINUTES:-}" ]]; then
  pass "LOCKOUT_MINUTES is defined: $LOCKOUT_MINUTES"
else
  fail "LOCKOUT_MINUTES is not defined"
fi

# ------------------------------------------------------------
# 2. Check code references for lockout logic
# ------------------------------------------------------------
section "2) CHECK CODE REFERENCES"

if [[ -f "$MAIN_FILE" ]]; then
  pass "main.py exists"
else
  fail "main.py missing"
fi

grep -q "failed_login_count" "$MAIN_FILE" 2>/dev/null && pass "main.py references failed_login_count" || fail "main.py does not reference failed_login_count"
grep -q "locked_until" "$MAIN_FILE" 2>/dev/null && pass "main.py references locked_until" || fail "main.py does not reference locked_until"
grep -q "MAX_FAILED_ATTEMPTS" "$MAIN_FILE" 2>/dev/null && pass "main.py references MAX_FAILED_ATTEMPTS" || fail "main.py does not reference MAX_FAILED_ATTEMPTS"
grep -q "LOCKOUT_MINUTES" "$MAIN_FILE" 2>/dev/null && pass "main.py references LOCKOUT_MINUTES" || fail "main.py does not reference LOCKOUT_MINUTES"

# ------------------------------------------------------------
# 3. Check database schema for lockout fields
# ------------------------------------------------------------
section "3) CHECK DATABASE SCHEMA"

if [[ -f "$DB_FILE" ]]; then
  pass "Database file exists"
else
  fail "Database file missing"
fi

SCHEMA_OUTPUT=$(sudo -u secureuploader sqlite3 "$DB_FILE" "PRAGMA table_info(users);" 2>/dev/null)

echo "$SCHEMA_OUTPUT" | grep -q "failed_login_count" && pass "users table includes failed_login_count" || fail "users table missing failed_login_count"
echo "$SCHEMA_OUTPUT" | grep -q "locked_until" && pass "users table includes locked_until" || fail "users table missing locked_until"
echo "$SCHEMA_OUTPUT" | grep -q "last_failed_login" && pass "users table includes last_failed_login" || warn "users table missing last_failed_login"

# ------------------------------------------------------------
# 4. Live application test
# ------------------------------------------------------------
section "4) LIVE LOCKOUT TEST"

LOGIN_URL="http://127.0.0.1:8000/login"
TEST_USER="${TEST_LOCKOUT_USER:-lockouttest}"
TEST_PASS="${TEST_LOCKOUT_PASSWORD:-WrongPassword123!}"

# check app reachable
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/ || true)
if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "302" ]]; then
  pass "App is reachable on 127.0.0.1:8000"
else
  fail "App is not reachable on 127.0.0.1:8000"
fi

if [[ -n "${MAX_FAILED_ATTEMPTS:-}" ]]; then
  ATTEMPTS=$((MAX_FAILED_ATTEMPTS + 1))
else
  ATTEMPTS=4
fi

echo "Using test username: $TEST_USER"
echo "Running $ATTEMPTS failed login attempts against $LOGIN_URL"

LOCKOUT_EVIDENCE=0
for i in $(seq 1 "$ATTEMPTS"); do
  RESP=$(curl -s -i -X POST "$LOGIN_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    --data "username=$TEST_USER&password=$TEST_PASS")
  echo "--- Attempt $i complete ---"

  echo "$RESP" | grep -Eiq "locked|too many|try again|unsuccessful|invalid" && LOCKOUT_EVIDENCE=1
done

if [[ "$LOCKOUT_EVIDENCE" -eq 1 ]]; then
  pass "Application returned evidence of unsuccessful-login handling/lockout messaging"
else
  warn "No explicit lockout text observed in HTTP response"
fi

# ------------------------------------------------------------
# 5. Database evidence for the test user
# ------------------------------------------------------------
section "5) DATABASE EVIDENCE AFTER TEST"

USER_ROW=$(sudo -u secureuploader sqlite3 -header -column "$DB_FILE" \
  "SELECT username, failed_login_count, locked_until, last_failed_login FROM users WHERE username='$TEST_USER';" 2>/dev/null)

if [[ -n "$USER_ROW" ]]; then
  echo "$USER_ROW"
  echo "$USER_ROW" | grep -q "$TEST_USER" && pass "Test user exists in database"

  echo "$USER_ROW" | grep -Eq "[1-9][0-9]*" && pass "Database shows failed login counter activity" || fail "Database does not show failed login counter activity"

  echo "$USER_ROW" | grep -q ":" && pass "Database shows timestamp evidence for lockout or failed login tracking" || warn "No timestamp evidence detected"
else
  warn "Test user not found in database; live DB evidence could not be verified"
fi

# ------------------------------------------------------------
# 6. Assessment objective scoring
# ------------------------------------------------------------
section "6) ASSESSMENT OBJECTIVE SCORING"

# AO[a]: means is defined
if [[ -n "${MAX_FAILED_ATTEMPTS:-}" && -n "${LOCKOUT_MINUTES:-}" ]]; then
  AO_A_PASS=1
  pass "AO[a] PASS - means of limiting unsuccessful logon attempts is defined"
else
  fail "AO[a] FAIL - threshold and/or lockout duration not clearly defined"
fi

# AO[b]: defined means is implemented
IMPLEMENTED_SIGNS=0

grep -q "failed_login_count" "$MAIN_FILE" 2>/dev/null && IMPLEMENTED_SIGNS=$((IMPLEMENTED_SIGNS + 1))
grep -q "locked_until" "$MAIN_FILE" 2>/dev/null && IMPLEMENTED_SIGNS=$((IMPLEMENTED_SIGNS + 1))
echo "$SCHEMA_OUTPUT" | grep -q "failed_login_count" && IMPLEMENTED_SIGNS=$((IMPLEMENTED_SIGNS + 1))
echo "$SCHEMA_OUTPUT" | grep -q "locked_until" && IMPLEMENTED_SIGNS=$((IMPLEMENTED_SIGNS + 1))

if [[ "$IMPLEMENTED_SIGNS" -ge 4 ]]; then
  AO_B_PASS=1
  pass "AO[b] PASS - defined means appears implemented in code and schema"
else
  fail "AO[b] FAIL - implementation evidence is incomplete"
fi

# ------------------------------------------------------------
# 7. Final result
# ------------------------------------------------------------
section "7) FINAL RESULT"

echo "Passes : $PASS_COUNT"
echo "Fails  : $FAIL_COUNT"
echo "Warns  : $WARN_COUNT"

if [[ "$AO_A_PASS" -eq 1 && "$AO_B_PASS" -eq 1 ]]; then
  echo
  echo "FINAL RESULT: MET (technical implementation evidence for AC.L2-3.1.8)"
else
  echo
  echo "FINAL RESULT: NOT MET"
fi
