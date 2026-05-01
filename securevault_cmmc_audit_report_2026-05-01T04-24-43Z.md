# SecureVault CMMC Level 2 Objective-Based Audit Report

**Generated:** 2026-05-01T04:24:43Z  
**Host:** secure-vault-vm  
**Application Directory:** /home/mohammed/secure_uploader  
**Database:** /srv/secure_uploader_data/files.db  
**Auditor:** Mohammed Alruwaili  

> This report is technical evidence for the Senior Design SecureVault project. It supports CMMC Level 2 style assessment using Examine, Interview, and Test methods. It does not claim official CMMC certification.

| Control / FR | Objective | Method | Finding | Evidence |
|---|---|---|---|---|
| BASELINE | Scope | Examine | PASS | Application directory detected: /home/mohammed/secure_uploader |
| BASELINE | File | Examine | PASS | main.py exists |
| BASELINE | File | Examine | PASS | crypto_utils.py exists |
| BASELINE | Config | Examine | WARN | .env not found in app dir; may be configured via systemd/Azure |
| BASELINE | Service | Examine | PASS | systemd unit exists: /etc/systemd/system/secureuploader.service |
| BASELINE | Runtime | Test | PASS | secureuploader.service is active |
| BASELINE | Syntax | Test | PASS | main.py passes python syntax check |
| AC.L2-3.1.1 | a,d | Examine/Test | PASS | Authorized users are identified and protected routes require login/session |
| AC.L2-3.1.1 | c,f | Examine | PASS | File/device/resource authorization logic appears present using owner/share/access fields |
| AC.L2-3.1.2 | a,b | Examine/Test | PASS | User roles/functions are defined and access appears role-restricted |
| AC.L2-3.1.3 | a-e | Examine/Test | PASS | CUI/file flow is controlled through upload/download/share/delete routes and access checks |
| AC.L2-3.1.4 | a-c | Examine | PASS | Separation of admin and standard user duties appears implemented |
| AC.L2-3.1.5 | a-d | Examine/Test | PASS | Least privilege evidence found through admin/owner/share restrictions |
| AC.L2-3.1.6 | a,b | Examine | PASS | Non-security/standard user role separation appears present |
| AC.L2-3.1.7 | a-d | Examine/Test | PASS | Privileged functions appear blocked for non-privileged users and loggable |
| AC.L2-3.1.8 | a,b | Examine/Test | PASS | Failed login limitation/rate limiting evidence found |
| AC.L2-3.1.9 | a,b | Examine/Test | PASS | Privacy/security notice or onboarding banner evidence appears present |
| AC.L2-3.1.10 | a-c | Examine/Test | PASS | Session inactivity lock/timeout configuration appears present |
| AC.L2-3.1.11 | a,b | Examine/Test | PASS | Session termination condition and logout/session clear evidence found |
| AC.L2-3.1.12 | a-d | Examine/Test | PASS | Remote access/session activity appears monitored through IP/user audit logging |
| AC.L2-3.1.14 | a,b | Examine/Test | PASS | Remote/app access routed through managed reverse proxy to localhost backend |
| AC.L2-3.1.15 | a-d | Examine | PASS | Privileged remote admin/security access appears role-restricted |
| AC.L2-3.1.16-19 | All | Interview/SSP | WARN | No wireless/mobile app evidence; document N/A or inherited/not used in SSP |
| AC.L2-3.1.20 | a-f | Examine | PASS | External/cloud service use appears identified through Azure Blob/Key Vault configuration |
| AC.L2-3.1.22 | a,b | Interview/Examine | WARN | Public information control needs manual content review and approval evidence |
| IA.L2-3.5.1 | a-d | Examine/Test | PASS | Users are uniquely identified by username/user_id/OIDC identifiers |
| IA.L2-3.5.2 | a,b | Examine/Test | PASS | Authentication mechanism/password verification/OIDC evidence found |
| IA.L2-3.5.3 | a-d | Examine/Test | PASS | MFA/OIDC/Entra or TOTP evidence appears present |
| IA.L2-3.5.4 | a,b | Examine/Test | PASS | Replay-resistant token/state/CSRF/SameSite evidence found |
| IA.L2-3.5.8 | a,b | Examine | WARN | Password reuse prevention not found; document if handled by Entra or not implemented |
| IA.L2-3.5.9 | a-c | Interview/SSP | WARN | Temporary password handling not found; document as N/A if no temp passwords used |
| IA.L2-3.5.10 | a,b | Examine/Test | PASS | Passwords appear cryptographically protected using hashing |
| IA.L2-3.5.11 | a,b | Examine | PASS | Password input/obscuring evidence appears present in templates or inline HTML |
| AU.L2-3.3.1 | a-d | Examine/Test | PASS | Audit record generation logic found |
| AU.L2-3.3.2 | a,b | Examine/Test | PASS | Audit records appear linked to user/time/IP |
| AU.L2-3.3.3 | a,b | Examine/Test | PASS | Admin audit log review functionality appears present |
| AU.L2-3.3.4 | a,b | Test | WARN | Audit failure handling/alerting may need manual validation |
| AU.L2-3.3.5 | a,b | Examine | PASS | Audit fields support correlation by user/IP/file/event |
| AU.L2-3.3.6 | a,b | Examine/Test | PASS | Audit review/reporting functionality appears present |
| AU.L2-3.3.7 | a,b | Test | PASS | System time synchronization is active |
| AU.L2-3.3.8 | a,b | Examine | PASS | Audit DB located at /srv/secure_uploader_data/files.db; check file permissions below |
| AU.L2-3.3.9 | a,b | Examine/Test | PASS | Audit management/review appears restricted to admin |
| CM.L2-3.4.1 | a-c | Examine | PASS | Git repository provides configuration baseline/history |
| CM.L2-3.4.1 | a-c | Examine | PASS | Dependency baseline file exists |
| CM.L2-3.4.6 | a,b | Examine | PASS | .gitignore excludes secrets/local DB/venv/uploads |
| CM.L2-3.4.3 | a-e | Examine | PASS | Recent git change history available |
| CM.L2-3.4.7 | a,b | Examine | PASS | No obvious dangerous user-facing execution functions found |
| CM.L2-3.4.8 | a,b | Examine/Test | PASS | Upload constraints/application behavior controls appear present |
| CM.L2-3.4.9 | a,b | Interview/Examine | WARN | Need policy/OS evidence restricting user-installed software |
| SC.L2-3.13.16 | a,b | Examine/Test | PASS | Data-at-rest encryption implementation appears present |
| SC.L2-3.13.10 | a-c | Examine/Test | PASS | Key management evidence found through Key Vault/env key handling |
| SC.L2-3.13.11 | a,b | Examine | PASS | Cryptographic mechanism evidence appears present |
| SC.L2-3.13.8 | a,b | Examine/Test | PASS | Nginx TLS/HTTPS reverse proxy evidence found |
| SC.L2-3.13.1 | a,b | Examine/Test | PASS | Backend bound to localhost behind boundary/reverse proxy |
| SC.L2-3.13.6 | a,b | Test | PASS | UFW firewall active |
| SC.L2-3.13.12 | a,b | Interview/SSP | WARN | If no collaboration devices are used, document as N/A in SSP |
| SC.L2-3.13.13 | a,b | Interview | WARN | Mobile code requires policy/config evidence |
| SC.L2-3.13.14 | a,b | Interview/SSP | WARN | Need N/A statement if VoIP not in scope |
| SC.L2-3.13.15 | a,b | Examine/Test | PASS | Communication authenticity/token evidence appears present |
| DB | Source | Examine | PASS | SQLite database exists: /srv/secure_uploader_data/files.db |
| IA/AC | Schema | Examine | PASS | users table exists |
| IA.L2-3.5.1 | a | Examine | PASS | users table contains unique identifier field |
| IA.L2-3.5.10 | a | Examine | PASS | users table stores password hash, not plaintext |
| AC.L2-3.1.2 | a,b | Examine | PASS | users table contains role/admin field |
| AC.L2-3.1.8 | a,b | Examine | WARN | failed login/lockout DB fields not found; maybe limiter-only |
| AC.L2-3.1.1 | a,d | Examine | PASS | files table contains ownership field |
| AC.L2-3.1.2 | b | Examine | PASS | file_access table supports shared authorization |
| AU.L2-3.3.1 | a-d | Examine | PASS | audit log table exists |
| MP.L2-3.8.9 | a,b | Examine | WARN | backup_records table not found |
| MP.L2-3.8.9 | a-c | Examine/Test | PASS | Backup/storage functionality appears present |
| MP.L2-3.8.3 | a,b | Examine/Test | PASS | Media/file disposal/delete logic appears present |
| MP.L2-3.8.7 | a,b | Interview/SSP | WARN | Document removable media as not used/N/A if true |
| IR.L2-3.6.1 | a-c | Examine/Test | PASS | Incident handling/reporting workflow appears present |
| IR.L2-3.6.2 | a,b | Examine/Test | PASS | Incident reporting evidence appears present |
| IR.L2-3.6.3 | a,b | Interview/Examine | WARN | Incident response testing requires tabletop/test record |
| MA.L2-3.7.1 | a-d | Examine | WARN | Need maintenance log/procedure evidence |
| MA.L2-3.7.5 | a-d | Test | WARN | Remote maintenance MFA requires SSH/Entra evidence |
| RA.L2-3.11.1-3 | All | Examine/Test | WARN | Need vulnerability scan and remediation records |
| PS.L2-3.9.1-2 | All | Interview/Examine | WARN | Personnel security is mostly policy/admin process evidence |
| PE.L2-3.10.1-6 | All | SSP/Interview | WARN | Document physical protection as Azure inherited/shared responsibility |
| CA.L2-3.12.4 | a,b | Examine | PASS | System Security Plan file found |
| CA.L2-3.12.4 | a,b | Examine | WARN | Security policy file not found; attach policy document |
| CA.L2-3.12.1 | a,b | Test | PASS | This script executed a technical security-control assessment and generated findings |
| CA.L2-3.12.2 | a,b | Examine | WARN | POA&M/operational plan not found; add if any gaps remain |
| AT.L2-3.2.1-3 | All | Examine | PASS | Training/awareness evidence appears present in app/code |
| Runtime | Network | Test | PASS | App backend listening on 127.0.0.1:8000 |
| SC.L2-3.13.8 | Test | Test | PASS | HTTPS endpoint responds locally |
| Runtime | Backend | Test | PASS | Backend responds on localhost |
| AC.L2-3.1.8 | SSH | Test | PASS | Fail2Ban sshd jail active |
| AC.L2-3.1.12 | SSH | Examine/Test | WARN | SSH password authentication setting not confirmed |
| MANUAL | Guide | Examine/Interview/Test | INFO | For every WARN, attach screenshot/policy/interview note before final submission |
| MANUAL | Findings | Assessment Judgment | INFO | Mark MET only when all applicable objectives are satisfied; otherwise NOT MET or N/A with reason |
| MANUAL | N/A | SSP | INFO | Wireless/mobile/VoIP/physical/personnel controls may be N/A or inherited only if documented in SSP |

## Summary

- PASS: 68
- WARN: 22
- FAIL: 0
- INFO: 3

## Interpretation

- **PASS** = technical evidence was found by the script.
- **WARN** = manual evidence, screenshot, policy, interview, SSP statement, or N/A justification is required.
- **FAIL** = expected technical evidence was not found and should be fixed or documented.

## Recommended Use

Run:

```bash
./securevault_cmmc_objective_audit.sh | tee final_terminal_evidence.txt
```

Attach this Markdown report, raw output, screenshots, SSP, and the FR-1 to FR-67 mapping table as the auditor evidence package.
