# System Security Plan (SSP)
SecureVault – CMMC Level 2 Secure File Storage System

## 1. System Overview

The SecureVault system is a cloud-hosted secure file storage web application designed to protect Controlled Unclassified Information (CUI). The system enforces authentication, role-based access control, encryption at rest and in transit, and audit logging aligned with CMMC Level 2 security requirements.

---

## 2. System Boundary

The system boundary includes:

- Flask web application (main.py)
- SQLite database (files.db)
- Encrypted file storage directory (uploads/)
- Authentication and RBAC logic
- Azure cloud infrastructure components
- Encryption utilities (crypto_utils.py)

These components collectively support secure storage, processing, and transmission of CUI within the SecureVault environment.

---

## 3. Environment of Operation

The SecureVault system operates in:

- Microsoft Azure Virtual Machine environment
- Linux-based host operating system
- Python runtime with Flask framework
- Secure HTTPS-based access
- Controlled administrator-managed deployment

The environment supports secure processing, storage, and transmission of protected data.

---

## 4. Security Requirement Implementation

Security requirements are implemented through:

- Role-Based Access Control (admin / user roles)
- Argon2 password hashing
- AES encryption for file storage
- Session security protections
- Access control enforcement for file ownership and sharing
- Authentication-required access to protected routes
- Rate limiting on login endpoints
- Secure cookie configuration

These controls support compliance with CMMC Level 2 access control and authentication requirements.

---

## 5. Connections to External Systems

SecureVault connects to the following external and supporting systems:

- Microsoft Azure Virtual Machine hosting the application environment
- Azure Virtual Network providing network isolation and routing
- Azure Storage components used for encrypted file persistence
- Linux operating system services supporting runtime execution
- Internal authentication and role-based access control mechanisms

These connections define the operational trust boundary of the SecureVault system.

---

## 6. Non-Applicable Security Requirements

Any security requirements determined to be not applicable are documented separately in the project control mapping documentation and approved by project stakeholders.

---

## 7. Roles and Responsibilities

Roles within the SecureVault system include:

Administrator:
- manages users
- assigns permissions
- reviews system configuration

Standard User:
- uploads files
- accesses authorized shared files
- downloads permitted resources

---

## 8. SSP Update Frequency

## 8. SSP Review and Update Policy

The SecureVault System Security Plan (SSP) is reviewed at least annually and whenever significant changes occur to:

- system architecture
- cloud infrastructure
- authentication mechanisms
- encryption configuration
- access control policies
- deployment environment

The system administrator is responsible for maintaining the SSP and ensuring updates reflect the current operational security posture of the system.

Last Review Date:
April 2026

Next Scheduled Review:
April 2027



## Session Termination Policy (AC.L2-3.1.11)

SecureVault automatically terminates user sessions after 15 minutes of inactivity.

Session timeout enforcement is implemented using Flask session lifetime configuration:

- permanent session enabled after authentication
- inactivity timeout set to 15 minutes
- session termination requires re-authentication

This mechanism prevents unauthorized access from unattended authenticated sessions and supports compliance with CMMC Level 2 control AC.L2-3.1.11.
