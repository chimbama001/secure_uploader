# CMMC Level 2 Secure File Management Web Application

## Project Overview
This project is an academic Senior Design demonstration of a secure file management web application aligned with **CMMC Level 2** and **NIST SP 800-171** security controls.

⚠️ **Important Notice**
This system is developed **for academic purposes only** and does **NOT** represent an official CMMC certification or assessment.

## Key Objectives
- Demonstrate implementation of 67 scoped CMMC Level 2 security controls
- Provide audit-ready evidence and testing procedures
- Use secure-by-design principles in a cloud-hosted environment

## Technology Stack
- Backend: Python (Flask)
- Database: SQLite
- Encryption:
  - File encryption: AES-GCM
  - Password hashing: Argon2
- Authentication: Role-Based Access Control (Admin / User)
- Hosting: Azure Virtual Machine


## System Security Plan (SSP)

The SecureVault System Security Plan (SSP) is located at:

docs/SSP.md
docs/SSP.docx

This document describes system boundaries, environment of operation,
security control implementation methods, external system relationships,
and SSP review/update procedures in alignment with CMMC Level 2 control
CA.L2-3.12.4.


## Development & Testing Workflow
Azure CLI → SSH → Git Pull → Run → Test

## Status
🚧 Project initialization phase 
