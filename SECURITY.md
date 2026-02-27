# 🔒 Security Policy — BlueFalconInk LLC

**Effective Date**: February 2026
**Applies To**: [cisa-ed-26-03-tracker](https://github.com/bluefalconink/cisa-ed-26-03-tracker) and all BlueFalconInk LLC repositories.

---

## Overview

The CISA ED 26-03 Compliance Tracker is a Streamlit-based tool for Federal Agencies and enterprises to track remediation of Cisco SD-WAN vulnerabilities mandated by CISA Emergency Directive 26-03. This document outlines security practices for this repository.

---

## 🛡️ Data Handling

### What This Application Handles

- **Asset inventory data** — hostnames, IP addresses, system types, firmware versions
- **Compliance status** — forensics, patching, threat hunt checklists
- **Hunt findings** — IOC logs with severity, evidence, analyst attribution

### Data Storage

- Data is stored in a **local SQLite database** (`compliance_data.db`) by default.
- The SQLite file is in `.gitignore` and is **never committed** to the repository.
- For production deployments, swap to a managed database (e.g., Cloud SQL) with encryption at rest.

### What We Do NOT Do

- ❌ We do **not** transmit compliance data to external services
- ❌ We do **not** store credentials in the repository
- ❌ We do **not** log or persist raw network configurations

---

## 🔐 Authentication & Secrets

### Container Deployment

- The Docker image is designed for **Google Cloud Run** with **Identity-Aware Proxy (IAP)** for access control.
- All secrets should be stored in **Cloud Run environment variables** or **Secret Manager** — never in repository code.

### GitHub Actions

- All workflow actions are **pinned to SHA hashes** to prevent supply-chain attacks.
- Repository secrets are stored in **GitHub Actions Secrets** — never in code.

---

## 🏗️ Infrastructure Security

### Container Security

- Docker images use `python:3.11-slim` with minimal attack surface.
- Containers run as a **non-root user** (`appuser`) — enforced via `USER` directive in the Dockerfile.
- A Docker `HEALTHCHECK` instruction is defined for liveness monitoring.
- Container images are scanned for vulnerabilities using **Trivy** (CRITICAL/HIGH) in CI.

### Automated Security Scanning (CSIAC Governance)

| Tool | Type | Trigger | Target |
|------|------|---------|--------|
| **Bandit** | SAST (Static Analysis) | Push/PR to `master` | All Python code |
| **pip-audit + Safety** | Dependency Scanning | Push/PR to `master` | `requirements.txt` |
| **Trivy** | Container Scanning | Push/PR to `master` | Application Docker image |
| **Dependabot** | Dependency Updates | Weekly (Monday) | Python packages + GitHub Actions |

Results are uploaded to the GitHub **Security** tab as SARIF for centralized triage.

### Network Security

- Cloud Run enforces **HTTPS-only** connections (TLS managed by Google).
- The application should be deployed behind **IAP** for authenticated access.

---

## 📋 Compliance Notes

This tool itself supports compliance with CISA ED 26-03. The tool does not collect, process, or store PII beyond what the operator enters into the inventory.

All compliance data (asset inventory, hunt findings, reports) is stored locally in the operator's environment and is under the operator's control.

---

## 🐛 Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

1. **Do NOT** open a public GitHub issue for security vulnerabilities.
2. Email **security@bluefalconink.com** with a detailed description.
3. We will acknowledge receipt within **48 hours**.
4. We aim to provide a fix within **7 business days**.

### Scope

This policy covers:
- The `cisa-ed-26-03-tracker` repository and all application code
- The Dockerized deployment configuration
- CI/CD pipelines and GitHub Actions workflows

---

## 📄 License

This security policy applies to all BlueFalconInk LLC repositories.

**© BlueFalconInk LLC. All rights reserved.**
