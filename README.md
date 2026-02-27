# 🦅 BlueFalconInk — CISA ED 26-03 Compliance Tracker

[![Generate Architecture Docs](https://github.com/bluefalconink/cisa-ed-26-03-tracker/actions/workflows/generate-docs.yml/badge.svg)](https://github.com/bluefalconink/cisa-ed-26-03-tracker/actions/workflows/generate-docs.yml)

**Built by [BlueFalconInk LLC](https://github.com/bluefalconink)** | [MIT License](LICENSE)

A rapid-response compliance tool for Federal Agencies and enterprises to meet the mandates of **CISA Emergency Directive 26-03** regarding Cisco SD-WAN vulnerabilities (CVE-2026-20127 & CVE-2022-20775).

Developed in collaboration with joint guidance from **NSA, CISA, ASD's ACSC, Canadian Cyber Centre, NCSC-NZ,** and **NCSC-UK**.

---

## 🚨 Critical Deadlines

| Milestone             | Deadline                     |
|-----------------------|------------------------------|
| **Inventory**         | February 26, 2026 — 11:59 PM ET |
| **Patching**          | February 27, 2026 — 5:00 PM ET  |
| **Final Report**      | March 5, 2026                |

---

## ✨ Features

- **Live Deadline Countdowns** — Real-time urgency tracking for Inventory, Patch, and Report deadlines
- **Dashboard Metrics** — At-a-glance counts: Total Assets, Forensics Complete, Patched, Hunt Complete, Hardened
- **Asset Registration** — Manual single-asset entry with hostname, IP, system type, version, and notes
- **Bulk Import** — One-click import from **CSV, Excel (.xlsx), JSON, or TSV** with intelligent column matching via regex, duplicate detection, and preview
- **5-Step Compliance Workflow** — Per-asset tracking across Inventory → Forensics (3 artifacts) → Patch → Hunt (6-point checklist) → Hardening
- **Forensic Gate Enforcement** — Patching is blocked until all 3 forensic artifacts are captured
- **6-Point Threat Hunt Checklist** — OMP peers, control connections, user accounts, version downgrade, audit logs, config changes
- **Integrated Threat Hunt Guide** — Attack chain / kill chain phases, CLI command reference, IOC table, hunt decision flowchart
- **Hunt Findings Log** — Log individual IOC findings with category, severity, description, evidence, and analyst attribution
- **CISA Reporting Engine** — One-click JSON export (includes hunt checklist + findings) and CSV export for the March 5 deadline
- **Docker Ready** — Containerized for Google Cloud Run with IAP security

---

## 🚀 Quick Start (Local)

1. **Clone & Setup:**
   ```bash
   git clone https://github.com/bluefalconink/cisa-ed-26-03-tracker.git
   cd cisa-ed-26-03-tracker
   python -m venv venv
   source venv/bin/activate      # Linux/macOS
   venv\Scripts\activate         # Windows
   pip install -r requirements.txt
   ```

2. **Launch:**
   ```bash
   streamlit run app.py
   ```
   The app will automatically create the SQLite database (`compliance_data.db`) on first run.

---

## 📥 Bulk Asset Import

Import your existing asset inventory from any common format:

| Format | Extension | Notes |
|--------|-----------|-------|
| CSV | `.csv` | Comma-separated |
| Excel | `.xlsx` | First sheet is read |
| JSON | `.json` | Array of objects or records-oriented |
| TSV | `.tsv` / `.txt` | Tab-separated |

**Column matching** uses flexible regex patterns — your columns don't need exact names. For example, `host_name`, `Hostname`, or `device_name` all map to the hostname field. Duplicate assets (matching hostname + IP) are automatically skipped.

---

## ☁️ Production Deployment (Google Cloud Run)

Deploy in a secure, production-ready state in under 10 minutes:

### Step 1: Build the Container
```bash
gcloud builds submit --tag gcr.io/$GOOGLE_CLOUD_PROJECT/cisa-tracker .
```

### Step 2: Deploy to Cloud Run
```bash
gcloud run deploy cisa-tracker \
  --image gcr.io/$GOOGLE_CLOUD_PROJECT/cisa-tracker \
  --platform managed \
  --region us-east1 \
  --no-allow-unauthenticated
```

### Step 3: Secure with Identity-Aware Proxy (IAP)
1. Navigate to **Security > Identity-Aware Proxy** in the GCP Console.
2. Enable IAP for the `cisa-tracker` service.
3. Add your agency's user group as **IAP-secured Web App User**.

---

## 📝 Compliance Workflow (CISA 5-Step Action Sequence)

According to ED 26-03 and the Supplemental Direction:

| Step | Action | Details |
|------|--------|---------|
| **1. Inventory** | Log all `vManage` and `vSmart` instances | By Feb 26, 11:59 PM ET |
| **2. Collect Artifacts** | VM snapshots, core dumps (`/opt`, `/var`), `/home` copies | **Before** patching (enforced in UI) |
| **3. Patch** | Apply Cisco updates | By Feb 27, 5:00 PM ET — Versions: `20.12.6.1+`, `20.15.4.2+`, `20.18.2.1+` |
| **4. Hunt** | 6-point threat hunt checklist per asset | OMP peers, control connections, users, version, logs, config |
| **5. Implement** | Hardening per Cisco SD-WAN Hardening Guide | Restrict exposure, isolate mgmt planes, enhance logging |

---

## 🔍 Threat Hunt Guide

The app includes an embedded **Threat Hunt Guide** based on the joint guidance from CISA, NSA, and Five Eyes partners:

- **Attack Chain** — Kill chain phases from initial access (CVE-2026-20127) through lateral movement
- **CLI Commands** — 7 reference commands with expected-vs-suspicious output guidance
- **IOC Reference** — Network-level and host-level indicators of compromise
- **Decision Flowchart** — Step-by-step hunt decision workflow

---

## 📊 Data Persistence

This app uses **SQLite** by default for immediate deployment. For long-term multi-region persistence, update the connection string in `database.py` to point to a **Google Cloud SQL (PostgreSQL)** instance:

```python
engine = create_engine('postgresql://user:pass@host/dbname')
```

---

## 📂 Project Structure

```
cisa-ed-26-03-tracker/
├── .github/
│   └── workflows/
│       └── generate-docs.yml    # GitHub Actions: auto-generate architecture docs
├── app.py                       # Main Streamlit application (920 lines)
├── database.py                  # SQLAlchemy 2.0 ORM models & session factory
├── requirements.txt             # Python dependencies
├── Dockerfile                   # Container configuration (python:3.11-slim)
├── PRD_ED_26_03.md              # Product Requirements Document
├── ARCHITECTURE.md              # Auto-generated architecture documentation
├── LICENSE                      # MIT License
├── .gitignore                   # Python / SQLite / IDE ignores
├── ACSC-led Cisco SD-WAN Hunt Guide.pdf  # Official joint threat hunt guide
└── README.md                    # This file
```

---

## 🗄️ Database Schema

### `inventory` (SDWANInstance)
Tracks each Cisco SD-WAN asset through the full 5-step compliance lifecycle:
- Identity: `hostname`, `ip_address`, `sys_type`, `version`
- Forensics: `snapshot_captured`, `core_dump_captured`, `home_dir_copied`, `forensics_captured`
- Patching: `patch_applied`
- Hunt: 6 individual checklist booleans + `hunt_completed` (auto-calculated)
- Hardening: `hardening_implemented`
- Metadata: `notes`, `timestamp`, `last_updated`

### `hunt_findings` (HuntFinding)
Individual IOC findings linked to assets:
- `asset_id` (FK → inventory), `category`, `severity`, `description`, `evidence`, `analyst`, `timestamp`

---

## 🔒 Security Notes

- **Never** deploy with `--allow-unauthenticated` in production.
- Use **Identity-Aware Proxy (IAP)** to gate access behind organizational SSO.
- Forward all SD-WAN logs to a remote, external syslog server.
- Isolate SD-WAN management planes on dedicated, trusted networks.
- Restrict SD-WAN control components behind firewalls with IP allowlists.

---

## 🦅 About BlueFalconInk LLC

BlueFalconInk LLC builds rapid-response cybersecurity compliance tooling for federal agencies and the broader security community. This project is open-source and freely available to support emergency directive response.

**GitHub:** [github.com/bluefalconink](https://github.com/bluefalconink)  
**License:** MIT
