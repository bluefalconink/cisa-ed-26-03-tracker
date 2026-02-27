# Project Requirements Document: ED 26-03 Compliance Tracker

**Organization:** BlueFalconInk LLC  
**Repository:** [github.com/bluefalconink/cisa-ed-26-03-tracker](https://github.com/bluefalconink/cisa-ed-26-03-tracker)

## 1. Executive Summary

This application is designed for rapid deployment during the ED 26-03 emergency window. It serves as a **single source of truth** for an agency's network and security teams to track asset inventory, forensic collection, patching status, threat hunting, and hardening activities related to Cisco SD-WAN vulnerabilities.

CISA issued Emergency Directive (ED) 26-03 on **February 25, 2026**, titled "Mitigate Vulnerabilities in Cisco SD-WAN Systems," along with **Supplemental Direction ED 26-03: Hunt and Hardening Guidance for Cisco SD-WAN Systems**, in response to the **active exploitation** of critical vulnerabilities in Cisco Catalyst SD-WAN infrastructure.

> *"CISA remains unwavering in its commitment to protect our federal networks from malicious cyber threat actors... The ease with which these vulnerabilities can be exploited demands immediate action from all federal agencies."* — **CISA Acting Director Dr. Madhu Gottumukkala**

### Joint Guidance Authoring Agencies
The directive and associated **Cisco SD-WAN Threat Hunt Guide** were developed in collaboration with:
- **United States National Security Agency (NSA)**
- **United States Cybersecurity and Infrastructure Security Agency (CISA)**
- **Australian Signals Directorate's Australian Cyber Security Centre (ASD's ACSC)**
- **Canadian Centre for Cyber Security (Cyber Centre)**
- **New Zealand National Cyber Security Centre (NCSC-NZ)**
- **United Kingdom National Cyber Security Centre (NCSC-UK)**

---

## 2. Key Vulnerabilities

| CVE | Description | Severity |
|-----|-------------|----------|
| **CVE-2026-20127** | Zero-day authentication bypass in SD-WAN peering (vManage/vSmart). Allows unauthenticated remote attackers to gain admin-level access. | **Critical** |
| **CVE-2022-20775** | Privilege escalation used in conjunction with initial bypass for full ROOT access. | **High** |

Evidence suggests exploitation may have begun as early as 2023.

---

## 3. Critical Deadlines & CISA 5-Step Action Sequence

CISA and the authoring organizations direct agencies to **immediately**:

| Step | Action | Deadline / Timing |
|------|--------|-------------------|
| **1. Inventory** | All in-scope Cisco SD-WAN systems | Feb 26, 2026 — 11:59 PM ET |
| **2. Collect Artifacts** | Virtual snapshots, core dumps, and logs of SD-WAN systems | Before patching |
| **3. Patch** | Cisco SD-WAN systems for CVE-2026-20127 & CVE-2022-20775 | Feb 27, 2026 — 5:00 PM ET |
| **4. Hunt** | For evidence of compromise (see Supplemental Direction) | Ongoing |
| **5. Implement** | As outlined in Cisco's Catalyst SD-WAN Hardening Guide | Ongoing |
| **Final Report** | Submit detailed completion report and inventory to CISA | March 5, 2026 |

---

## 4. Functional Requirements

### A. Asset Inventory Management
- **Single Point of Entry:** Log `vManage` and `vSmart` instances with hostname, IP address, software version, and environment notes.
- **Real-time Visibility:** Shared dashboard where multiple engineers can view the current inventory status.
- **Metrics Dashboard:** At-a-glance counts of total assets, forensics completion, patch status, hunt completion, and hardening status.
- **Bulk Import:** One-click import from CSV, Excel (.xlsx), JSON, or TSV files with:
  - Intelligent regex-based column matching (e.g., `host_name`, `Hostname`, `device_name` all map to hostname)
  - Automatic duplicate detection (matching hostname + IP address)
  - Preview table before committing import
  - Support for flexible column naming across agency inventory exports

### B. Forensic Workflow Enforcement
- **Strict Sequencing:** The UI must enforce that forensic capture (snapshots/core dumps/home directories) is completed and verified **before** the system can be marked as "Patched."
- **Granular Artifact Tracking:** Individual checkboxes for:
  - VM Snapshot captured
  - Admin Core Dump (`/opt`, `/var`) exported
  - `/home` directory copy secured
- **Artifact Logging:** Record that snapshots and logs have been moved to secure, offline storage.

### C. Threat Hunting (Step 4 — Supplemental Direction ED 26-03)
Per the joint **Cisco SD-WAN Threat Hunt Guide** (CISA, NSA, ASD ACSC, Canadian Cyber Centre, NCSC-NZ, NCSC-UK):

- **Per-asset 6-point hunt checklist:**
  1. OMP peers reviewed (`show omp peers`) — detect rogue/unknown peers
  2. Control connections verified (`show control connections`) — confirm all expected
  3. User accounts audited (`show running-config aaa`) — detect unauthorized root/admin accounts
  4. Software version downgrade check (`show software`) — detect version regression
  5. Audit/syslog logs reviewed (`show log`, `show audit-log`) — detect gaps, tampering, anomalies
  6. Configuration changes reviewed (running-config diff vs baseline) — detect unauthorized policy changes
- **Hunt auto-completes** only when all 6 checks are marked done per asset.
- **Hunt Findings Log:** Dedicated table (`hunt_findings`) for analysts to log individual IOC findings with:
  - Finding category (Rogue Peer, Unauthorized User, Version Downgrade, Log Tampering, etc.)
  - Severity (CRITICAL / HIGH / MEDIUM / INFO)
  - Description, evidence (CLI output / log excerpts), analyst attribution
- **Integrated Threat Hunt Guide** embedded in the UI with:
  - Known attack chain / kill chain phases
  - CLI command reference with "what to look for" guidance per command
  - IOC reference table (network-level and host-level indicators)
  - Step-by-step hunt decision flowchart
- Hunt findings are included in the **CISA JSON report export** for the March 5 deadline.

#### Known Attack Chain (from joint intelligence)
| Phase | Technique | CVE |
|-------|-----------|-----|
| Initial Access | Auth bypass via SD-WAN peering | CVE-2026-20127 |
| Rogue Peer | Insert legitimate-looking component into fabric | — |
| Persistence | Software downgrade to older vulnerable version | — |
| Privilege Escalation | Root access via priv-esc | CVE-2022-20775 |
| Defense Evasion | Log tampering, clearing audit trails | — |
| Lateral Movement | Control plane abuse to push malicious policy | — |

### D. Hardening Implementation (Step 5)
- Per-asset toggle for hardening completion status.
- Checklist guidance based on **Cisco's Catalyst SD-WAN Hardening Guide**.
- Restrict perimeter exposure, isolate management planes, enhance logging.

### E. Reporting & Export
- **CISA-Standard JSON Export:** One-click generation of a JSON file formatted to meet CISA reporting requirements.
- **CSV Export:** Tabular export of all assets and their compliance statuses.

---

## 5. Technical Architecture

| Component | Technology | Rationale |
|-----------|-----------|-----------|
| **Frontend/UI** | Streamlit | Rapid development; Python scripts become web apps instantly. |
| **Persistence** | SQLAlchemy / SQLite | SQLite for immediate clone-and-run; SQLAlchemy enables easy migration to Cloud SQL/Postgres. |
| **Containerization** | Docker | Consistent environments across dev and production. |
| **Deployment** | Google Cloud Run | Serverless, scales to zero, deploys in under 5 minutes. |
| **Security** | Identity-Aware Proxy (IAP) | Eliminates custom login; uses organizational SSO. |

---

## 6. Project Structure

```
cisa-ed-26-03-tracker/
├── .github/
│   └── workflows/
│       └── generate-docs.yml    # GitHub Actions: auto-generate architecture docs
├── app.py                       # Main Streamlit application (~920 lines)
├── database.py                  # SQLAlchemy 2.0 ORM models & session factory
├── requirements.txt             # Python dependency list
├── Dockerfile                   # Container configuration for Cloud Run
├── PRD_ED_26_03.md              # This document
├── ARCHITECTURE.md              # Auto-generated architecture documentation
├── README.md                    # Setup and deployment instructions
├── LICENSE                      # MIT License — BlueFalconInk LLC
├── .gitignore                   # Python / SQLite / IDE / OS ignores
└── ACSC-led Cisco SD-WAN Hunt Guide.pdf  # Official joint threat hunt guide
```

---

## 7. Deployment Model

### Local Development
1. Clone the repository.
2. Run `pip install -r requirements.txt`.
3. Launch with `streamlit run app.py`.
4. The SQLite database is auto-created on first run.

### Production (Google Cloud Run)
1. **Containerize:** Build the image using the provided Dockerfile.
2. **Push:** Upload to Artifact Registry / Container Registry.
3. **Deploy:** Execute `gcloud run deploy` with `--no-allow-unauthenticated`.
4. **IAP Enablement:** Enable Identity-Aware Proxy to restrict access to agency domain users only.

For persistent cross-restart data in production, swap the SQLite connection string in `database.py` to a Cloud SQL (PostgreSQL) instance.

---

## 8. Security Hardening (Production)

- **Authentication:** Deploy with `--no-allow-unauthenticated`. Use Google IAP for organizational SSO.
- **Audit Trail:** `last_updated` and `timestamp` fields provide a basic audit trail of compliance status changes.
- **Network Isolation:** Place SD-WAN control components behind firewalls; use allowlists for known peer IP addresses.
- **Management Plane Isolation:** Restrict access to management interfaces to dedicated, trusted administrative networks.
- **Enhanced Logging:** Forward all SD-WAN logs to a remote, external syslog server to prevent attackers from erasing evidence.

---

## 9. Recommended Patch Versions

Per Cisco and CISA guidance:
- **20.12.6.1+**
- **20.15.4.2+**
- **20.18.2.1+**

---

## 10. Implementation Timeline (Zero-Hour Playbook)

| Minutes | Phase | Action |
|---------|-------|--------|
| 0 – 30 | **Environment Sync** | Set up GitHub repo; initialize GCP project. |
| 30 – 70 | **App Finalization** | Deploy code; verify local DB writes. |
| 70 – 100 | **Secure Deployment** | Deploy to Cloud Run; enable IAP. |
| 100 – 120 | **Data Ingestion** | Distribute URL to engineering team; begin logging assets. |

---

## 11. Official References

- **ED 26-03:** [CISA Directives Page](https://www.cisa.gov/news-events/directives)
- **Supplemental Direction ED 26-03:** Hunt and Hardening Guidance for Cisco SD-WAN Systems
- **Cisco SD-WAN Threat Hunt Guide** — Joint guidance by CISA, NSA, ASD ACSC, Canadian Cyber Centre, NCSC-NZ, NCSC-UK
- **Cisco Catalyst SD-WAN Hardening Guide** — Vendor hardening recommendations
- **Press Release:** February 25, 2026 — "Immediate Action Required: CISA Issues Emergency Directive to Secure Cisco SD-WAN Systems"
