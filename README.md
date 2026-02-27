# 🦅 BlueFalconInk — CISA ED 26-03 Compliance Tracker

**Built by [BlueFalconInk LLC](https://github.com/bluefalconink)**

A rapid-response compliance tool for Federal Agencies and enterprises to meet the mandates of **CISA Emergency Directive 26-03** regarding Cisco SD-WAN vulnerabilities (CVE-2026-20127 & CVE-2022-20775).

---

## 🚨 Critical Deadlines

| Milestone             | Deadline                     |
|-----------------------|------------------------------|
| **Inventory**         | February 26, 2026 — 11:59 PM ET |
| **Patching**          | February 27, 2026 — 5:00 PM ET  |
| **Final Report**      | March 5, 2026                |

---

## 🚀 Quick Start (Local)

1. **Clone & Setup:**
   ```bash
   git clone <repo-url>
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

## 📝 Compliance Workflow

According to ED 26-03 and the Supplemental Direction:

1. **Inventory** — All `vManage` and `vSmart` instances must be logged by Feb 26, 11:59 PM ET.
2. **Forensics** — Capture VM snapshots, admin core dumps (`/opt`, `/var`), and `/home` directory copies **BEFORE** patching.
3. **Patching** — Apply updates by Feb 27, 5:00 PM ET. Recommended versions: `20.12.6.1+`, `20.15.4.2+`, `20.18.2.1+`.
4. **Threat Hunting** — Check for unauthorized peering events (unexpected `vManage`/`vSmart` peers) and unauthorized root account activity.

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
├── app.py               # Main Streamlit application
├── database.py          # Database models and session handling
├── requirements.txt     # Python dependencies
├── Dockerfile           # Container configuration
├── PRD_ED_26_03.md      # Project Requirements Document
└── README.md            # This file
```

---

## 🔒 Security Notes

- **Never** deploy with `--allow-unauthenticated` in production.
- Use **Identity-Aware Proxy (IAP)** to gate access behind organizational SSO.
- Forward all SD-WAN logs to a remote, external syslog server.
- Restrict SD-WAN control components behind firewalls with IP allowlists.

---

## 🦅 About BlueFalconInk LLC

BlueFalconInk LLC builds rapid-response cybersecurity compliance tooling for federal agencies and the broader security community. This project is open-source and freely available to support emergency directive response.

**GitHub:** [github.com/bluefalconink](https://github.com/bluefalconink)  
**License:** MIT
