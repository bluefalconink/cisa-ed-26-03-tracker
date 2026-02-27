import streamlit as st
import pandas as pd
from database import SessionLocal, SDWANInstance, HuntFinding, init_db
from datetime import datetime
import json

# Initialize database on first run
init_db()

# Page Configuration
st.set_page_config(
    page_title="BlueFalconInk | ED 26-03 Compliance Tracker",
    page_icon="🦅",
    layout="wide",
)


# Database Helper
def get_session():
    return SessionLocal()


# ──────────────────────────────────────────────
# HEADER & URGENCY COUNTDOWN
# ──────────────────────────────────────────────
st.title("🦅 BlueFalconInk — CISA ED 26-03 Compliance Tracker")
st.caption(
    "Emergency Directive 26-03: Mitigate Vulnerabilities in Cisco SD-WAN Systems — "
    "CVE-2026-20127 & CVE-2022-20775  |  "
    "Released February 25, 2026 by CISA  |  "
    "Developed by **BlueFalconInk LLC**"
)

# Deadline countdowns
now = datetime.now()
inventory_deadline = datetime(2026, 2, 26, 23, 59)
patch_deadline = datetime(2026, 2, 27, 17, 0)
report_deadline = datetime(2026, 3, 5, 23, 59)

col_d1, col_d2, col_d3 = st.columns(3)

inv_remaining = inventory_deadline - now
patch_remaining = patch_deadline - now
report_remaining = report_deadline - now

if inv_remaining.total_seconds() > 0:
    col_d1.error(
        f"⚠️ INVENTORY DEADLINE: "
        f"{inv_remaining.days}d {inv_remaining.seconds // 3600}h "
        f"{(inv_remaining.seconds // 60) % 60}m remaining\n\n"
        f"**Feb 26, 11:59 PM ET**"
    )
else:
    col_d1.success("✅ Inventory deadline passed")

if patch_remaining.total_seconds() > 0:
    col_d2.warning(
        f"🔧 PATCH DEADLINE: "
        f"{patch_remaining.days}d {patch_remaining.seconds // 3600}h "
        f"{(patch_remaining.seconds // 60) % 60}m remaining\n\n"
        f"**Feb 27, 5:00 PM ET**"
    )
else:
    col_d2.success("✅ Patch deadline passed")

if report_remaining.total_seconds() > 0:
    col_d3.info(
        f"📝 REPORT DEADLINE: "
        f"{report_remaining.days}d {report_remaining.seconds // 3600}h "
        f"{(report_remaining.seconds // 60) % 60}m remaining\n\n"
        f"**March 5, 2026**"
    )
else:
    col_d3.success("✅ Report deadline passed")

st.divider()

# ──────────────────────────────────────────────
# QUICK STATS DASHBOARD
# ──────────────────────────────────────────────
db = get_session()
assets = db.query(SDWANInstance).all()

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Total Assets", len(assets))
m2.metric(
    "Forensics Complete",
    sum(1 for a in assets if a.forensics_captured),
)
m3.metric(
    "Patched",
    sum(1 for a in assets if a.patch_applied),
)
m4.metric(
    "Hunt Complete",
    sum(1 for a in assets if a.hunt_completed),
)
m5.metric(
    "Hardened",
    sum(1 for a in assets if a.hardening_implemented),
)

st.divider()

# ──────────────────────────────────────────────
# SECTION 1: ASSET REGISTRATION
# ──────────────────────────────────────────────
st.header("1️⃣ Inventory — All In-Scope Cisco SD-WAN Systems")
st.markdown(
    "Register all **vManage** (Manager) and **vSmart** (Controller) instances. "
    "This data feeds the CISA inventory submission.  \n"
    "*Per the directive: 'Inventory all in-scope Cisco SD-WAN systems.'*"
)

with st.expander("➕ Register SD-WAN Instance", expanded=len(assets) == 0):
    with st.form("add_asset", clear_on_submit=True):
        c1, c2, c3 = st.columns(3)
        hostname = c1.text_input("Hostname / Device ID")
        ip_addr = c2.text_input("IP Address")
        version = c3.text_input("Current Software Version")
        sys_type = st.selectbox(
            "System Type",
            ["vManage (Manager)", "vSmart (Controller)"],
        )
        notes = st.text_area("Notes (location, environment, etc.)", height=68)

        if st.form_submit_button("📥 Log Asset to Inventory"):
            if hostname and ip_addr:
                new_asset = SDWANInstance(
                    hostname=hostname,
                    ip_address=ip_addr,
                    sys_type=sys_type,
                    version=version,
                    notes=notes,
                )
                db.add(new_asset)
                db.commit()
                st.success(f"✅ Inventory logged: **{hostname}** ({ip_addr})")
                st.rerun()
            else:
                st.error("Hostname and IP Address are required.")

st.divider()

# ──────────────────────────────────────────────
# SECTION 2-5: COMPLIANCE WORKFLOW (Artifacts → Patch → Hunt → Harden)
# ──────────────────────────────────────────────
st.header("2️⃣ Collect Artifacts → 3️⃣ Patch → 4️⃣ Hunt → 5️⃣ Implement Hardening")
st.warning(
    "⚠️ **DO NOT PATCH** until snapshots, core dumps, and /home directory copies "
    "are secured. CISA mandates forensic artifact collection **before** patching."
)

if assets:
    for asset in assets:
        with st.container(border=True):
            col_info, col_forensics, col_patch, col_hunt, col_harden = st.columns([2, 3, 2, 2, 2])

            # ── Info ──
            with col_info:
                st.markdown(f"### {asset.hostname}")
                st.caption(
                    f"**Type:** {asset.sys_type}  \n"
                    f"**IP:** {asset.ip_address}  \n"
                    f"**Version:** {asset.version or 'N/A'}  \n"
                    f"**Notes:** {asset.notes or '—'}"
                )

            # ── Forensic Artifacts (Supplemental Direction) ──
            with col_forensics:
                st.markdown("**Required Artifacts (ED 26-03 Supplemental):**")
                f1 = st.checkbox(
                    "VM Snapshot captured",
                    value=asset.snapshot_captured,
                    key=f"snap_{asset.id}",
                )
                f2 = st.checkbox(
                    "Admin Core Dump (/opt, /var)",
                    value=asset.core_dump_captured,
                    key=f"core_{asset.id}",
                )
                f3 = st.checkbox(
                    "/home directory copy",
                    value=asset.home_dir_copied,
                    key=f"home_{asset.id}",
                )

                if st.button("💾 Save Forensic Status", key=f"save_f_{asset.id}"):
                    asset.snapshot_captured = f1
                    asset.core_dump_captured = f2
                    asset.home_dir_copied = f3
                    asset.forensics_captured = all([f1, f2, f3])
                    db.commit()
                    st.rerun()

                if asset.forensics_captured:
                    st.success("All forensic artifacts confirmed ✅")

            # ── Patch Status ──
            with col_patch:
                st.markdown("**Patch Status:**")
                patch_toggle = st.toggle(
                    "Patch Applied",
                    value=asset.patch_applied,
                    key=f"patch_{asset.id}",
                )
                if patch_toggle != asset.patch_applied:
                    if patch_toggle and not asset.forensics_captured:
                        st.error(
                            "⛔ Cannot mark patched — "
                            "complete forensic capture first!"
                        )
                    else:
                        asset.patch_applied = patch_toggle
                        db.commit()
                        st.rerun()

                if asset.patch_applied:
                    st.success("Patched ✅")
                else:
                    st.info("Awaiting patch")

            # ── Threat Hunt (Step 4 — Granular Checklist) ──
            with col_hunt:
                st.markdown("**Threat Hunt Checklist:**")
                h1 = st.checkbox(
                    "OMP peers reviewed",
                    value=asset.hunt_omp_peers_checked,
                    key=f"h_omp_{asset.id}",
                    help="show omp peers — look for unknown peer IPs",
                )
                h2 = st.checkbox(
                    "Control connections verified",
                    value=asset.hunt_control_connections_checked,
                    key=f"h_ctrl_{asset.id}",
                    help="show control connections — confirm all are expected",
                )
                h3 = st.checkbox(
                    "User accounts audited",
                    value=asset.hunt_unauthorized_users_checked,
                    key=f"h_user_{asset.id}",
                    help="Check for unauthorized root / admin accounts",
                )
                h4 = st.checkbox(
                    "Version downgrade check",
                    value=asset.hunt_version_downgrade_checked,
                    key=f"h_ver_{asset.id}",
                    help="show software — look for unexpected version regression",
                )
                h5 = st.checkbox(
                    "Audit / syslog reviewed",
                    value=asset.hunt_audit_logs_checked,
                    key=f"h_log_{asset.id}",
                    help="Check for cleared/tampered logs, anomalous entries",
                )
                h6 = st.checkbox(
                    "Config changes reviewed",
                    value=asset.hunt_config_changes_checked,
                    key=f"h_cfg_{asset.id}",
                    help="Diff running-config vs baseline for unauthorized changes",
                )
                if st.button("💾 Save Hunt Status", key=f"save_h_{asset.id}"):
                    asset.hunt_omp_peers_checked = h1
                    asset.hunt_control_connections_checked = h2
                    asset.hunt_unauthorized_users_checked = h3
                    asset.hunt_version_downgrade_checked = h4
                    asset.hunt_audit_logs_checked = h5
                    asset.hunt_config_changes_checked = h6
                    asset.hunt_completed = all([h1, h2, h3, h4, h5, h6])
                    db.commit()
                    st.rerun()

                if asset.hunt_completed:
                    st.success("Hunt complete ✅")

            # ── Hardening (Step 5) ──
            with col_harden:
                st.markdown("**Hardening (Step 5):**")
                st.caption(
                    "Implement Cisco's Catalyst SD-WAN "
                    "Hardening Guide recommendations."
                )
                harden_toggle = st.toggle(
                    "Hardening Implemented",
                    value=asset.hardening_implemented,
                    key=f"harden_{asset.id}",
                )
                if harden_toggle != asset.hardening_implemented:
                    asset.hardening_implemented = harden_toggle
                    db.commit()
                    st.rerun()

                if asset.hardening_implemented:
                    st.success("Hardened ✅")
else:
    st.info("No assets registered yet. Use the form above to begin inventory.")

st.divider()

# ──────────────────────────────────────────────
# THREAT HUNT GUIDE (Supplemental Direction ED 26-03)
# Based on joint guidance: CISA, NSA, ASD ACSC,
# Canadian Cyber Centre, NCSC-NZ, NCSC-UK
# ──────────────────────────────────────────────
st.header("🔍 Cisco SD-WAN Threat Hunt Guide")
st.markdown(
    "*Based on Supplemental Direction ED 26-03 and the joint "
    "**Cisco SD-WAN Threat Hunt Guide** issued by CISA, NSA, ASD's ACSC, "
    "Canadian Cyber Centre, NCSC-NZ, and NCSC-UK.*"
)

# ── Attack Chain Overview ──
with st.expander("🗺️ Known Attack Chain (Kill Chain)", expanded=False):
    st.markdown(
        """
The observed threat activity follows this sequence:

| Phase | Technique | Detail |
|-------|-----------|--------|
| **1. Initial Access** | Auth Bypass (CVE-2026-20127) | Unauthenticated remote attacker exploits the SD-WAN peering mechanism to bypass authentication on vManage/vSmart. |
| **2. Rogue Peer Insertion** | Fabric Manipulation | Attacker registers a temporary, legitimate-looking SD-WAN component (peer) into the overlay fabric. |
| **3. Persistence** | Software Downgrade | Attacker downgrades the system to an older vulnerable version to ensure continued access. |
| **4. Privilege Escalation** | Root Access (CVE-2022-20775) | Exploits privilege escalation to gain full ROOT on the compromised node. |
| **5. Defense Evasion** | Log Tampering | Attacker may clear audit logs, syslog entries, and core dumps to cover tracks. |
| **6. Lateral Movement** | Control Plane Abuse | Uses compromised controller to push malicious policy/routes to other SD-WAN nodes. |

**Evidence suggests this activity may have begun as early as 2023.**
"""
    )

# ── CLI Hunt Commands Reference ──
with st.expander("⌨️ CLI Commands for Threat Hunting", expanded=False):
    st.markdown("Use these commands on each vManage and vSmart instance to detect indicators of compromise:")

    st.markdown("#### 1. Check OMP Peer State (Rogue Peer Detection)")
    st.code("show omp peers", language="bash")
    st.markdown(
        "**What to look for:** Any peer IP addresses or system-IPs that are **not** in your "
        "authorized inventory. An unexpected `peer-type:vmanage` or `peer-type:vsmart` entry "
        "from an unknown IP is a **critical indicator** of compromise."
    )

    st.markdown("#### 2. Verify Control Connections")
    st.code("show control connections", language="bash")
    st.markdown(
        "**What to look for:** Connections to/from IP addresses not in your known controller list. "
        "Pay attention to the `PEER-TYPE`, `PEER-SYSTEM-IP`, and `STATE` columns. "
        "Any `connect` state from an unrecognized peer warrants immediate investigation."
    )

    st.markdown("#### 3. Check for Unauthorized User Accounts")
    st.code("show running-config aaa\nshow running-config system | include user", language="bash")
    st.markdown(
        "**What to look for:** Accounts you did not create — especially any with `group netadmin` "
        "or root-level privileges. Compare against your authorized user baseline."
    )

    st.markdown("#### 4. Detect Software Version Downgrades")
    st.code("show software\nrequest platform software package show", language="bash")
    st.markdown(
        "**What to look for:** The currently running version should match your expected patched "
        "version. A **regression** to an older version (e.g., dropping from 20.12.x to 20.9.x) "
        "is a strong indicator that an attacker downgraded the system for re-exploitation."
    )

    st.markdown("#### 5. Review Audit and System Logs")
    st.code("show log\nshow audit-log\nshow logging | include auth|login|peer|omp", language="bash")
    st.markdown(
        "**What to look for:**\n"
        "- Gaps or sudden truncation in logs (evidence of log clearing)\n"
        "- Repeated failed/succeeded authentication from unknown sources\n"
        "- OMP peering events with unrecognized system-IPs\n"
        "- Any `root` login events outside maintenance windows"
    )

    st.markdown("#### 6. Review Configuration Changes")
    st.code(
        "show running-config | compare rollback-config\n"
        "show configuration history",
        language="bash",
    )
    st.markdown(
        "**What to look for:**\n"
        "- Policy or route changes you did not authorize\n"
        "- New or modified ACLs allowing unexpected traffic\n"
        "- Changes to OMP/peering settings\n"
        "- Disabled logging or modified syslog destinations"
    )

    st.markdown("#### 7. Check for Anomalous Processes")
    st.code("vshell\nps aux | grep -v '\\[.*\\]'\nnetstat -tlnp", language="bash")
    st.markdown(
        "**What to look for:**\n"
        "- Unknown processes running as root\n"
        "- Unexpected listening ports or established connections\n"
        "- Processes with suspicious names or running from `/tmp`"
    )

# ── Specific IOCs ──
with st.expander("🚩 Indicators of Compromise (IOCs)", expanded=False):
    st.markdown(
        """
### Network-Level IOCs
| Indicator | Type | Description |
|-----------|------|-------------|
| Unexpected OMP peer | **CRITICAL** | A `peer-type:vmanage` or `peer-type:vsmart` entry from an IP not in your inventory |
| Unknown control connection | **CRITICAL** | DTLS/TLS control-plane connection from an unrecognized system-IP |
| Anomalous peering volume | **HIGH** | Sudden spike in OMP route advertisements or session establishments |
| Unexpected outbound connections | **HIGH** | vManage/vSmart initiating connections to IPs outside management subnet |

### Host-Level IOCs
| Indicator | Type | Description |
|-----------|------|-------------|
| Unauthorized root user | **CRITICAL** | New user accounts with `netadmin` or root-level privileges |
| Software version regression | **CRITICAL** | Running version is older than last known patched version |
| Log gaps or truncation | **HIGH** | Sudden interruption in audit logs, syslog, or journal entries |
| Modified `/home` directories | **HIGH** | New files, SSH keys, or scripts in user home directories |
| Unexpected cron jobs | **HIGH** | Scheduled tasks not in your baseline configuration |
| Core dump anomalies | **MEDIUM** | Missing or unexpectedly present core dumps in `/opt`, `/var` |
| Configuration drift | **MEDIUM** | Running-config differs from approved baseline without change record |

### Filesystem Artifacts to Examine
- `/opt/` and `/var/` — core dumps and application data
- `/home/` — user profiles, `.ssh/authorized_keys`, `.bash_history`
- `/tmp/` — attacker tools, staged payloads
- `/var/log/` — syslog, audit logs, auth logs
"""
    )

# ── Hunt Decision Flowchart ──
with st.expander("🔄 Hunt Decision Workflow", expanded=False):
    st.markdown(
        """
### Step-by-Step Hunt Procedure

```
For each vManage / vSmart system:
│
├─ 1. Run "show omp peers"
│     ├─ Unknown peer found? ──► CRITICAL FINDING → Isolate immediately
│     └─ All peers known? ──► Continue
│
├─ 2. Run "show control connections"
│     ├─ Unknown connection? ──► CRITICAL FINDING → Capture state, escalate
│     └─ All connections expected? ──► Continue
│
├─ 3. Run "show running-config aaa"
│     ├─ Unknown accounts? ──► CRITICAL FINDING → Document, do NOT delete yet
│     └─ All accounts authorized? ──► Continue
│
├─ 4. Run "show software"
│     ├─ Version downgrade detected? ──► CRITICAL FINDING → Full forensic capture
│     └─ Version matches expected? ──► Continue
│
├─ 5. Review audit/syslog
│     ├─ Gaps or anomalies? ──► HIGH FINDING → Preserve logs, investigate timeline
│     └─ Logs intact and clean? ──► Continue
│
├─ 6. Diff running-config vs baseline
│     ├─ Unauthorized changes? ──► HIGH FINDING → Document changes, assess impact
│     └─ Config matches baseline? ──► Continue
│
└─ 7. Mark "Hunt Complete" for this asset
```

**IMPORTANT:** If ANY critical finding is discovered:
1. **Do NOT remediate yet** — preserve the state for forensic analysis
2. Log the finding in the **Hunt Findings Log** below
3. Capture a fresh VM snapshot of the compromised state
4. Report to CISA per Supplemental Direction ED 26-03
"""
    )

st.divider()

# ──────────────────────────────────────────────
# HUNT FINDINGS LOG
# ──────────────────────────────────────────────
st.header("📓 Hunt Findings Log")
st.markdown(
    "Document all findings from your threat hunting activities. "
    "These entries feed directly into the **March 5 Final Report** to CISA."
)

# Add new finding
with st.expander("➕ Log a Hunt Finding", expanded=False):
    with st.form("add_finding", clear_on_submit=True):
        fc1, fc2 = st.columns(2)
        finding_asset = fc1.selectbox(
            "Affected Asset",
            options=[(a.id, f"{a.hostname} ({a.ip_address})") for a in assets]
            if assets
            else [],
            format_func=lambda x: x[1],
        )
        finding_category = fc2.selectbox(
            "Finding Category",
            [
                "Rogue/Unknown OMP Peer",
                "Unauthorized Control Connection",
                "Unauthorized User Account",
                "Software Version Downgrade",
                "Log Tampering / Gaps",
                "Unauthorized Config Change",
                "Suspicious Process / Listener",
                "Modified /home Directory",
                "Unexpected Cron Job",
                "Other",
            ],
        )
        finding_severity = st.selectbox(
            "Severity",
            ["CRITICAL", "HIGH", "MEDIUM", "INFO"],
        )
        finding_desc = st.text_area(
            "Description",
            placeholder="Describe what was found, which command revealed it, and the timeline.",
            height=80,
        )
        finding_evidence = st.text_area(
            "Evidence (CLI output / log excerpt)",
            placeholder="Paste the relevant CLI output or log lines here.",
            height=100,
        )
        finding_analyst = st.text_input("Analyst Name / ID")

        if st.form_submit_button("📝 Log Finding"):
            if finding_asset and finding_desc:
                new_finding = HuntFinding(
                    asset_id=finding_asset[0],
                    category=finding_category,
                    severity=finding_severity,
                    description=finding_desc,
                    evidence=finding_evidence,
                    analyst=finding_analyst,
                )
                db.add(new_finding)
                db.commit()
                st.success("Finding logged successfully.")
                st.rerun()
            else:
                st.error("Select an asset and provide a description.")

# Display existing findings
all_findings = db.query(HuntFinding).order_by(HuntFinding.timestamp.desc()).all()
if all_findings:
    st.markdown(f"**{len(all_findings)} finding(s) recorded:**")
    for f in all_findings:
        sev_color = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "INFO": "🔵",
        }.get(f.severity, "⚪")
        with st.container(border=True):
            hc1, hc2, hc3 = st.columns([1, 3, 1])
            hc1.markdown(f"{sev_color} **{f.severity}**")
            hc2.markdown(
                f"**{f.category}**  \n"
                f"{f.description}  \n"
                f"*Asset ID: {f.asset_id} | Analyst: {f.analyst or 'N/A'} | "
                f"{f.timestamp}*"
            )
            if f.evidence:
                hc3.button("View Evidence", key=f"ev_{f.id}")
            if f.evidence:
                with st.expander(f"Evidence — Finding #{f.id}", expanded=False):
                    st.code(f.evidence, language="text")
else:
    st.info("No hunt findings logged yet. Use the form above to record findings.")

st.divider()

# ──────────────────────────────────────────────
# CISA REPORTING ENGINE
# ──────────────────────────────────────────────
st.header("📤 CISA Reporting Engine")
st.markdown(
    "Generate the mandated JSON report for CISA submission. "
    "Ensure all assets are registered and statuses are current before exporting."
)

col_r1, col_r2 = st.columns(2)

with col_r1:
    if st.button("📊 Generate Inventory Report (JSON)"):
        # Gather hunt findings for the report
        report_findings = db.query(HuntFinding).all()
        report = {
            "directive": "ED 26-03",
            "supplemental_direction": "Hunt and Hardening Guidance for Cisco SD-WAN Systems",
            "agency": "BlueFalconInk LLC",
            "generated_at": str(datetime.now()),
            "total_assets": len(assets),
            "assets": [
                {
                    "hostname": a.hostname,
                    "ip_address": a.ip_address,
                    "system_type": a.sys_type,
                    "version": a.version,
                    "forensics_captured": a.forensics_captured,
                    "patch_applied": a.patch_applied,
                    "hunt_completed": a.hunt_completed,
                    "hunt_checklist": {
                        "omp_peers_reviewed": a.hunt_omp_peers_checked,
                        "control_connections_verified": a.hunt_control_connections_checked,
                        "user_accounts_audited": a.hunt_unauthorized_users_checked,
                        "version_downgrade_checked": a.hunt_version_downgrade_checked,
                        "audit_logs_reviewed": a.hunt_audit_logs_checked,
                        "config_changes_reviewed": a.hunt_config_changes_checked,
                    },
                    "hardening_implemented": a.hardening_implemented,
                    "notes": a.notes,
                    "last_updated": str(a.last_updated),
                }
                for a in assets
            ],
            "hunt_findings": [
                {
                    "asset_id": f.asset_id,
                    "category": f.category,
                    "severity": f.severity,
                    "description": f.description,
                    "evidence": f.evidence,
                    "analyst": f.analyst,
                    "timestamp": str(f.timestamp),
                }
                for f in report_findings
            ],
            "completion_status": {
                "inventory_complete": len(assets) > 0,
                "all_forensics": all(a.forensics_captured for a in assets)
                if assets
                else False,
                "all_patched": all(a.patch_applied for a in assets)
                if assets
                else False,
                "all_hunted": all(a.hunt_completed for a in assets)
                if assets
                else False,
                "all_hardened": all(a.hardening_implemented for a in assets)
                if assets
                else False,
            },
        }
        json_str = json.dumps(report, indent=4)
        st.code(json_str, language="json")
        st.download_button(
            label="⬇️ Download JSON for CISA Submission",
            data=json_str,
            file_name=f"ED_26_03_Inventory_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
            mime="application/json",
        )

with col_r2:
    if st.button("📋 Export Asset Table (CSV)"):
        if assets:
            df = pd.DataFrame(
                [
                    {
                        "Hostname": a.hostname,
                        "IP Address": a.ip_address,
                        "Type": a.sys_type,
                        "Version": a.version,
                        "Forensics": a.forensics_captured,
                        "Patched": a.patch_applied,
                        "Hunt Done": a.hunt_completed,
                        "Hardened": a.hardening_implemented,
                        "Notes": a.notes,
                    }
                    for a in assets
                ]
            )
            csv_data = df.to_csv(index=False)
            st.dataframe(df, use_container_width=True)
            st.download_button(
                label="⬇️ Download CSV",
                data=csv_data,
                file_name=f"ED_26_03_Assets_{datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                mime="text/csv",
            )
        else:
            st.warning("No assets to export.")

st.divider()

# ──────────────────────────────────────────────
# SIDEBAR: DIRECTIVE REFERENCE
# ──────────────────────────────────────────────
st.sidebar.header("📌 ED 26-03 Quick Reference")
st.sidebar.markdown(
    """
**Emergency Directive 26-03** — *Released Feb 25, 2026*

**CISA 5-Step Action Sequence:**
1. **Inventory** all in-scope Cisco SD-WAN systems
2. **Collect artifacts** (virtual snapshots & logs)
3. **Patch** for CVE-2026-20127 & CVE-2022-20775
4. **Hunt** for evidence of compromise
5. **Implement** Cisco's Catalyst SD-WAN Hardening Guide

---

**Key CVEs:**
- **CVE-2026-20127** — Zero-day auth bypass in SD-WAN peering
- **CVE-2022-20775** — Privilege escalation to root

**Deadlines:**
1. **Feb 26, 11:59 PM ET** — Inventory submission
2. **Feb 27, 5:00 PM ET** — Patching complete
3. **March 5, 2026** — Final report to CISA

**Recommended Patch Versions:**
- 20.12.6.1+
- 20.15.4.2+
- 20.18.2.1+

**Hardening Measures:**
- Restrict perimeter exposure (firewall + allowlists)
- Isolate management planes
- Forward all SD-WAN logs to external syslog
- Review Cisco's Catalyst SD-WAN Hardening Guide & blog
"""
)

st.sidebar.divider()
st.sidebar.markdown(
    "**Supplemental Direction:** Hunt and Hardening Guidance for Cisco SD-WAN Systems — "
    "Check for unauthorized peering events "
    "(unexpected `vManage` or `vSmart` peers) and root account activity."
)

st.sidebar.divider()
st.sidebar.markdown(
    """
**Joint Guidance Authoring Agencies:**
- 🇺🇸 NSA (National Security Agency)
- 🇺🇸 CISA
- 🇦🇺 ASD's Australian Cyber Security Centre (ACSC)
- 🇨🇦 Canadian Centre for Cyber Security
- 🇳🇿 New Zealand NCSC
- 🇬🇧 UK National Cyber Security Centre (NCSC-UK)

**Official Resources:**
- [ED 26-03 Directive](https://www.cisa.gov/news-events/directives)
- Cisco SD-WAN Threat Hunt Guide
- Cisco Catalyst SD-WAN Hardening Guide
"""
)

st.sidebar.divider()
st.sidebar.markdown(
    "---\n"
    "🦅 **Built by [BlueFalconInk LLC](https://github.com/bluefalconink)**  \n"
    "Open-source rapid-response compliance tooling."
)

# Close session
db.close()
