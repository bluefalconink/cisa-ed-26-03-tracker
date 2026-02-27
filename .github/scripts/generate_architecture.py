"""
Auto-generate ARCHITECTURE.md for the CISA ED 26-03 Compliance Tracker.

This script introspects the codebase (database models, app structure, Dockerfile,
requirements) and produces a Mermaid-illustrated architecture document.

Run by GitHub Actions on every push to master that touches *.py / requirements.txt / Dockerfile.
"""

import ast
import os
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # repo root


# ─── Helpers ──────────────────────────────────────────────────────────────────

def count_lines(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except Exception:
        return 0


def extract_classes(filepath: Path) -> list[dict]:
    """Parse a Python file and return a list of class metadata."""
    classes = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return classes
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            bases = [
                getattr(b, "id", getattr(b, "attr", ""))
                for b in node.bases
            ]
            methods = [
                n.name for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            attrs = []
            for n in node.body:
                if isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name):
                    attrs.append(n.target.id)
                elif isinstance(n, ast.Assign):
                    for t in n.targets:
                        if isinstance(t, ast.Name):
                            attrs.append(t.id)
            docstring = ast.get_docstring(node) or ""
            classes.append({
                "name": node.name,
                "bases": bases,
                "methods": methods,
                "attributes": attrs,
                "docstring": docstring,
                "lineno": node.lineno,
            })
    return classes


def extract_functions(filepath: Path) -> list[dict]:
    """Parse a Python file and return top-level function metadata."""
    funcs = []
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return funcs
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            docstring = ast.get_docstring(node) or ""
            args = [a.arg for a in node.args.args]
            funcs.append({
                "name": node.name,
                "args": args,
                "docstring": docstring,
                "lineno": node.lineno,
            })
    return funcs


def extract_imports(filepath: Path) -> list[str]:
    """Return top-level imported module names."""
    mods = set()
    try:
        tree = ast.parse(filepath.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module.split(".")[0])
    return sorted(mods)


def parse_requirements(filepath: Path) -> list[dict]:
    """Parse requirements.txt into list of {name, spec}."""
    deps = []
    try:
        for line in filepath.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"([A-Za-z0-9_-]+)(.*)", line)
                if match:
                    deps.append({"name": match.group(1), "spec": match.group(2).strip()})
    except Exception:
        pass
    return deps


def parse_dockerfile(filepath: Path) -> dict:
    """Extract key Dockerfile metadata."""
    info = {"base_image": "", "port": "", "entrypoint": ""}
    try:
        content = filepath.read_text(encoding="utf-8")
        m = re.search(r"FROM\s+(\S+)", content)
        if m:
            info["base_image"] = m.group(1)
        m = re.search(r"EXPOSE\s+(\d+)", content)
        if m:
            info["port"] = m.group(1)
        m = re.search(r"(?:ENTRYPOINT|CMD)\s+(.+)", content)
        if m:
            info["entrypoint"] = m.group(1).strip()
    except Exception:
        pass
    return info


def extract_section_headers(filepath: Path) -> list[dict]:
    """Extract Streamlit section headers from app.py (st.header / st.subheader calls)."""
    headers = []
    try:
        for i, line in enumerate(filepath.read_text(encoding="utf-8").splitlines(), 1):
            m = re.search(r'st\.(header|subheader)\(\s*["\'](.+?)["\']', line)
            if m:
                headers.append({"level": m.group(1), "text": m.group(2), "line": i})
    except Exception:
        pass
    return headers


# ─── Introspect the codebase ──────────────────────────────────────────────────

db_path = ROOT / "database.py"
app_path = ROOT / "app.py"
req_path = ROOT / "requirements.txt"
docker_path = ROOT / "Dockerfile"

db_classes = extract_classes(db_path)
db_functions = extract_functions(db_path)
app_classes = extract_classes(app_path)
app_functions = extract_functions(app_path)
app_imports = extract_imports(app_path)
app_sections = extract_section_headers(app_path)
requirements = parse_requirements(req_path)
docker_info = parse_dockerfile(docker_path)

db_lines = count_lines(db_path)
app_lines = count_lines(app_path)

# Collect all project files (excluding hidden dirs, __pycache__, .venv, db files)
project_files = []
for p in sorted(ROOT.rglob("*")):
    rel = p.relative_to(ROOT)
    parts = rel.parts
    if any(part.startswith(".") and part != ".github" for part in parts):
        continue
    if "__pycache__" in parts or ".venv" in parts:
        continue
    if p.suffix == ".db":
        continue
    if p.is_file():
        project_files.append(rel)


# ─── Build the Markdown ──────────────────────────────────────────────────────

lines = []
w = lines.append  # shorthand

w("# Architecture Documentation")
w("")
w(f"**Auto-generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}** by "
  "[generate-docs.yml](.github/workflows/generate-docs.yml)")
w("")
w("> This document is automatically regenerated by GitHub Actions whenever source "
  "code changes are pushed to the `master` branch.")
w("")

# ─── 1. System Overview ──────────────────────────────────────────────────────
w("## 1. System Overview")
w("")
w("The **CISA ED 26-03 Compliance Tracker** is a single-page Streamlit web application "
  "that guides federal agencies through the 5-step CISA action sequence for Cisco SD-WAN "
  "vulnerability remediation (CVE-2026-20127 & CVE-2022-20775).")
w("")
w("```mermaid")
w("graph TB")
w('    User["🧑‍💻 Agency Analyst<br/>Browser"] --> |HTTPS| Streamlit["🦅 Streamlit App<br/>app.py"]')
w('    Streamlit --> |SQLAlchemy ORM| DB["🗄️ SQLite / PostgreSQL<br/>database.py"]')
w('    Streamlit --> |JSON / CSV Export| Report["📄 CISA Report<br/>March 5 Deadline"]')
w('    Streamlit --> |File Upload| Import["📥 Bulk Import<br/>CSV / Excel / JSON / TSV"]')
w('    Docker["🐳 Docker Container<br/>python:3.11-slim"] --> Streamlit')
w('    GCR["☁️ Google Cloud Run"] --> Docker')
w('    IAP["🔒 Identity-Aware Proxy"] --> GCR')
w("")
w('    style Streamlit fill:#1f77b4,color:#fff')
w('    style DB fill:#2ca02c,color:#fff')
w('    style IAP fill:#d62728,color:#fff')
w('    style GCR fill:#ff7f0e,color:#fff')
w("```")
w("")

# ─── 2. Technology Stack ─────────────────────────────────────────────────────
w("## 2. Technology Stack")
w("")
w("| Layer | Technology | Version / Spec |")
w("|-------|-----------|----------------|")
for dep in requirements:
    role = {
        "streamlit": "Frontend / UI",
        "pandas": "Data Processing",
        "sqlalchemy": "ORM / Database",
        "openpyxl": "Excel Import",
    }.get(dep["name"].lower(), "Dependency")
    w(f'| {role} | `{dep["name"]}` | `{dep["spec"] or "latest"}` |')
w(f'| Container | Docker | Base: `{docker_info["base_image"]}` |')
w(f'| Deployment | Google Cloud Run | Port `{docker_info["port"]}` |')
w("| Auth | Google IAP | Organizational SSO |")
w("| Database | SQLite (dev) / PostgreSQL (prod) | Auto-created on startup |")
w("")

# ─── 3. Data Model ───────────────────────────────────────────────────────────
w("## 3. Data Model")
w("")
w("```mermaid")
w("erDiagram")
for cls in db_classes:
    if cls["name"] == "Base":
        continue
    tbl = cls["name"]
    w(f"    {tbl} {{")
    for attr in cls["attributes"]:
        if attr.startswith("_"):
            continue
        w(f"        field {attr}")
    w("    }")
w("")
# Relationships
w('    SDWANInstance ||--o{ HuntFinding : "has many"')
w("```")
w("")

for cls in db_classes:
    if cls["name"] == "Base":
        continue
    w(f"### `{cls['name']}`")
    if cls["docstring"]:
        w(f"_{cls['docstring']}_")
    w("")
    w("| Column | Purpose |")
    w("|--------|---------|")
    col_docs = {
        "id": "Primary key",
        "hostname": "Device hostname / identifier",
        "ip_address": "Management IP address",
        "sys_type": "vManage (Manager) or vSmart (Controller)",
        "version": "Current Cisco SD-WAN software version",
        "forensics_captured": "All 3 forensic artifacts collected (derived)",
        "snapshot_captured": "VM snapshot captured before patching",
        "core_dump_captured": "Admin core dump (/opt, /var) exported",
        "home_dir_copied": "/home directory copy secured",
        "patch_applied": "Cisco patch applied (gated by forensics)",
        "hunt_completed": "All 6 hunt checklist items completed",
        "hunt_omp_peers_checked": "OMP peers reviewed (show omp peers)",
        "hunt_control_connections_checked": "Control connections verified",
        "hunt_unauthorized_users_checked": "User accounts audited (AAA config)",
        "hunt_version_downgrade_checked": "Software version regression checked",
        "hunt_audit_logs_checked": "Audit/syslog logs reviewed",
        "hunt_config_changes_checked": "Config changes reviewed vs baseline",
        "hardening_implemented": "Hardening measures applied per Cisco guide",
        "notes": "Free-text notes (location, environment, etc.)",
        "timestamp": "Record creation timestamp",
        "last_updated": "Last modification timestamp",
        "asset_id": "Foreign key → SDWANInstance.id",
        "category": "Finding category (Rogue Peer, Unauthorized User, etc.)",
        "severity": "CRITICAL / HIGH / MEDIUM / INFO",
        "description": "Detailed finding description",
        "evidence": "CLI output or log excerpt",
        "analyst": "Name of analyst who logged the finding",
        "asset": "SQLAlchemy relationship back to SDWANInstance",
        "hunt_findings": "SQLAlchemy relationship to HuntFinding records",
    }
    for attr in cls["attributes"]:
        if attr.startswith("_"):
            continue
        doc = col_docs.get(attr, "")
        w(f"| `{attr}` | {doc} |")
    w("")

# ─── 4. Application Structure ────────────────────────────────────────────────
w("## 4. Application Structure")
w("")
w(f"`app.py` — **{app_lines} lines** | `database.py` — **{db_lines} lines**")
w("")

if app_sections:
    w("### UI Sections")
    w("")
    w("| # | Section | Line |")
    w("|---|---------|------|")
    for i, sec in enumerate(app_sections, 1):
        text = sec["text"].replace("|", "\\|")
        w(f"| {i} | {text} | L{sec['line']} |")
    w("")

w("### Application Flow")
w("")
w("```mermaid")
w("flowchart TD")
w('    A["🏠 Page Load"] --> B["⏰ Deadline Countdowns"]')
w('    B --> C["📊 Dashboard Metrics"]')
w('    C --> D["1️⃣ Asset Inventory"]')
w('    D --> D1["Manual Registration"]')
w('    D --> D2["Bulk Import<br/>CSV/Excel/JSON/TSV"]')
w('    D --> E["2-5️⃣ Compliance Workflow"]')
w('    E --> E1["Forensics<br/>3 Artifact Checkboxes"]')
w('    E1 --> |"Gate: All 3 Required"| E2["Patch Toggle"]')
w('    E2 --> E3["Hunt<br/>6-Point Checklist"]')
w('    E3 --> E4["Hardening Toggle"]')
w('    E --> F["🔍 Threat Hunt Guide"]')
w('    F --> F1["Attack Chain"]')
w('    F --> F2["CLI Commands"]')
w('    F --> F3["IOC Reference"]')
w('    F --> F4["Decision Flowchart"]')
w('    E --> G["📋 Hunt Findings Log"]')
w('    G --> H["📤 CISA Reporting Engine"]')
w('    H --> H1["JSON Export"]')
w('    H --> H2["CSV Export"]')
w("")
w('    style A fill:#1f77b4,color:#fff')
w('    style E fill:#2ca02c,color:#fff')
w('    style H fill:#d62728,color:#fff')
w("```")
w("")

# ─── 5. Module Reference ─────────────────────────────────────────────────────
w("## 5. Module Reference")
w("")

w("### database.py")
w("")
w("ORM models and database session factory using SQLAlchemy 2.0 `Mapped` / `mapped_column` style.")
w("")
for cls in db_classes:
    if cls["name"] == "Base":
        w(f"- **`{cls['name']}`** — SQLAlchemy declarative base class")
    else:
        w(f"- **`{cls['name']}`** — {len(cls['attributes'])} columns "
          f"(line {cls['lineno']})")
w("")
for fn in db_functions:
    w(f"- **`{fn['name']}({', '.join(fn['args'])})`** — "
      f"{fn['docstring'] or 'Database utility function'} (line {fn['lineno']})")
w("")

w("### app.py")
w("")
w("Streamlit single-page application.")
w("")
w("**Imports:** " + ", ".join(f"`{m}`" for m in app_imports))
w("")
if app_functions:
    w("**Functions:**")
    w("")
    for fn in app_functions:
        w(f"- **`{fn['name']}({', '.join(fn['args'])})`** — "
          f"{fn['docstring'] or 'Application helper'} (line {fn['lineno']})")
    w("")

# ─── 6. Deployment Architecture ──────────────────────────────────────────────
w("## 6. Deployment Architecture")
w("")
w("```mermaid")
w("graph LR")
w('    subgraph "Local Development"')
w('        DEV["streamlit run app.py"] --> SQLITE["SQLite<br/>compliance_data.db"]')
w("    end")
w("")
w('    subgraph "Production (GCP)"')
w('        IAP2["🔒 IAP<br/>Org SSO"] --> CR["☁️ Cloud Run"]')
w('        CR --> CONT["🐳 Docker<br/>python:3.11-slim"]')
w('        CONT --> APP["Streamlit<br/>Port 8080"]')
w('        APP --> PG["🐘 Cloud SQL<br/>PostgreSQL"]')
w("    end")
w("")
w('    style IAP2 fill:#d62728,color:#fff')
w('    style CR fill:#ff7f0e,color:#fff')
w('    style PG fill:#2ca02c,color:#fff')
w("```")
w("")
w(f"- **Base Image:** `{docker_info['base_image']}`")
w(f"- **Exposed Port:** `{docker_info['port']}`")
w(f"- **Entrypoint:** `{docker_info['entrypoint']}`")
w("")

# ─── 7. File Inventory ───────────────────────────────────────────────────────
w("## 7. File Inventory")
w("")
w("| File | Lines | Purpose |")
w("|------|-------|---------|")
file_docs = {
    "app.py": "Main Streamlit application",
    "database.py": "SQLAlchemy ORM models & session factory",
    "requirements.txt": "Python dependency list",
    "Dockerfile": "Container build configuration",
    "README.md": "Setup, features, and deployment guide",
    "PRD_ED_26_03.md": "Product Requirements Document",
    "ARCHITECTURE.md": "This auto-generated architecture doc",
    "LICENSE": "MIT License — BlueFalconInk LLC",
    ".gitignore": "Git ignore rules",
    "ACSC-led Cisco SD-WAN Hunt Guide.pdf": "Official joint threat hunt guide (PDF)",
}
for f in project_files:
    fname = str(f).replace("\\", "/")
    lc = count_lines(ROOT / f)
    desc = file_docs.get(f.name, "")
    if not desc and f.suffix == ".yml":
        desc = "GitHub Actions workflow"
    if not desc and f.suffix == ".py" and ".github" in fname:
        desc = "CI/CD script"
    w(f"| `{fname}` | {lc} | {desc} |")
w("")

# ─── 8. CI/CD ────────────────────────────────────────────────────────────────
w("## 8. CI/CD Pipeline")
w("")
w("```mermaid")
w("graph LR")
w('    PUSH["git push<br/>master"] --> |"paths: **.py,<br/>requirements.txt,<br/>Dockerfile"| GHA["GitHub Actions<br/>generate-docs.yml"]')
w('    GHA --> PY["Run<br/>generate_architecture.py"]')
w('    PY --> |"Introspect codebase"| MD["ARCHITECTURE.md"]')
w('    MD --> |"git commit + push"| REPO["📦 Repository"]')
w("")
w('    style PUSH fill:#1f77b4,color:#fff')
w('    style GHA fill:#ff7f0e,color:#fff')
w('    style REPO fill:#2ca02c,color:#fff')
w("```")
w("")
w("The `generate-docs` workflow:")
w("1. Triggers on pushes to `master` that modify `*.py`, `requirements.txt`, or `Dockerfile`")
w("2. Runs `generate_architecture.py` which introspects the codebase via AST parsing")
w("3. Produces Mermaid diagrams, data model docs, and module reference")
w("4. Auto-commits `ARCHITECTURE.md` back to the repository")
w("")

# ─── Footer ──────────────────────────────────────────────────────────────────
w("---")
w("")
w("*Built by [BlueFalconInk LLC](https://github.com/bluefalconink) — "
  "Defending federal networks with open-source tooling.*")
w("")

# ─── Write output ─────────────────────────────────────────────────────────────
output = "\n".join(lines)
out_path = ROOT / "ARCHITECTURE.md"
out_path.write_text(output, encoding="utf-8")
print(f"✅ Generated {out_path} ({len(lines)} lines)")
