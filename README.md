# Localized AI-Driven Infrastructure Auditing & Remediation Platform

An offline-first operations toolkit for collecting host and network surface signals, correlating them against a local knowledge corpus, and presenting structured remediation guidance through a browser-based control plane. The design targets air-gapped and regulated environments where outbound cloud APIs and third-party telemetry are not acceptable.

## Architecture overview

The platform runs entirely on the operator machine or bastion: filesystem and OS introspection, optional LAN-oriented TCP discovery, YARA-oriented integrity checks, and log-derived indicators are fused into a single text profile. A **local** natural-language retrieval layer (scikit-learn TF–IDF over SQLite-stored procedures) ranks remediation entries without calling external inference services. A Flask application serves a responsive dashboard that orchestrates audit runs and surfaces JSON results. **No external APIs are required** for core operation; dependencies are installable from wheels or internal mirrors in disconnected settings.

## Core technical features

| Area | Implementation |
|------|----------------|
| Network surface discovery | Multi-threaded TCP probing coordinated with **Python `concurrent.futures`** for bounded parallelism across targets and ports |
| Remediation intelligence | **scikit-learn** pipeline with **TF–IDF** vectorization over locally curated sysadmin knowledge in **SQLite** |
| Operator experience | **Flask** web application with a responsive dashboard (`templates/`, static assets) bound to **127.0.0.1:5000** by default |

Additional collectors include OS log analysis, optional antivirus-style file checks (YARA, hashing), and package/configuration drift hints where the host platform permits.

## Requirements

- Python 3.10+ recommended
- Windows, Linux, or macOS (some collectors are OS-specific; run with appropriate privileges for log and network access)

## Setup

1. **Clone the repository**

   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
   cd YOUR_REPO
   ```

2. **Create and activate a virtual environment**

   ```bash
   python -m venv venv
   ```

   - Windows (PowerShell): `.\venv\Scripts\Activate.ps1`
   - Windows (cmd): `venv\Scripts\activate.bat`
   - Linux / macOS: `source venv/bin/activate`

3. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Initialize the local knowledge database** (creates `sysadmin_knowledge.db` and seeds schema/content as implemented in the project):

   ```bash
   python main.py database-init
   ```

2. **Start the web dashboard**:

   ```bash
   python app.py
   ```

3. Open a browser at **http://127.0.0.1:5000** and use the UI to trigger audits or review outputs.

CLI workflows such as `python main.py audit` or `python main.py logs` are also available; see `main.py` subcommands for options (for example `--subnet` for scanner scope).

## Security and operations notes

Run audits only on systems you are authorized to assess. Network scanning and log ingestion can be intrusive; align with organizational policy and applicable aviation/UAV ground-segment procedures. The default Flask bind address is loopback; reverse-proxy or TLS termination are out of scope for this academic prototype unless you add them.

## Academic context

This software was developed as a **final-year diploma project** at the **National Polytechnic University of Armenia**, combining **DevOps** practice with **aviation systems / UAV infrastructure** themes: trustworthy, offline-capable tooling for infrastructure assurance.
