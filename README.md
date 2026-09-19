# Forgotten Gateway Defense Lab

A comprehensive cybersecurity assessment and attack reconstruction system for an authorized lab environment (e.g. Healthcare Management System / HMS).

The system is structured in two decoupled, cooperating levels:
- **Level 1**: Network Exposure Assessment (Nmap scanning, service discovery, expected vs. observed port comparison, scan history).
- **Level 2**: Attack Reconstruction and Security Detection (remote telemetry ingestion, event normalization, transparent detection rules, multi-stage attack correlation, MITRE ATT&CK mapping, timeline reconstruction, and evidence-based risk scoring).

---

## Architecture Overview

```text
LEVEL 1: Network Exposure Assessment
   ↓ Target IP & Service Discovery (Nmap XML Parsing)
Infrastructure & Service Context (Target, Open Ports, Protocols)
   ↓
LEVEL 2: Attack Reconstruction Pipeline
   ↓ Telemetry (Remote Mac Nginx Agent or Controlled Local Scenarios)
Event Collection & Authenticated Transport (HMAC SHA-256 Envelope)
   ↓
Event Normalization (Nginx Parser → SecurityEvent with Stable IDs)
   ↓
Level 2 Detection Engine (Auth Anomaly, Account Discovery, Admin Probing, Transfer Access)
   ↓
Correlation Engine (Sliding Window & Source IP Attack Chains)
   ↓
MITRE ATT&CK Mapping (T1071.001, T1087, T1041, T1190 Explicit Evidence/Limitations)
   ↓
Timeline Reconstruction (Chronological Merge of Events, Alerts, and Correlations)
   ↓
Risk & Severity Scoring (Explainable 0–100 Score & Low/Medium/High/Critical Breakdown)
   ↓
Level 2 Dashboard & Forensic Investigation View (Interactive Tkinter Desktop GUI)
```

---

## Requirements

- Python 3.10 or newer (tested on Python 3.13)
- Tkinter (`python3-tk` on Debian/Ubuntu, included by default on Windows & macOS)
- Standard library only (`pytest` optional for test discovery)
- Nmap installed on system `PATH` (for Level 1 live scans)

---

## Quick Start

### 1. Launch the Desktop Application
```bash
python main.py
```
From the main window, click **"LEVEL 2: ATTACK RECONSTRUCTION"** to open the Level 2 forensic dashboard.

### 2. Run the Reproducible Level 2 CLI Demo
You can run any of the controlled local scenarios through the complete end-to-end pipeline:
```bash
# Run multi-stage attack reconstruction demo
python run_level2_demo.py --scenario multi_stage

# Run normal traffic baseline
python run_level2_demo.py --scenario normal

# Run all scenarios sequentially
python run_level2_demo.py --scenario all
```

### 3. Run the Automated Test Suite
```bash
# Run comprehensive Level 2 test suite
python test_level2_pipeline.py

# Run all unit and integration tests via pytest
python -m pytest

# Run Level 1 scanner tests
python test_app.py

# Run Level 2 legacy transport tests
python test_level2.py

# Run GUI smoke tests
python test_gui.py
python test_gui_level2.py
```

---

## Level 2: Attack Reconstruction Details

### 1. Event Normalization (`SecurityEvent`)
Raw access and error log entries are normalized into a strongly-typed `SecurityEvent` model:
- `event_id`: Deterministic SHA-256 fingerprint (`evt-...`) preventing duplicate processing.
- `timestamp`: Normalized ISO-8601 string.
- `source_ip`, `destination`, `destination_port`.
- `method`, `path`, `protocol`, `status`, `response_size`.
- `referrer`, `user_agent`, `raw_event` (verbatim log line preserved for evidence).

### 2. Detection Engine Rules
Every detection is strictly evidence-based and avoids exaggerated claims:
- **Authentication Anomaly (`repeated-failed-authentication`)**:
  - *Rule*: $\ge 3$ failed `POST /login` attempts (HTTP 401 or 403) from the same source IP within a configurable sliding window (default 300s).
  - *Severity*: High | *MITRE*: `T1071.001` Web Protocols.
- **Account Discovery (`account-discovery-path`)**:
  - *Rule*: HTTP requests to `/users`, `/user`, `/accounts`, `/account`, `/api/users`, `/api/accounts`.
  - *Evidence statement*: Logs observe access to discovery endpoints; does not claim successful compromise.
  - *Severity*: Medium | *MITRE*: `T1087` Account Discovery.
- **Administrative Endpoint Probing (`admin-path-access`)**:
  - *Rule*: HTTP requests accessing `/admin`, `/administrator`, `/management`, `/actuator`, `/wp-admin`.
  - *Evidence statement*: Administrative endpoint probed; logged as suspicious reconnaissance.
  - *Severity*: Medium | *MITRE*: `T1071.001` Web Protocols.
- **Sensitive Resource / Transfer Access (`transfer-path-observed`)**:
  - *Rule*: Successful (HTTP 200) requests to `/export`, `/download`, `/backup`, `/dump`, `/exfil`.
  - *Evidence statement*: Transfer-like endpoint accessed; explicitly notes that HTTP logs alone cannot confirm exfiltration without packet/application inspection.
  - *Severity*: Medium | *MITRE*: `T1041` Exfiltration Over C2 Channel.

### 3. Correlation Engine
Alerts are not treated in isolation. The correlation engine groups detections by `source_ip` within a sliding window (default 900s) and identifies multi-stage attack progression:
- Reconnaissance $\to$ Account Discovery $\to$ Authentication Anomaly $\to$ Sensitive Resource Access.
- Multi-stage chains are elevated to **Critical** or **High** severity with an explicit chain summary and references to all supporting evidence events.

### 4. MITRE ATT&CK Mapping & Evidence Model
Supported techniques:
- `T1071.001` Web Protocols (administrative probing, repeated failed logins).
- `T1087` Account Discovery (probing account endpoints).
- `T1041` Exfiltration Over C2 Channel (transfer endpoint access; recorded with low confidence due to log limitations).
- `T1190` Exploit Public-Facing Application (explicitly flagged as **insufficient evidence** because web access logs cannot prove application memory/code exploitation).

### 5. Risk and Severity Assessment
Explainable, evidence-based additive scoring model (0–100):
- Administrative Probing: **+15 pts**
- Account Discovery: **+20 pts**
- Repeated Authentication Failures: **+30 pts**
- Sensitive Resource Access: **+25 pts**
- Multi-Stage Correlation Chain: **+10 pts** (up to +20)
- Level 1 Exposure Context (Target web service confirmed open): **+5 pts**

**Classification**:
- `0–29`: **Low**
- `30–59`: **Medium**
- `60–79`: **High**
- `80–100`: **Critical**

---

## Real Telemetry vs. Safe Test Scenarios

### Option A: Real Telemetry (Mac $\leftrightarrow$ Windows LAN)
1. In the Windows Dashboard (**LEVEL 2**), enter bind address (`0.0.0.0`), port (`8765`), private shared token, and click **START RECEIVER**.
2. On the Mac running Nginx, execute `mac_log_agent.py`:
   ```bash
   python3 mac_log_agent.py \
     --access-log /opt/homebrew/var/log/nginx/access.log \
     --error-log /opt/homebrew/var/log/nginx/error.log \
     --receiver-host <WINDOWS_IP> \
     --receiver-port 8765 \
     --token '<SHARED_TOKEN>'
   ```

### Option B: Controlled Local Scenarios
Built directly into the GUI and CLI:
- **Scenario A (Normal Traffic)**: Standard browsing (`GET /`, `GET /products`, successful login). Zero false positive alerts.
- **Scenario B (Authentication Anomaly)**: Repeated failed POST logins.
- **Scenario C (Account Discovery)**: Probing `/users`, `/accounts`.
- **Scenario D (Admin Probing)**: Probing `/admin`, `/management`.
- **Scenario E (Multi-stage Attack)**: Probing $\to$ Account Discovery $\to$ Brute Force $\to$ Backup download.

---

## Limitations of Web Log Telemetry

1. **Exploitation Visibility (`T1190`)**: Nginx access logs record HTTP request methods, URIs, and status codes. They cannot verify whether a memory corruption, code injection, or deserialization vulnerability succeeded inside the application.
2. **Exfiltration Confirmation (`T1041`)**: Access to a download or export URI reflects a web response, not necessarily malicious data theft or data contents.
3. **Internal Pivoting**: Nginx logs only capture ingress traffic to that specific reverse proxy; lateral movement within internal networks requires host or network telemetry.
