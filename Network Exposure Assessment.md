# Network Exposure Assessment

A standalone Python/Tkinter desktop utility for a **Level 1 network exposure assessment** and **Level 2 attack reconstruction** of an authorized lab environment. Level 1 executes a fixed Nmap scan and presents observed services. Level 2 receives authenticated telemetry sent by a Mac-side Nginx log agent, normalizes real events, applies transparent detections, maps supported activity to MITRE ATT&CK, and builds a timeline only from received evidence.

## Requirements

- Python 3.10 or newer
- Tkinter (`python3-tk` on Debian/Ubuntu)
- Nmap installed and available on `PATH`
- Local privilege configuration that permits the fixed scan command to run without an interactive password prompt

## Installation and run

```bash
python3 --version
nmap --version
python3 main.py
```

No third-party Python packages are required. The included `requirements.txt` documents this. SYN and UDP scans commonly require elevated privileges. The application intentionally uses `sudo -n`, which never prompts for or stores a password. Configure narrowly scoped, authorized local permissions for Nmap or run it from an appropriately privileged environment; do not disable system security controls globally.

## Features

- Strict IPv4/IPv6 validation via Python's `ipaddress` module.
- Fixed argument-list execution with `subprocess.Popen`; no `shell=True`, shell interpolation, or user-supplied flags.
- Background scanning with a 180-second timeout so the GUI remains responsive.
- Actual Nmap XML parsing with `xml.etree.ElementTree`.
- Open-port summary cards, service table, row-level details, raw XML transparency view, clipboard copy, and a local JSON scan history.
- Failed scans are recorded as history metadata without fabricated results.

## Level 2: Attack Reconstruction

The deployment has two sides:

```text
MAC:     Nginx + HMS + mac_log_agent.py
                  │ authenticated JSON-lines telemetry
WINDOWS: main.py + Level 2 receiver/dashboard
```

The Windows application never opens or browses Mac filesystem paths. The Mac agent reads only the two explicitly configured Nginx files, follows new entries incrementally, handles rotation/truncation, prevents duplicate event IDs, preserves raw lines, and sends authenticated events over the LAN using an HMAC shared token. It does not collect macOS unified logs or other system logs.

### Start the Windows receiver/dashboard

On Windows, start the application:

```bash
python3 main.py
```

Open **LEVEL 2: ATTACK RECONSTRUCTION**, enter a bind address, receiver port, and a private shared token, then click **START RECEIVER**. Allow the selected TCP port through the lab firewall only for the Mac agent. The dashboard reports `CONNECTED`, `DISCONNECTED`, `LAST EVENT RECEIVED`, `EVENTS RECEIVED`, and collector health.

### Start the Mac collector

On the Mac hosting Nginx/HMS, run the agent from this project directory. Replace the receiver address and token with the values configured in the Windows dashboard:

```bash
python3 mac_log_agent.py \
  --access-log /opt/homebrew/var/log/nginx/access.log \
  --error-log /opt/homebrew/var/log/nginx/error.log \
  --receiver-host WINDOWS_RECEIVER_IP \
  --receiver-port 8765 \
  --token 'CHANGE_THIS_TO_THE_PRIVATE_SHARED_TOKEN'
```

The agent reconnects when the receiver is unavailable and emits heartbeats while connected. Use a narrowly scoped lab firewall rule and protect the token; this transport is intended for a controlled LAN, not an exposed public endpoint.

The rule engine currently identifies repeated failed `POST /login` requests, administrative paths, account/user discovery paths, and transfer-like paths. These are transparent observations and do not claim successful exploitation or exfiltration. Nginx-only evidence maps observed web activity to `T1071.001` where appropriate, `T1087` for account-discovery paths, and `T1041` only as low-confidence transfer-like evidence. `T1190` is shown as **insufficient evidence** unless a future collector supplies evidence beyond Nginx HTTP logs.

Level 1 remains independent: Nmap establishes network exposure/context, while Nginx logs establish observed application activity. The UI does not claim that an Nmap result detected an attack.

### Validation and safe test workflow

```bash
python3 -m py_compile main.py scanner.py parser.py models.py history.py level2_models.py nginx_parser.py nginx_collector.py level2_detection.py level2_pipeline.py ui/dashboard.py ui/level2_dashboard.py
```

For end-to-end validation, issue ordinary authorized requests to the HMS (for example, load its normal login page or use its normal test workflow), confirm that Nginx writes the request to `access.log`, and observe the event arrive in the Windows dashboard. Do not perform exploitation, credential attacks, destructive requests, or real exfiltration. The application does not insert scenario timestamps or fabricate events.

The command displayed in the UI is:

```text
sudo -n nmap -sS -sU -sV -p T:22,80,443,3000,445,49152,U:53 -oX - <TARGET_IP>
```

Use only against systems and networks for which you have explicit authorization. Nmap scan results remain local in `scan_history.json`; Level 2 telemetry is transmitted only from the configured Mac agent to the configured authenticated Windows receiver.
