# BLACKFEATHER — Deployment Guide

## Project Structure

```
blackfeather/
├── agent/
│   └── blackfeather_agent.py       # Endpoint agent
├── engine/
│   ├── mitre_knowledge.py          # MITRE ATT&CK data layer
│   ├── mitre_mapping.py            # Behavior → technique mapping
│   ├── detection_engine.py         # Behavioral + signature detection
│   └── ai_engine.py                # AI analysis, prediction, chain
├── dashboard/
│   └── index.html                  # SOC dashboard (served by backend)
├── data/                           # Auto-created, stores machine JSON
├── blackfeather_server.py          # FastAPI backend (entry point)
└── requirements.txt
```

---

## 1. BACKEND SETUP

### Install dependencies
```bash
pip install -r requirements.txt
```

### Run backend
```bash
# From the blackfeather/ root directory
uvicorn blackfeather_server:app --host 0.0.0.0 --port 8000
```

The backend will serve:
- Dashboard UI:  http://localhost:8000/
- API docs:      http://localhost:8000/docs
- Ingest API:    http://localhost:8000/api/ingest  (POST, used by agents)

### Internet exposure (ngrok)
```bash
# Install ngrok from https://ngrok.com
ngrok http 8000
# Use the https://xxxx.ngrok.io URL as your --server for agents
```

---

## 2. ENDPOINT AGENT

### Run (Python)
```bash
# From agent directory
pip install psutil requests
python blackfeather_agent.py --server http://YOUR_SERVER:8000

# Options:
#   --server     Backend URL (required)
#   --interval   Collection interval in seconds (default: 30)
#   --once       Collect one snapshot and exit (testing)
```

### Build Windows EXE
```bash
cd agent/
pip install pyinstaller
pyinstaller --onefile --name blackfeather_agent --noconsole blackfeather_agent.py
# Output: dist/blackfeather_agent.exe
```

### Deploy EXE on Windows endpoint
```cmd
blackfeather_agent.exe --server https://your-server-url
```

### Run as Windows Service (optional)
```cmd
# Using NSSM (Non-Sucking Service Manager)
nssm install BLACKFEATHER "C:\path\to\blackfeather_agent.exe" "--server https://your-server-url"
nssm start BLACKFEATHER
```

---

## 3. VERIFY DEPLOYMENT

```bash
# Check backend health
curl http://localhost:8000/api/stats

# Send test telemetry manually
curl -X POST http://localhost:8000/api/ingest \
  -H "Content-Type: application/json" \
  -d '{"machine_id":"test-001","machine_name":"TESTPC","os":"Windows 10","timestamp":"2024-01-01T00:00:00Z","processes":[{"pid":1234,"name":"powershell.exe","cmdline":"powershell -enc AAAA==","parent_pid":456,"parent_name":"winword.exe","create_time":"2024-01-01T00:00:00Z","connections":[],"cpu_percent":5,"memory_mb":50}],"network":[]}'
```

---

## 4. MULTI-MACHINE DEPLOYMENT

Each machine runs the agent independently:
```
Machine A → blackfeather_agent.exe --server https://server-url
Machine B → blackfeather_agent.exe --server https://server-url
Machine C → blackfeather_agent.exe --server https://server-url
```

All agents report to the same backend. The dashboard shows all machines in the sidebar, color-coded by threat level.

---

## 5. DASHBOARD FEATURES

| Feature | Location |
|---|---|
| Machine list (real-time) | Sidebar |
| Attack score ring | Overview tab |
| AI attack narrative | Overview tab |
| Attack chain visualization | Overview tab |
| Risk trend graph | Overview tab |
| MITRE techniques table | ATT&CK tab |
| Malware family matches | ATT&CK tab |
| Behavioral alerts | Alerts tab |
| Intent / Personality | AI Analysis tab |
| Prediction engine | AI Analysis tab |
| Mitigations | AI Analysis tab |
| Full structured report | Report tab |
| Download report (JSON) | Report tab |

---

## 6. DETECTION CAPABILITIES

### Behavioral Detection
- Parent-child process anomalies (Office → PowerShell, etc.)
- CPU burst / memory spike detection
- Process masquerading (fake svchost, lsass)
- Suspicious network connections (RAT/C2 ports)

### Signature Detection
- 40+ malicious command patterns
- High-risk binary names (mimikatz, procdump, etc.)
- Encoded PowerShell, LOLBin abuse, credential dumping

### MITRE ATT&CK Coverage
- 14 tactics, 60+ techniques mapped
- 25+ malware families tracked (WannaCry, Cobalt Strike, LockBit...)

### AI Analysis
- Natural language attack story
- Intent classification (8 categories)
- Attack personality profiling
- Kill-chain prediction
- Risk scoring (0-100)

---

## 7. SECURITY NOTES

- This is a **defensive** monitoring tool
- Agent runs with user-level privileges (elevate for full process access)
- All data stays on your infrastructure
- No external API calls required (fully offline-capable)
- Secure the backend behind a reverse proxy + TLS in production
- Restrict `/api/ingest` to known agent IPs in production
