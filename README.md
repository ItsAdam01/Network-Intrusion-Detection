# Network Intrusion Detection System (NIDS + WAF)

A full-stack, real-time network security monitoring dashboard combining a **Network Intrusion Detection System (NIDS)** and a **Web Application Firewall (WAF)**. Threats are detected live and streamed to a terminal-aesthetic React frontend via Socket.IO.

---

## Features

### NIDS — Network Layer
Sniffs traffic on all interfaces (loopback + real NICs) using Scapy and detects:

| Attack Type | Severity | Detection Method |
|---|---|---|
| ICMP Echo Request | Low | ICMP type 8 packets |
| NULL Scan | Medium | TCP flags = 0x00 |
| XMAS Scan | Medium | TCP FIN+PSH+URG flags |
| Port Scan | Medium | ≥8 unique SYN ports in 30s |
| SYN Flood | Critical | ≥15 SYNs to non-owned ports in 15s |
| Cleartext Credentials | High | `username=` / `password=` in payload |

### WAF — Application Layer
Inspects forwarded HTTP request data (method, path, headers, body, params):

| Rule | Severity |
|---|---|
| SQL Injection (UNION, DROP, OR bypass, time-based, stacked) | Critical |
| XSS (script tags, event handlers, javascript:, eval) | High |
| Path Traversal (../,  /etc/passwd, cmd.exe, /bin/sh) | Critical |
| Malicious Scanner User-Agent (sqlmap, nikto, nmap, etc.) | Critical |
| Brute Force Login (≥5 failures in 30s window) | Critical |
| Oversized Payload (>1 MB body) | High |

### Frontend Dashboard
- Two-tab interface: **NIDS** (network layer) and **WAF** (application layer)
- Real-time alert feed with severity color-coding (Critical / High / Medium / Low)
- Live packet counters and protocol breakdown (TCP / UDP / ICMP / Other)
- WAF stats: total requests, blocked, passed, block rate %
- **NIDS Attack Simulator** — fire test attacks from the UI with a single click
- **WAF Request Inspector** — send custom payloads and see alerts inline
- Expandable alert rows showing raw payload with syntax highlighting

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              React Frontend (3000)           │
│   NIDS Tab ◄──────────── Socket.IO ──────►  │
│   WAF Tab                                   │
└────────────┬────────────────────┬───────────┘
             │ HTTP + Socket.IO   │ HTTP + Socket.IO
             ▼                   ▼
    ┌─────────────────┐  ┌─────────────────┐
    │  app.py (:5000) │  │ waf_app.py(:5001│
    │  Flask + NIDS   │  │  Flask + WAF    │
    └────────┬────────┘  └─────────────────┘
             │
    ┌────────▼────────┐
    │   engine.py     │  Scapy packet sniffer
    │   attacker.py   │  Attack simulator
    └─────────────────┘
```

---

## Project Structure

```
Network-Intrusion-Detection/
├── backend/
│   ├── app.py          # Flask server + NIDS entry point (port 5000)
│   ├── engine.py       # Scapy sniffer, packet analysis, alert emission
│   ├── attacker.py     # Attack simulation scripts (Scapy + raw sockets)
│   ├── waf_app.py      # WAF Flask server (port 5001)
│   └── test_waf.py     # Pytest suite for the WAF (100+ tests)
└── frontend/
    └── src/
        └── App.js      # React dashboard (single-file, IBM Plex Mono aesthetic)
```

---

## Requirements

### Backend
- Python 3.8+
- `flask`, `flask-socketio`, `flask-cors`
- `scapy` (required for NIDS packet capture)
- `pytest` (for running the test suite)

Install dependencies:
```bash
pip install flask flask-socketio flask-cors scapy pytest --break-system-packages
```

> ⚠️ **Root/sudo is required** for Scapy to capture raw packets.

### Frontend
- Node.js 16+
- React (Create React App)
- `socket.io-client`

---

## Getting Started

### 1. Start the NIDS backend
```bash
cd backend
sudo python app.py
```
Starts on **port 5000**. Launches the Scapy sniffer in a background thread.

### 2. Start the WAF backend
```bash
cd backend
python waf_app.py
```
Starts on **port 5001**. No root required.

### 3. Start the frontend
```bash
cd frontend
npm install
npm start
```
Opens at **http://localhost:3000**.

---

## Running Attack Simulations

### From the UI
Navigate to the **NIDS** tab in the dashboard and use the **Attack Simulator** panel to fire individual attacks with one click.

### From the command line
```bash
cd backend
sudo python attacker.py
```
Runs the full simulation sequence: ICMP ping → NULL scan → XMAS scan → Port scan → SYN flood → Cleartext credentials.

### Via API
```bash
curl -X POST http://localhost:5000/simulate \
  -H "Content-Type: application/json" \
  -d '{"attack": "syn_flood"}'
```

Available attack IDs: `icmp`, `null_scan`, `xmas_scan`, `port_scan`, `syn_flood`, `cleartext`

---

## Running Tests

```bash
cd backend
pytest test_waf.py -v
```

The test suite covers:
- False positive regression (infrastructure headers must not trigger alerts)
- SQL injection detection (15+ patterns, case-insensitive)
- XSS detection (script tags, event handlers, protocol handlers)
- Path traversal detection (Unix and Windows paths, encoded sequences)
- Malicious user-agent blocking (sqlmap, nikto, nmap, burpsuite, etc.)
- Oversized payload blocking
- Brute force detection and counter reset logic
- Stats counter accuracy
- Multiple simultaneous threat detection

---

## API Reference

### NIDS Server (`localhost:5000`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check |
| POST | `/simulate` | Trigger an attack simulation |

**POST `/simulate`**
```json
{ "attack": "syn_flood" }
```

**Socket.IO events emitted:**
- `new_alert` — a detected threat event
- `traffic_stats` — packet counts by protocol

### WAF Server (`localhost:5001`)

| Method | Endpoint | Description |
|---|---|---|
| GET | `/` | Health check + stats |
| POST | `/inspect` | Analyze a forwarded request |
| POST | `/login` | Demo login endpoint (brute force detection) |

**POST `/inspect`**
```json
{
  "method": "POST",
  "path": "/search",
  "body": "' OR 1=1--",
  "headers": { "User-Agent": "Mozilla/5.0" },
  "params": {}
}
```

**Socket.IO events emitted:**
- `waf_alert` — a blocked/detected threat
- `waf_stats` — running totals (total, blocked, passed)

---

## Notes

- The NIDS engine uses `sendp()` (L2) via Scapy on the loopback interface (`lo`) to ensure simulated packets are captured correctly on Linux.
- Own service ports (5000, 5001, 8080) are excluded from SYN flood and port scan tracking to avoid false positives from normal Socket.IO traffic.
- Alerts are deduplicated within a 1.5-second window per `(type, src)` pair to suppress repeated events from high-rate attacks.
- The WAF only scans user-controlled inputs (body, path, params, and a whitelist of security-relevant headers like `cookie`, `user-agent`, `referer`) — not infrastructure headers like `Content-Type` or `Connection` — to eliminate false positives.
