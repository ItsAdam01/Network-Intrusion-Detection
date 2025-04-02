"""
waf_app.py — Web Application Firewall (WAF) / Application-Level IDS

Endpoints:
  POST /inspect          — send any HTTP request data for analysis
  POST /login            — demo login endpoint (triggers brute-force detection)
  GET  /                 — health check

The WAF emits Socket.IO events:
  waf_alert              — a detected threat  { type, severity, source, message, ... }
  waf_stats              — running totals      { total, blocked, passed, time }
"""

from flask import Flask, request, jsonify
from flask_socketio import SocketIO
from flask_cors import CORS
import datetime
import time
import re
from collections import defaultdict

app      = Flask(__name__)
CORS(app, origins="*")
socketio = SocketIO(app, cors_allowed_origins="*")

#  Counters 
stats = {"total": 0, "blocked": 0, "passed": 0, "auth_failed": 0}

#  Brute force tracking: ip → {attempts, window_start} 
brute_tracker   = defaultdict(lambda: {"attempts": 0, "window_start": time.time()})
BRUTE_THRESHOLD = 5   # failed attempts before alert
BRUTE_WINDOW    = 30  # seconds


SCANNED_HEADERS = {"user-agent", "referer", "cookie", "x-forwarded-for",
                   "x-real-ip", "origin", "authorization"}

#  SQL injection patterns ─
SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
    r"(--|#|/\*)",                         # SQL comments
    r"('\s*(OR|AND)\s*'?\d)",              # ' OR 1=1
    r"(;\s*(DROP|DELETE|INSERT|UPDATE))",  # stacked queries
    r"(SLEEP\s*\(|BENCHMARK\s*\()",        # time-based blind SQLi
    r"(xp_cmdshell|EXEC\s*\()",           # MSSQL exec
]
SQL_REGEX = re.compile("|".join(SQL_PATTERNS), re.IGNORECASE)

#  XSS patterns 
XSS_PATTERNS = [
    r"<script[\s>]",
    r"javascript\s*:",
    r"on\w+\s*=",           # onerror=, onload=, onclick=, etc.
    r"<iframe[\s>]",
    r"<img[^>]+src\s*=\s*['\"]?\s*javascript",
    r"eval\s*\(",
    r"document\.(cookie|location|write)",
]
XSS_REGEX = re.compile("|".join(XSS_PATTERNS), re.IGNORECASE)

#  Path traversal 
TRAVERSAL_PATTERNS = [
    r"\.\./", r"\.\.\\", r"%2e%2e",
    r"/etc/passwd", r"/etc/shadow",
    r"c:\\windows", r"cmd\.exe",
    r"/bin/sh", r"/bin/bash",
]
TRAVERSAL_REGEX = re.compile("|".join(TRAVERSAL_PATTERNS), re.IGNORECASE)

#  Suspicious user agents ─
BAD_UA = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|hydra|medusa|burpsuite|"
    r"metasploit|havij|acunetix|w3af|openvas)", re.IGNORECASE
)


def emit_alert(type_, severity, source, message, extra=None):
    stats["blocked"] += 1
    alert = {
        "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
        "type":      type_,
        "severity":  severity,
        "source":    source,
        "message":   message,
    }
    if extra:
        alert.update(extra)
    socketio.emit('waf_alert', alert)
    print(f"[WAF] {severity:8s} | {type_} | {source} | {message[:60]}")
    return alert


def emit_stats():
    socketio.emit('waf_stats', {**stats, "time": datetime.datetime.now().strftime("%H:%M:%S")})


def analyze_request(ip, method, path, headers, body, params):
    """
    Run all WAF rules. Returns list of alert dicts.

    IMPORTANT: Only user-controlled inputs are scanned for injection patterns.
    Infrastructure headers (Content-Type, Content-Length, Accept, Connection,
    Host, etc.) are intentionally excluded — they contain words like DELETE and
    UPDATE that would cause constant false positives against the SQL regex.
    """
    found = []

    #  User-Agent check (separate, targeted) 
    # Normalize key lookup — headers dict may use any casing
    ua = next((v for k, v in headers.items() if k.lower() == "user-agent"), "")
    if BAD_UA.search(ua):
        found.append(emit_alert(
            "Malicious Scanner", "Critical", ip,
            f"Known attack tool user agent: {ua[:80]}",
            {"method": method, "path": path}
        ))

    #  Build scan surface: only user-controlled inputs 
    scanned_header_values = " ".join(
        str(v) for k, v in headers.items()
        if k.lower() in SCANNED_HEADERS
    )
    all_input = " ".join(filter(None, [
        path,
        str(body),
        " ".join(str(v) for v in params.values()),
        scanned_header_values,
    ]))

    #  SQL injection 
    if SQL_REGEX.search(all_input):
        found.append(emit_alert(
            "SQL Injection", "Critical", ip,
            f"SQL pattern detected in {method} {path}",
            {"method": method, "path": path, "snippet": all_input[:120]}
        ))

    #  XSS 
    if XSS_REGEX.search(all_input):
        found.append(emit_alert(
            "XSS Attempt", "High", ip,
            f"Cross-site scripting pattern in {method} {path}",
            {"method": method, "path": path}
        ))

    #  Path traversal ─
    if TRAVERSAL_REGEX.search(all_input):
        found.append(emit_alert(
            "Path Traversal", "Critical", ip,
            f"Directory traversal attempt on {path}",
            {"method": method, "path": path}
        ))

    #  Oversized body ─
    if len(str(body)) > 1_000_000:
        found.append(emit_alert(
            "Oversized Payload", "High", ip,
            f"Request body {len(str(body)):,} bytes — possible DoS attempt",
            {"method": method, "path": path}
        ))

    return found


#  Routes 

@app.route('/')
def health():
    return jsonify({"status": "WAF running", "stats": stats})


@app.route('/inspect', methods=['POST'])
def inspect():
    """Generic endpoint — analyze any forwarded request."""
    stats["total"] += 1
    ip      = request.remote_addr or "unknown"
    data    = request.get_json(silent=True) or {}
    method  = data.get("method", request.method)
    path    = data.get("path", request.path)
    # Use caller-supplied headers if provided, otherwise fall back to real headers
    # but strip infrastructure headers to avoid false positives
    headers = data.get("headers") or {
        k: v for k, v in request.headers.items()
        if k.lower() in SCANNED_HEADERS | {"user-agent"}
    }
    body    = data.get("body", "")
    params  = data.get("params", {})

    alerts = analyze_request(ip, method, path, headers, str(body), params)
    if not alerts:
        stats["passed"] += 1

    emit_stats()
    return jsonify({
        "blocked": len(alerts) > 0,
        "alerts":  alerts,
        "stats":   stats,
    })


@app.route('/login', methods=['POST'])
def login():
    """Demo login — detects brute force + credential stuffing."""
    stats["total"] += 1
    ip   = request.remote_addr or "unknown"
    data = request.get_json(silent=True) or {}
    user = data.get("username", "")
    pwd  = data.get("password", "")

    # Only pass user-supplied values — not all request headers
    analyze_request(
        ip, "POST", "/login",
        {"user-agent": request.headers.get("User-Agent", "")},
        f"username={user}&password={pwd}",
        {"username": user, "password": pwd}
    )

    #  Brute force detection 
    tracker = brute_tracker[ip]
    now     = time.time()
    if now - tracker["window_start"] > BRUTE_WINDOW:
        tracker["attempts"]     = 0
        tracker["window_start"] = now

    success = (user == "admin" and pwd == "correct")
    if not success:
        tracker["attempts"] += 1
        if tracker["attempts"] >= BRUTE_THRESHOLD:
            emit_alert(
                "Brute Force Login", "Critical", ip,
                f"{tracker['attempts']} failed login attempts in {BRUTE_WINDOW}s for user '{user}'",
                {"method": "POST", "path": "/login", "username": user}
            )
            tracker["attempts"] = 0

    if success:
        stats["passed"] += 1
    else:
        stats["auth_failed"] += 1

    emit_stats()
    return jsonify({
        "success": success,
        "blocked": not success,
        "alerts":  [],
        "message": "OK" if success else "Invalid credentials",
    })


if __name__ == '__main__':
    print("--- WAF Server Starting on port 5001 ---")
    socketio.run(app, host='0.0.0.0', port=5001, debug=True)