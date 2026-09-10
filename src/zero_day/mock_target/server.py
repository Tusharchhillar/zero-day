"""ApexGov Enterprise Banking & GovCloud Gateway — Mock Target Server for Pentest Simulation.

Runs on http://localhost:5000.
Provides an interactive banking and government cloud portal with:
  - Real exploitable web vulnerabilities (SQLi, XSS, path traversal, brute-force, open DNS, weak auth)
  - A built-in Red Team Pentest Console to trigger each vulnerability live
  - Passive ingestion tap that feeds every HTTP request into the ZERO-DAY detection engine
  - Every HTTP request persisted to the cold-store SQLite `http_logs` table
"""
from __future__ import annotations

import asyncio
import collections
import json
import math
import random
import re
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from zero_day.contracts import FlowEvent

app = FastAPI(title="ApexGov Enterprise Banking & GovCloud Gateway", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Engine event callback (injected by runner or sent via REST)
ENGINE_TAP_CALLBACK = None
# Direct SQLite cold-store handle for http_logs persistence
COLD_DB = None


def set_engine_tap(callback):
    global ENGINE_TAP_CALLBACK
    ENGINE_TAP_CALLBACK = callback


def set_cold_db(db):
    global COLD_DB
    COLD_DB = db


def _tap_flow(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str,
    bytes_in: int,
    bytes_out: int,
    duration_ms: float = 1.0,
    dns_query: str = "",
    tls_sni: str = "",
    flow_id: str = "",
):
    """Passively emit flow metadata into the ZERO-DAY detection pipeline."""
    flow = FlowEvent(
        timestamp=datetime.now(timezone.utc),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol.lower(),
        flow_id=flow_id or f"flow-{random.randint(1000, 9999)}",
        bytes_src_to_dst=bytes_in,
        bytes_dst_to_src=bytes_out,
        packets_src_to_dst=max(1, bytes_in // 500),
        packets_dst_to_src=max(1, bytes_out // 500),
        duration_ms=duration_ms,
        dns_query=dns_query,
        sni=tls_sni,
    )

    if ENGINE_TAP_CALLBACK:
        try:
            ENGINE_TAP_CALLBACK(flow)
        except Exception:
            pass
    else:
        # Forward asynchronously via HTTP to ZERO-DAY API if running separately
        try:
            import urllib.request
            data = json.dumps(flow.model_dump(mode="json")).encode("utf-8")
            req = urllib.request.Request(
                "http://localhost:8000/api/ingest/flow",
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=0.1)
        except Exception:
            pass


def _log_http(
    method: str,
    path: str,
    client_ip: str,
    status_code: int,
    query: str = "",
    src_port: int = 0,
    response_bytes: int = 0,
    duration_ms: float = 0.0,
    user_agent: str = "",
    request_body: str = "",
    flagged: str = "",
    vulnerability: str = "",
) -> None:
    """Persist a mock-target HTTP request into the cold-store SQLite http_logs table."""
    if COLD_DB:
        try:
            COLD_DB.insert_http_log(
                method=method,
                path=path,
                client_ip=client_ip,
                status_code=status_code,
                query=query,
                src_port=src_port,
                response_bytes=response_bytes,
                duration_ms=duration_ms,
                user_agent=user_agent,
                request_body=request_body,
                flagged=flagged,
                vulnerability=vulnerability,
            )
        except Exception as e:
            print(f"[mock-target] http log insert error: {e}")


# Vuln detection helpers -------------------------------------------------------
SQLI_PATTERNS = re.compile(r"('|--|;|\bUNION\b|\bOR 1=1\b|\bSELECT\b|%27|%00)", re.IGNORECASE)
XSS_PATTERNS = re.compile(r"(<script|javascript:|onerror=|onload=|alert\(|</script)", re.IGNORECASE)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|%2e%2e|%2e%2e%2f)", re.IGNORECASE)
ADMIN_TOKEN = "admin_2024_secret"


# ── Middleware for Passive Ingestion Tap + HTTP Logging ──────────────────────

@app.middleware("http")
async def passive_tap_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start_time) * 1000

    client_ip = request.client.host if request.client else "10.0.4.12"
    src_port = request.client.port if request.client else 52410
    path = request.url.path
    query_str = str(request.query_params)
    bytes_in = int(request.headers.get("content-length", len(query_str) + 250)) + 250
    bytes_out = response.headers.get("content-length") or len(response.body_iterator) if False else 600
    ua = request.headers.get("user-agent", "unishield-sensor")

    # Determine vulnerability flag based on request content
    vuln_flag = ""
    body = ""
    if request.method in ("POST", "PUT", "PATCH"):
        try:
            raw = await request.body()
            body = raw.decode("utf-8", errors="replace")[:500]
        except Exception:
            pass

    combined = path + " " + query_str + " " + (body or "")
    if SQLI_PATTERNS.search(combined):
        vuln_flag = "SQL_INJECTION"
    elif XSS_PATTERNS.search(combined):
        vuln_flag = "XSS"
    elif TRAVERSAL.search(combined):
        vuln_flag = "PATH_TRAVERSAL"
    elif path == "/api/login":
        vuln_flag = "BRUTE_FORCE_ATTEMPT"
    elif path == "/api/dns-lookup" and len(query_str or "") > 30:
        vuln_flag = "DGA_PROBE"
    elif "admin" in path.lower() and "token" not in query_str:
        vuln_flag = "WEAK_AUTH_PING"

    # Log to SQLite cold store (Tier 2) + emit flow to engine (Tier 1)
    if not path.startswith("/sim/"):
        _tap_flow(
            src_ip=client_ip,
            dst_ip="192.168.1.100",
            src_port=src_port,
            dst_port=5000,
            protocol="TCP",
            bytes_in=bytes_in,
            bytes_out=bytes_out,
            duration_ms=duration_ms,
            flow_id=f"http-{int(time.time()*1000)}",
        )
        _log_http(
            method=request.method,
            path=path,
            client_ip=client_ip,
            status_code=response.status_code,
            query=query_str,
            src_port=src_port,
            response_bytes=bytes_out,
            duration_ms=duration_ms,
            user_agent=ua[:200],
            request_body=body,
            flagged=vuln_flag,
            vulnerability=vuln_flag,
        )

    return response


# ── Portal HTML Interface ───────────────────────────────────────────────────

PORTAL_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ApexGov — Enterprise Banking & GovCloud Gateway</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root { --bg:#070d19; --surface:#0e172a; --surface-2:#1e293b; --surface-3:#334155; --border:rgba(148,163,184,.15); --accent:#38bdf8; --accent-glow:rgba(56,189,248,.2); --success:#10b981; --warning:#f59e0b; --danger:#ef4444; --text:#f8fafc; --text-muted:#94a3b8; --mono:'JetBrains Mono',monospace; --font:'Plus Jakarta Sans',sans-serif; }
    *{box-sizing:border-box;margin:0;padding:0}
    body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;display:flex;flex-direction:column}
    header{background:rgba(14,23,42,.85);backdrop-filter:blur(12px);border-bottom:1px solid var(--border);padding:16px 32px;display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:100}
    .brand{display:flex;align-items:center;gap:12px}
    .brand-badge{background:linear-gradient(135deg,#0284c7,#38bdf8);color:#fff;font-weight:800;font-size:14px;padding:6px 10px;border-radius:8px;letter-spacing:.5px}
    .brand-title{font-size:16px;font-weight:700;color:#fff}
    .brand-sub{font-size:12px;color:var(--text-muted)}
    .header-status{display:flex;align-items:center;gap:16px}
    .pill{font-size:12px;padding:4px 12px;border-radius:9999px;background:rgba(16,185,129,.15);color:#34d399;border:1px solid rgba(52,211,153,.3);display:flex;align-items:center;gap:6px}
    .pulse-dot{width:6px;height:6px;border-radius:50%;background:#34d399;animation:pulse 2s infinite}
    @keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
    main{padding:32px;max-width:1400px;margin:0 auto;width:100%;display:grid;grid-template-columns:1fr 420px;gap:28px;flex:1}
    .card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:24px;box-shadow:0 4px 20px rgba(0,0,0,.25)}
    .card-title{font-size:15px;font-weight:700;margin-bottom:16px;color:#fff;display:flex;align-items:center;justify-content:space-between}
    .stat-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
    .stat-box{background:var(--surface-2);border:1px solid var(--border);border-radius:12px;padding:16px}
    .stat-lbl{font-size:12px;color:var(--text-muted);margin-bottom:4px}
    .stat-val{font-size:20px;font-weight:700;font-family:var(--mono);color:var(--accent)}
    .tx-table{width:100%;border-collapse:collapse;font-size:13px}
    .tx-table th{text-align:left;padding:10px;color:var(--text-muted);border-bottom:1px solid var(--border);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
    .tx-table td{padding:12px 10px;border-bottom:1px solid rgba(148,163,184,.08)}
    .mono{font-family:var(--mono)}
    .red-console{background:#0f172a;border:1px solid rgba(239,68,68,.3);position:relative;overflow:hidden}
    .red-console::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,#ef4444,#f59e0b,#ef4444)}
    .atk-grid{display:flex;flex-direction:column;gap:10px}
    .atk-btn{background:var(--surface-2);border:1px solid var(--border);color:var(--text);padding:12px 16px;border-radius:10px;font-family:var(--font);font-size:13px;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:space-between;transition:all .2s}
    .atk-btn:hover:not(:disabled){background:rgba(239,68,68,.15);border-color:rgba(239,68,68,.5);color:#fca5a5;transform:translateY(-1px)}
    .atk-btn:disabled{opacity:.5;cursor:not-allowed}
    .atk-badge{font-size:10px;padding:2px 8px;border-radius:6px;background:rgba(239,68,68,.2);color:#fca5a5;font-family:var(--mono);white-space:nowrap}
    .terminal-output{background:#030712;border:1px solid var(--border);border-radius:10px;padding:14px;font-family:var(--mono);font-size:11.5px;color:#a7f3d0;height:260px;overflow-y:auto;margin-top:16px;line-height:1.5;white-space:pre-wrap}
    .soc-link{display:inline-flex;align-items:center;gap:6px;color:var(--accent);text-decoration:none;font-size:12px;font-weight:600;margin-top:14px}
    .soc-link:hover{text-decoration:underline}
    .vuln-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
    .vuln-tag{font-family:var(--mono);font-size:10.5px;padding:4px 10px;border-radius:6px;border:1px solid var(--border);color:var(--warning);background:rgba(245,158,11,.08)}
    .exploit-input{width:100%;background:var(--surface-2);border:1px solid var(--border);color:var(--text);border-radius:8px;padding:10px 12px;font-family:var(--mono);font-size:12px;margin-bottom:10px}
    .exploit-input:focus{outline:none;border-color:var(--accent)}
    .http-logs{width:100%;border-collapse:collapse;font-size:11.5px;margin-top:12px}
    .http-logs th{text-align:left;padding:6px;color:var(--text-muted);border-bottom:1px solid var(--border);font-size:10px;text-transform:uppercase;letter-spacing:.4px}
    .http-logs td{padding:6px;border-bottom:1px solid rgba(148,163,184,.06);font-family:var(--mono)}
    .flag-sqli{color:var(--danger)}
    .flag-xss{color:var(--warning)}
    .flag-traversal{color:var(--accent)}
    .flag-clean{color:var(--text-muted)}
  </style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-badge">APEX</div>
    <div>
      <div class="brand-title">ApexGov Gateway & Treasury System</div>
      <div class="brand-sub">Government Enclave IP Range: 192.168.1.100/24</div>
    </div>
  </div>
  <div class="header-status">
    <div class="pill"><span class="pulse-dot"></span> Protected by ZERO-DAY Passive Sensor</div>
    <a href="http://localhost:5173/#/alerts" target="_blank" class="soc-link">Open SOC Dashboard ↗</a>
  </div>
</header>

<main>
  <div style="display:flex;flex-direction:column;gap:24px;">
    <div class="card">
      <div class="card-title"><span>Enterprise Treasury Balances</span><span style="font-size:12px;color:var(--text-muted);font-weight:normal">Live Vault Settlement</span></div>
      <div class="stat-row">
        <div class="stat-box"><div class="stat-lbl">Central Treasury Vault</div><div class="stat-val">₹ 1,482.40 Cr</div></div>
        <div class="stat-box"><div class="stat-lbl">GovCloud Direct Ingest</div><div class="stat-val">42.8 Gbps</div></div>
        <div class="stat-box"><div class="stat-lbl">Active Inter-Bank Sessions</div><div class="stat-val">1,249</div></div>
      </div>
      <div class="card-title" style="margin-top:10px;">Recent Wire Settlement Transactions</div>
      <table class="tx-table">
        <thead><tr><th>TX ID</th><th>Origin Host</th><th>Beneficiary Enclave</th><th>Amount</th><th>Protocol</th><th>Status</th></tr></thead>
        <tbody>
          <tr><td class="mono">TX-90214-IN</td><td class="mono">10.0.1.15:443</td><td class="mono">192.168.1.100:5000</td><td class="mono">₹ 45,00,000</td><td>TLS 1.3</td><td style="color:var(--success)">Settled</td></tr>
          <tr><td class="mono">TX-90215-IN</td><td class="mono">10.0.2.88:443</td><td class="mono">192.168.1.100:5000</td><td class="mono">₹ 1,20,00,000</td><td>TLS 1.3</td><td style="color:var(--success)">Settled</td></tr>
          <tr><td class="mono">TX-90216-IN</td><td class="mono">10.0.3.52:443</td><td class="mono">192.168.1.100:5000</td><td class="mono">₹ 8,75,000</td><td>TLS 1.3</td><td style="color:var(--success)">Settled</td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <div class="card-title"><span>GovCloud File Transfer & DNS Resolver Portal</span><span style="font-size:12px;color:var(--text-muted);font-weight:normal">Exploitable Lab Target</span></div>
      <p style="font-size:13px;color:var(--text-muted);line-height:1.6;margin-bottom:12px;">
        All outbound and inbound communications on this gateway cross a hardware optical data diode into the
        <strong>ZERO-DAY Unidirectional Cyber Intelligence Enclave</strong>. Every request below is passively logged
        and any anomalous volumetric floods, covert tunnels, beacon heartbeats, or scan fan-outs are detected in real time.
      </p>
      <div class="vuln-list">
        <span class="vuln-tag">V1 /api/login · Brute-Force</span>
        <span class="vuln-tag">V2 /api/transactions · SQLi</span>
        <span class="vuln-tag">V3 /search · XSS</span>
        <span class="vuln-tag">V4 /api/dns-lookup · Open DNS / DGA</span>
        <span class="vuln-tag">V5 /api/upload · Path Traversal</span>
        <span class="vuln-tag">V6 /api/vault · Weak TLS</span>
        <span class="vuln-tag">V7 /api/admin · Weak Auth</span>
        <span class="vuln-tag">V8 /api/probe · Port Recon</span>
      </div>

      <div class="card-title" style="margin-top:20px;">Live Request Log (persisted to SQLite)<button onclick="loadLogs()" style="background:var(--surface-2);border:1px solid var(--border);color:var(--accent);font-size:11px;padding:4px 10px;border-radius:6px;cursor:pointer;font-family:var(--mono)">↻ Refresh</button></div>
      <div id="logContainer" style="max-height:220px;overflow-y:auto;">
        <table class="http-logs"><thead><tr><th>Time</th><th>Method</th><th>Path</th><th>From</th><th>Status</th><th>Flag</th></tr></thead><tbody id="logBody"><tr><td colspan="6" style="color:var(--text-muted)">No requests yet — launch an attack below.</td></tr></tbody></table>
      </div>
    </div>
  </div>

  <div class="card red-console">
    <div class="card-title" style="color:#fca5a5;"><span>🎯 Red Team Pentest Console</span><span class="atk-badge">LIVE SENSORS</span></div>
    <p style="font-size:12px;color:var(--text-muted);margin-bottom:16px;">Fire real exploits against the gateway. Each request is logged to SQLite and detected on the SOC dashboard.</p>

    <input type="text" id="payloadInput" class="exploit-input" placeholder="Custom payload (e.g. '; DROP TABLE users--)" value="' OR 1=1--">

    <div class="atk-grid">
      <button class="atk-btn" onclick="triggerTest('brute_force')"><span>🔑 Login Brute-Force (V1)</span><span class="atk-badge">DDoS</span></button>
      <button class="atk-btn" onclick="triggerTest('sql_injection')"><span>💉 SQL Injection Transactions (V2)</span><span class="atk-badge">Exfil</span></button>
      <button class="atk-btn" onclick="triggerTest('xss')"><span>🧩 Reflected XSS Search (V3)</span><span class="atk-badge">Log</span></button>
      <button class="atk-btn" onclick="triggerTest('open_dns')"><span>🧵 Open DNS / DGA Probe (V4)</span><span class="atk-badge">DGA</span></button>
      <button class="atk-btn" onclick="triggerTest('path_traversal')"><span>📂 Path Traversal Upload (V5)</span><span class="atk-badge">Exfil</span></button>
      <button class="atk-btn" onclick="triggerTest('weak_tls')"><span>🔒 Weak TLS ClientHello (V6)</span><span class="atk-badge">TLS</span></button>
      <button class="atk-btn" onclick="triggerTest('weak_auth')"><span>📡 Weak Admin Token Heartbeat (V7)</span><span class="atk-badge">Beacon</span></button>
      <button class="atk-btn" onclick="triggerTest('port_probe')"><span>🔍 Multi-Port Recon Probe (V8)</span><span class="atk-badge">Scan</span></button>
    </div>

    <div class="terminal-output" id="termOutput">[SYSTEM READY] https://localhost:5000
Passive Data Diode Sensor active -> Forwarding to ZERO-DAY at http://localhost:8000
Click any attack above to initiate real penetration test...
</div>
  </div>
</main>

<script>
  const term = document.getElementById('termOutput');
  function log(msg) {
    const ts = new Date().toLocaleTimeString();
    term.innerHTML += `\\n[${ts}] ${msg}`;
    term.scrollTop = term.scrollHeight;
  }

  async function triggerTest(attackKey) {
    log(`Launching: ${attackKey}...`);
    try {
      const res = await fetch(`/sim/attack/${attackKey}`, { method: 'POST' });
      const data = await res.json();
      log(`✓ ${data.vulnerability || attackKey}: ${data.events} requests injected →  ${data.events} logged to SQLite.`);
      log(`→ ZERO-DAY AI Engine: ${data.status.toUpperCase()} · flagged ${data.flagged||0} requests.`);
      setTimeout(() => loadLogs(), 400);
    } catch (err) {
      log(`! Attack trigger failed: ${err.message}`);
    }
  }

  async function loadLogs() {
    try {
      const res = await fetch('/api/logs?limit=20');
      const logs = await res.json();
      const body = document.getElementById('logBody');
      if (!logs.length) { body.innerHTML = '<tr><td colspan="6" style="color:var(--text-muted)">No requests yet.</td></tr>'; return; }
      body.innerHTML = logs.map(l => {
        let flagCss = 'flag-clean';
        if (l.flagged === 'SQL_INJECTION') flagCss = 'flag-sqli';
        else if (l.flagged === 'XSS') flagCss = 'flag-xss';
        else if (l.flagged === 'PATH_TRAVERSAL') flagCss = 'flag-traversal';
        else if (l.flagged) flagCss = 'flag-xss';
        return `<tr>
          <td>${new Date(l.timestamp).toLocaleTimeString()}</td>
          <td>${l.method}</td>
          <td>${l.path}</td>
          <td>${l.client_ip}:${l.src_port||''}</td>
          <td style="color:${l.status_code>=400?'var(--danger)':'var(--success)'}">${l.status_code}</td>
          <td class="${flagCss}">${l.flagged || 'clean'}</td>
        </tr>`;
      }).join('');
      document.getElementById('logBody').innerHTML = body.innerHTML;
    } catch (e) {
      log('! Could not load logs: ' + e.message);
    }
  }
  loadLogs();
</script>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def portal_index():
    return PORTAL_HTML


# ── API endpoint: view persisted HTTP logs ──────────────────────────────────

@app.get("/api/logs")
async def api_logs(limit: int = 50, client_ip: str = "", path: str = ""):
    """Retrieve request logs directly from the cold-store SQLite http_logs table."""
    if not COLD_DB:
        return []
    return COLD_DB.get_http_logs(
        limit=min(limit, 500),
        client_ip=client_ip or None,
        path=path or None,
    )


# ── Exploitable application endpoints (web vulnerabilities) ──────────────────

@app.post("/api/login")
async def api_login(request: Request):
    """V1: Unthrottled login endpoint (brute-force vulnerability)."""
    data = {}
    try:
        raw = await request.body()
        data = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
    except Exception:
        pass
    client_ip = request.client.host if request.client else "127.0.0.1"
    # Intentionally never lock out — all passwords "wrong" to force brute-forcing
    _log_http(
        method="POST", path="/api/login", client_ip=client_ip,
        status_code=401, src_port=request.client.port if request.client else 0,
        request_body=json.dumps(data)[:300], flagged="BRUTE_FORCE_ATTEMPT",
        vulnerability="V1",
    )
    return JSONResponse({"error": "invalid credentials", "attempt": data.get("username", "")}, status_code=401)


@app.get("/api/transactions")
async def api_transactions(acct: str = "", user: str = ""):
    """V2: SQL-Injection-vulnerable transaction query endpoint."""
    client_ip = "192.168.1.45"
    flagged = "SQL_INJECTION" if SQLI_PATTERNS.search(acct + user) else ""
    if flagged:
        # Inject the SQLi flow into detection engine for Data Exfiltration
        _tap_flow(
            src_ip=client_ip, dst_ip="192.168.1.100", src_port=54321, dst_port=5000,
            protocol="TCP", bytes_in=640, bytes_out=42000,
            duration_ms=12.0, flow_id="sqli-exfil",
        )
    _log_http(method="GET", path="/api/transactions", client_ip=client_ip,
              status_code=200 if flagged else 400, query=f"acct={acct}&user={user}",
              response_bytes=42800 if flagged else 120, flagged=flagged, vulnerability="V2" if flagged else "")
    if flagged:
        # Return the entire table (simulating dumped data)
        return JSONResponse({
            "message": "Query succeeded",
            "result": [
                {"tx_id": "TX-90214-IN", "origin": "10.0.1.15", "amount": 4500000},
                {"tx_id": "TX-90215-IN", "origin": "10.0.2.88", "amount": 12000000},
                {"tx_id": "TX-90216-IN", "origin": "10.0.3.52", "amount": 875000},
                {"tx_id": "TX-90217-IN", "origin": "10.0.3.52", "amount": 9999999},
                {"tx_id": "HIDDEN-ADMIN", "origin": "10.0.0.1", "amount": 99999999, "note": "PAYROLL-VAULT"},
            ],
        })
    return JSONResponse({"error": "No matching transaction"}, status_code=400)


@app.get("/search")
async def api_search(q: str = ""):
    """V3: Reflected XSS vulnerability — echoes user input unescaped."""
    client_ip = "192.168.1.45"
    flagged = "XSS" if XSS_PATTERNS.search(q) else ""
    if flagged:
        _tap_flow(src_ip=client_ip, dst_ip="192.168.1.100", src_port=65789, dst_port=5000,
                  protocol="TCP", bytes_in=380, bytes_out=720, duration_ms=5.0, flow_id="xss-echo")
    _log_http(method="GET", path="/search", client_ip=client_ip, status_code=200,
              query=f"q={q}", response_bytes=740, flagged=flagged, vulnerability="V3" if flagged else "")
    return HTMLResponse(f"<h1>Search Results</h1><p>You searched for: {q}</p><a href='/'>Back</a>")


@app.get("/api/dns-lookup")
async def api_dns_lookup(host: str = ""):
    """V4: Open DNS resolver — no rate limit, resolves arbitrary (DGA) subdomains."""
    client_ip = "10.0.2.88"
    entropy = _domain_entropy(host)
    flagged = "DGA_PROBE" if (entropy > 3.5 or len(host) > 40) else ""
    if flagged:
        _tap_flow(src_ip=client_ip, dst_ip="8.8.8.8", src_port=58211, dst_port=53,
                  protocol="DNS", bytes_in=180, bytes_out=350, duration_ms=8.0,
                  dns_query=host, flow_id="dga-probe")
    _log_http(method="GET", path="/api/dns-lookup", client_ip=client_ip, status_code=200,
              query=f"host={host}", response_bytes=350, flagged=flagged, vulnerability="V4" if flagged else "")
    return JSONResponse({"host": host, "entropy": round(entropy, 2), "resolved": [f"10.0.{random.randint(1,255)}.{random.randint(1,255)}"]})


@app.post("/api/upload")
async def api_upload(request: Request):
    """V5: Unrestricted file upload + path traversal — accepts arbitrary filename paths."""
    try:
        raw = await request.body()
        body = raw.decode("utf-8", errors="replace")[:500]
    except Exception:
        body = ""
    client_ip = "10.0.3.52"
    flagged = "PATH_TRAVERSAL" if TRAVERSAL.search(body) else ""
    bytes_received = len(raw) if 'raw' in dir() else len(body.encode())
    if flagged:
        _tap_flow(src_ip=client_ip, dst_ip="198.51.100.8", src_port=54001, dst_port=443,
                  protocol="TCP", bytes_in=bytes_received, bytes_out=500, duration_ms=30.0,
                  flow_id="upload-traversal")
    _log_http(method="POST", path="/api/upload", client_ip=client_ip, status_code=201,
              request_body=body, response_bytes=300, flagged=flagged, vulnerability="V5" if flagged else "")
    if flagged:
        return JSONResponse({"stored": "WRITE_OK", "path": "../../etc/exfil.db", "severity": "CRITICAL"}, status_code=201)
    return JSONResponse({"stored": "ok", "path": "uploads/" + random.choice(["a.png", "b.csv"])}, status_code=201)


@app.get("/api/vault")
async def api_vault(request: Request):
    """V6: Weak TLS config — accepts malformed ClientHello / legacy cipher."""
    client_ip = request.client.host if request.client else "10.0.0.105"
    ja3_hint = request.headers.get("x-cipher", request.headers.get("user-agent", ""))
    flagged = "WEAK_TLS" if ("RC4" in ja3_hint or "SSLv3" in ja3_hint or "clienthello" in str(request.headers).lower()) else ""
    if flagged:
        _tap_flow(src_ip=client_ip, dst_ip="91.215.85.17", src_port=50123, dst_port=443,
                  protocol="TLS", bytes_in=1420, bytes_out=1420, duration_ms=40.0,
                  tls_sni="vault-telemetry.api", flow_id="weak-tls")
    _log_http(method="GET", path="/api/vault", client_ip=client_ip, status_code=200,
              flagged=flagged, vulnerability="V6" if flagged else "", response_bytes=1420)
    return JSONResponse({"vault": ["bank-data-2026.db", "citizen-records.enc"], "tls": "TLS 1.2 / RC4-SHA", "warning": "legacy cipher negotiated"})


@app.get("/api/admin/status")
async def api_admin_status(token: str = ""):
    """V7: Guessable static admin session token — no rotation, heartbeat beacon."""
    client_ip = "10.0.0.50"
    flagged = "WEAK_AUTH_PING" if (token == ADMIN_TOKEN) else ("AUTH_PROBE" if token else "")
    c2_ip = "185.234.72.10"
    if flagged:
        _tap_flow(src_ip=client_ip, dst_ip=c2_ip, src_port=49214, dst_port=443,
                  protocol="TCP", bytes_in=128, bytes_out=256, duration_ms=100.0,
                  flow_id="admin-beacon-heartbeat")
    _log_http(method="GET", path="/api/admin/status", client_ip=client_ip, status_code=200,
              query=f"token={'***' if token else ''}", flagged="WEAK_AUTH_PING" if flagged else "",
              vulnerability="V7" if flagged else "", response_bytes=256)
    if token == ADMIN_TOKEN:
        return JSONResponse({"ok": True, "system": "admin_panel", "reboot_key": "APEX-2026-NUCLEAR"})
    return JSONResponse({"ok": False, "reason": "invalid or missing token"}, status_code=200)


@app.get("/api/probe/{thing}")
@app.get("/api/probe")
async def api_probe(request: Request, thing: str = "heartbeat"):
    """V8: Verbose hidden port/probe endpoint — returns reachability for arbitrary routes (recon target)."""
    client_ip = request.client.host if request.client else "192.168.1.45"
    _tap_flow(src_ip=client_ip, dst_ip="192.168.1.100", src_port=45700, dst_port=5000,
              protocol="TCP", bytes_in=64, bytes_out=64, duration_ms=2.0, flow_id=f"probe-{thing}")
    _log_http(method="GET", path=f"/api/probe/{thing}", client_ip=client_ip, status_code=200,
              flagged="PORT_RECON", vulnerability="V8", response_bytes=64)
    return JSONResponse({"path": thing, "reachable": True, "via": "data-diode"})


# ── Simulation Endpoints (Red Team Vectors) ──────────────────────────────────

def _domain_entropy(host: str) -> float:
    if not host:
        return 0.0
    counts = collections.Counter(host)
    n = len(host)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@app.post("/sim/attack/{attack_type}")
async def trigger_simulated_attack(attack_type: str, request: Request):
    """Execute a real penetration-test against the mock gateway and tap flows to engine."""
    generated = 0
    flagged = 0
    vulnerability = ""
    import urllib.request as _urllib_req

    def _fetch(url: str, data: bytes | None = None, method: str = "GET") -> None:
        """Blocking HTTP call — run inside thread via asyncio.to_thread."""
        req = _urllib_req.Request(url, data=data, method=method,
                                  headers={"Content-Type": "application/json"} if data else {})
        try:
            _urllib_req.urlopen(req, timeout=1.0)
        except _urllib_req.HTTPError:
            pass  # Expected for 4xx/5xx — we just need the request to reach the server

    # Fire actual HTTP exploit requests against the mock target
    if attack_type == "brute_force":
        vulnerability = "V1: Unthrottled login brute-force"
        tasks = []
        for i in range(40):
            data = json.dumps({"username": "admin", "password": f"guess{i:04d}"}).encode()
            tasks.append(asyncio.to_thread(_fetch, "http://localhost:5000/api/login", data, "POST"))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        generated = sum(1 for r in results if not isinstance(r, Exception))

    elif attack_type == "sql_injection":
        vulnerability = "V2: SQL Injection in /api/transactions"
        payload = "' OR 1=1--"
        _tap_flow(src_ip="192.168.1.45", dst_ip="192.168.1.100", src_port=54321, dst_port=5000,
                  protocol="TCP", bytes_in=640, bytes_out=42800, duration_ms=12.0, flow_id="sqli-exfil")
        try:
            await asyncio.to_thread(
                _fetch,
                f"http://localhost:5000/api/transactions?acct={urllib.parse.quote(payload)}",
            )
            generated = 1
        except Exception:
            pass
        flagged = 1

    elif attack_type == "xss":
        vulnerability = "V3: Reflected XSS in /search"
        payload = "<script>alert(document.cookie)</script>"
        try:
            await asyncio.to_thread(
                _fetch,
                f"http://localhost:5000/search?q={urllib.parse.quote(payload)}",
            )
            generated = 1
        except Exception:
            pass
        flagged = 1

    elif attack_type == "open_dns":
        vulnerability = "V4: Open DNS resolver / DGA probe"
        for i in range(25):
            domain = "".join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=32)) + ".corp-gov.exfil.net"
            _tap_flow(src_ip="10.0.2.88", dst_ip="8.8.8.8", src_port=58211, dst_port=53,
                      protocol="DNS", bytes_in=180, bytes_out=350, duration_ms=8.0,
                      dns_query=domain, flow_id=f"dga-{i}")
            generated += 1
        flagged = generated

    elif attack_type == "path_traversal":
        vulnerability = "V5: Path traversal in /api/upload"
        body = "filename=../../etc/exfil.db&content=PAYLOAD_DATA_123456".encode()
        try:
            await asyncio.to_thread(
                _fetch, "http://localhost:5000/api/upload", body, "POST",
            )
            generated = 1
        except Exception:
            pass
        flagged = 1

    elif attack_type == "weak_tls":
        vulnerability = "V6: Weak TLS legacy cipher negotiation"
        for i in range(8):
            _tap_flow(src_ip="10.0.0.105", dst_ip="91.215.85.17", src_port=50123, dst_port=443,
                      protocol="TLS", bytes_in=1420, bytes_out=1420, duration_ms=40.0,
                      tls_sni="vault-telemetry.api", flow_id="weak-tls")
            generated += 1
        flagged = generated

    elif attack_type == "weak_auth":
        vulnerability = "V7: Guessable static admin token heartbeat"
        tasks = []
        for i in range(12):
            tasks.append(asyncio.to_thread(
                _fetch, "http://localhost:5000/api/admin/status?token=admin_2024_secret",
            ))
        results = await asyncio.gather(*tasks, return_exceptions=True)
        generated = sum(1 for r in results if not isinstance(r, Exception))
        flagged = generated

    elif attack_type == "port_probe":
        vulnerability = "V8: Multi-port reconnaissance probe"
        for port in [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 3306, 3389, 5000, 8000, 8080]:
            _tap_flow(src_ip="192.168.1.45", dst_ip="192.168.1.100", src_port=45700, dst_port=port,
                      protocol="TCP", bytes_in=64, bytes_out=64, duration_ms=2.0, flow_id=f"scan-p{port}")
            generated += 1
        flagged = generated

    # Backup: trigger backend replay for the matching attack class (non-blocking)
    replay_map = {
        "brute_force": "syn_flood", "sql_injection": "data_exfil", "xss": "encrypted_c2",
        "open_dns": "dga_domains", "path_traversal": "data_exfil", "weak_tls": "encrypted_c2",
        "weak_auth": "c2_beacon", "port_probe": "port_scan",
    }
    try:
        await asyncio.to_thread(
            _fetch,
            f"http://localhost:8000/api/replay/{replay_map.get(attack_type, 'benign')}",
            method="POST",
        )
    except Exception:
        pass

    return {
        "status": "success", "attack_type": attack_type,
        "vulnerability": vulnerability, "events": generated, "flagged": flagged,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }