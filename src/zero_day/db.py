"""Database storage repository for ZERO-DAY SIH26145.

Dual storage engine:
1. SQLite Local Engine (fallback & fast local caching)
2. Supabase Cloud PostgreSQL (remote synchronization & multi-dashboard sync)
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from zero_day.contracts import AlertV1, EvidenceItem, Severity, ThreatClass

CLASS_TO_SIH: Dict[str, str] = {
    "volumetric_ddos": "Volumetric / Protocol DDoS",
    "ddos": "Volumetric / Protocol DDoS",
    "botnet_c2_beacon": "Botnet C2 Beaconing",
    "dga_domains": "DGA / DNS Tunnelling",
    "dns_tunnelling": "DGA / DNS Tunnelling",
    "encrypted_malware": "Malicious Encrypted Sessions",
    "reconnaissance_port_scan": "Reconnaissance / Port Scanning",
    "port_scan": "Reconnaissance / Port Scanning",
    "data_exfiltration": "Data Exfiltration",
    "exfiltration": "Data Exfiltration",
    "benign": "Benign Traffic",
}


class AlertDB:
    """Thread-safe SQLite & Supabase persistent alert repository."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        
        # Supabase config from environment
        self.supabase_url = os.getenv("SUPABASE_URL", "https://czvjvwtvmyvajhlbwrud.supabase.co").rstrip("/")
        self.supabase_key = os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN6dmp2d3R2bXl2YWpobGJ3cnVkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkwMDgxNzMsImV4cCI6MjEwNDU4NDE3M30.xNtvspUnHzaUGwD2DgHybHc64Xz52Ahd_dK3tcBvmjI")
        
        self._init_schema()
        self._seed_if_empty()

    def _supabase_request(
        self,
        method: str,
        path_suffix: str = "",
        body: Optional[Any] = None,
        headers_extra: Optional[Dict[str, str]] = None,
    ) -> Optional[Any]:
        """Perform a REST call to Supabase PostgREST endpoint."""
        if not self.supabase_url or not self.supabase_key:
            return None
        url = f"{self.supabase_url}/rest/v1/alerts{path_suffix}"
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        if headers_extra:
            headers.update(headers_extra)

        data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data_bytes, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                res_text = resp.read().decode("utf-8")
                return json.loads(res_text) if res_text else []
        except Exception as e:
            # Fallback gracefully if Supabase network is interrupted
            return None

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._get_connection() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    flow_id TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER DEFAULT 443,
                    dst_port INTEGER DEFAULT 443,
                    protocol TEXT DEFAULT 'TCP',
                    threat_class TEXT NOT NULL,
                    sih_category TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'New',
                    detector TEXT,
                    evidence_json TEXT,
                    model_version TEXT DEFAULT '1.0',
                    observation_window_s REAL DEFAULT 0.0,
                    source_rate REAL,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts (timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts (severity);
                CREATE INDEX IF NOT EXISTS idx_alerts_threat ON alerts (threat_class);
                CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
                CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts (src_ip);

                CREATE TABLE IF NOT EXISTS http_logs (
                    log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    query TEXT,
                    client_ip TEXT,
                    src_port INTEGER,
                    status_code INTEGER,
                    response_bytes INTEGER,
                    duration_ms REAL,
                    user_agent TEXT,
                    request_body TEXT,
                    flagged TEXT,
                    vulnerability TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_http_logs_timestamp ON http_logs (timestamp DESC);
                CREATE INDEX IF NOT EXISTS idx_http_logs_path ON http_logs (path);
                CREATE INDEX IF NOT EXISTS idx_http_logs_client_ip ON http_logs (client_ip);
            """)

    def insert_alert(self, alert: AlertV1, status: Optional[str] = None) -> None:
        """Insert or update an alert locally and sync to Supabase."""
        tc_val = alert.threat_class.value if hasattr(alert.threat_class, "value") else str(alert.threat_class)
        sih_cat = CLASS_TO_SIH.get(tc_val, "Botnet C2 Beaconing")
        sev_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        alert_status = status or getattr(alert, "status", "New") or "New"
        evidence_list = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in alert.evidence]
        ev_json = json.dumps(evidence_list)
        ts_str = alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)

        # 1. Local SQLite store
        with self._lock, self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, flow_id, src_ip, dst_ip,
                    src_port, dst_port, protocol, threat_class, sih_category,
                    severity, confidence, status, detector, evidence_json,
                    model_version, observation_window_s, source_rate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.alert_id, ts_str, alert.flow_id, alert.src_ip, alert.dst_ip,
                alert.src_port, alert.dst_port, alert.protocol.upper(), tc_val, sih_cat,
                sev_val, float(alert.confidence), alert_status, alert.detector, ev_json,
                alert.model_version, float(alert.observation_window_s), alert.source_rate, time.time(),
            ))

        # 2. Supabase Cloud Sync
        if self.supabase_url and self.supabase_key:
            sp_payload = {
                "alert_id": alert.alert_id,
                "timestamp": ts_str,
                "flow_id": alert.flow_id,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "protocol": alert.protocol.upper(),
                "threat_class": tc_val,
                "sih_category": sih_cat,
                "severity": sev_val,
                "confidence": float(alert.confidence),
                "status": alert_status,
                "detector": alert.detector,
                "evidence": evidence_list,
                "model_version": alert.model_version,
                "observation_window_s": float(alert.observation_window_s),
                "source_rate": float(alert.source_rate) if alert.source_rate else None,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            self._supabase_request(
                "POST",
                body=[sp_payload],
                headers_extra={"Prefer": "resolution=merge-duplicates,return=representation"},
            )

    def bulk_insert_alerts(self, alerts: List[AlertV1]) -> None:
        """Batch insert multiple alerts locally and into Supabase."""
        if not alerts:
            return
        rows = []
        sp_rows = []
        now = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()

        for a in alerts:
            tc_val = a.threat_class.value if hasattr(a.threat_class, "value") else str(a.threat_class)
            sih_cat = CLASS_TO_SIH.get(tc_val, "Botnet C2 Beaconing")
            sev_val = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            alert_status = getattr(a, "status", "New") or "New"
            evidence_list = [e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in a.evidence]
            ev_json = json.dumps(evidence_list)
            ts_str = a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp)

            rows.append((
                a.alert_id, ts_str, a.flow_id, a.src_ip, a.dst_ip,
                a.src_port, a.dst_port, a.protocol.upper(), tc_val, sih_cat,
                sev_val, float(a.confidence), alert_status, a.detector, ev_json,
                a.model_version, float(a.observation_window_s), a.source_rate, now,
            ))

            sp_rows.append({
                "alert_id": a.alert_id,
                "timestamp": ts_str,
                "flow_id": a.flow_id,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "src_port": a.src_port,
                "dst_port": a.dst_port,
                "protocol": a.protocol.upper(),
                "threat_class": tc_val,
                "sih_category": sih_cat,
                "severity": sev_val,
                "confidence": float(a.confidence),
                "status": alert_status,
                "detector": a.detector,
                "evidence": evidence_list,
                "model_version": a.model_version,
                "observation_window_s": float(a.observation_window_s),
                "source_rate": float(a.source_rate) if a.source_rate else None,
                "created_at": now_iso,
            })

        with self._lock, self._get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, flow_id, src_ip, dst_ip,
                    src_port, dst_port, protocol, threat_class, sih_category,
                    severity, confidence, status, detector, evidence_json,
                    model_version, observation_window_s, source_rate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

        if self.supabase_url and self.supabase_key and sp_rows:
            self._supabase_request(
                "POST",
                body=sp_rows,
                headers_extra={"Prefer": "resolution=merge-duplicates,return=representation"},
            )

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query persistent alerts, prioritizing Supabase if connected."""
        if self.supabase_url and self.supabase_key:
            params = f"?select=*&order=timestamp.desc&limit={limit}&offset={offset}"
            if severity and severity != "All":
                params += f"&severity=eq.{urllib.parse.quote(severity.upper())}"
            if status and status != "All":
                params += f"&status=eq.{urllib.parse.quote(status)}"
            if threat_class and threat_class != "All":
                params += f"&threat_class=eq.{urllib.parse.quote(threat_class)}"

            res = self._supabase_request("GET", path_suffix=params)
            if res is not None and isinstance(res, list) and len(res) > 0:
                for r in res:
                    r["source"] = {"ip": r.get("src_ip", "0.0.0.0"), "port": r.get("src_port", 443)}
                    r["destination"] = {"ip": r.get("dst_ip", "0.0.0.0"), "port": r.get("dst_port", 443)}
                return res

        query = "SELECT * FROM alerts WHERE 1=1"
        params_sql: List[Any] = []

        if severity and severity != "All":
            query += " AND severity = ?"
            params_sql.append(severity.upper())

        if threat_class and threat_class != "All":
            query += " AND (threat_class = ? OR sih_category = ?)"
            params_sql.extend([threat_class, threat_class])

        if status and status != "All":
            query += " AND status = ?"
            params_sql.append(status)

        if search:
            query += " AND (alert_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR threat_class LIKE ? OR sih_category LIKE ?)"
            s_param = f"%{search}%"
            params_sql.extend([s_param, s_param, s_param, s_param, s_param])

        query += " ORDER BY timestamp DESC, created_at DESC LIMIT ? OFFSET ?"
        params_sql.extend([limit, offset])

        with self._lock, self._get_connection() as conn:
            rows = conn.execute(query, params_sql).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single alert with full forensic evidence by ID."""
        if self.supabase_url and self.supabase_key:
            res = self._supabase_request("GET", path_suffix=f"?alert_id=eq.{alert_id}&select=*")
            if res and isinstance(res, list) and len(res) > 0:
                r = res[0]
                r["source"] = {"ip": r.get("src_ip", "0.0.0.0"), "port": r.get("src_port", 443)}
                r["destination"] = {"ip": r.get("dst_ip", "0.0.0.0"), "port": r.get("dst_port", 443)}
                return r

        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def update_status(self, alert_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Update lifecycle status of an alert."""
        valid_statuses = {"New", "Investigating", "Acknowledged", "Resolved", "Dismissed"}
        if new_status not in valid_statuses:
            return None

        with self._lock, self._get_connection() as conn:
            conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
            conn.commit()

        if self.supabase_url and self.supabase_key:
            self._supabase_request("PATCH", path_suffix=f"?alert_id=eq.{alert_id}", body={"status": new_status})

        return self.get_alert_by_id(alert_id)

    def count(self) -> int:
        """Total count of stored alerts."""
        with self._lock, self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def clear_all_alerts(self) -> int:
        """Delete all alerts from both SQLite and Supabase. Returns count deleted."""
        with self._lock, self._get_connection() as conn:
            count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            conn.execute("DELETE FROM alerts")
            conn.commit()

        if self.supabase_url and self.supabase_key:
            self._supabase_request("DELETE", path_suffix="")

        return count

    def insert_http_log(
        self,
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
        """Persist a mock-target HTTP request into the cold-store http_logs table."""
        try:
            with self._lock, self._get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO http_logs (
                        timestamp, method, path, query, client_ip, src_port,
                        status_code, response_bytes, duration_ms, user_agent,
                        request_body, flagged, vulnerability
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        datetime.now(timezone.utc).isoformat(),
                        method,
                        path,
                        query,
                        client_ip,
                        src_port,
                        status_code,
                        response_bytes,
                        duration_ms,
                        user_agent,
                        request_body,
                        flagged,
                        vulnerability,
                    ),
                )
        except Exception:
            pass

    def get_http_logs(
        self,
        limit: int = 50,
        client_ip: Optional[str] = None,
        path: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve persisted HTTP request logs from the cold-store http_logs table."""
        query = "SELECT * FROM http_logs WHERE 1=1"
        params: List[Any] = []
        if client_ip:
            query += " AND client_ip = ?"
            params.append(client_ip)
        if path:
            query += " AND path = ?"
            params.append(path)
        query += " ORDER BY log_id DESC LIMIT ?"
        params.append(limit)
        with self._lock, self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_metrics(self) -> Dict[str, Any]:
        """Aggregate summary metrics from database."""
        with self._lock, self._get_connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            sev_rows = conn.execute("SELECT severity, COUNT(*) FROM alerts GROUP BY severity").fetchall()
            cat_rows = conn.execute("SELECT sih_category, COUNT(*) FROM alerts GROUP BY sih_category").fetchall()
            stat_rows = conn.execute("SELECT status, COUNT(*) FROM alerts GROUP BY status").fetchall()

            return {
                "total_alerts": total,
                "severity_distribution": {r[0]: r[1] for r in sev_rows},
                "category_distribution": {r[0]: r[1] for r in cat_rows},
                "status_distribution": {r[0]: r[1] for r in stat_rows},
            }

    def _row_to_dict(self, row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        ev_raw = d.pop("evidence_json", "[]")
        try:
            d["evidence"] = json.loads(ev_raw)
        except Exception:
            d["evidence"] = []
        d["source"] = {"ip": d.get("src_ip", "0.0.0.0"), "port": d.get("src_port", 443)}
        d["destination"] = {"ip": d.get("dst_ip", "0.0.0.0"), "port": d.get("dst_port", 443)}
        return d

    def _seed_if_empty(self) -> None:
        """Seed initial high-fidelity alerts if database is clean."""
        if self.count() > 0:
            return

        now = datetime.now(timezone.utc)
        seeds = [
            AlertV1(
                alert_id="alt-ddos-001",
                timestamp=now,
                flow_id="flood-9821",
                src_ip="198.51.100.42",
                dst_ip="192.168.1.100",
                src_port=53210,
                dst_port=443,
                protocol="TCP",
                threat_class=ThreatClass.DDOS,
                severity=Severity.HIGH,
                confidence=0.92,
                status="New",
                detector="volumetric_ddos",
                evidence=[
                    EvidenceItem(feature="syn_rate", value=1840.0, reason="SYN packet rate of 1,840 pkts/s exceeds threshold 500 pkts/s"),
                    EvidenceItem(feature="src_entropy", value=4.82, reason="Source IP entropy 4.82 indicates multi-source spoofed flood"),
                ],
                observation_window_s=10.0,
            ),
            AlertV1(
                alert_id="alt-beacon-002",
                timestamp=now,
                flow_id="beacon-mixed",
                src_ip="10.0.0.50",
                dst_ip="185.234.72.10",
                src_port=49214,
                dst_port=443,
                protocol="TCP",
                threat_class=ThreatClass.BEACON,
                severity=Severity.CRITICAL,
                confidence=0.98,
                status="New",
                detector="botnet_c2_beacon",
                evidence=[
                    EvidenceItem(feature="inter_arrival_cv", value=0.0074, reason="IAT CV = 0.0074 (< 0.15 threshold) — strict automated periodicity"),
                    EvidenceItem(feature="beacon_count", value=14.0, reason="14 periodic heartbeat connections to 185.234.72.10:443 in 60s"),
                ],
                observation_window_s=60.0,
            ),
        ]
        self.bulk_insert_alerts(seeds)
