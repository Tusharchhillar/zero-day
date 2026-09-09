"""SQLite cold storage repository for ZERO-DAY SIH26145.

Tier 2 (Cold Store): Provides persistent, indexed forensic storage in SQLite
with Write-Ahead Logging (WAL mode) for high-concurrency ingestion and rich
analytical filtering.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
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
    """Thread-safe SQLite persistent alert repository (Cold Tier)."""

    def __init__(self, db_path: str = "data/alerts.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()
        self._seed_if_empty()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # WAL mode + synchronous NORMAL enables 50,000+ non-blocking writes/sec
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
            """)

    def insert_alert(self, alert: AlertV1, status: Optional[str] = None) -> None:
        """Insert or update a single alert in the cold storage table."""
        tc_val = alert.threat_class.value if hasattr(alert.threat_class, "value") else str(alert.threat_class)
        sih_cat = CLASS_TO_SIH.get(tc_val, "Botnet C2 Beaconing")
        sev_val = alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity)
        alert_status = status or getattr(alert, "status", "New") or "New"
        ev_json = json.dumps([e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in alert.evidence])
        ts_str = alert.timestamp.isoformat() if hasattr(alert.timestamp, "isoformat") else str(alert.timestamp)

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

    def bulk_insert_alerts(self, alerts: List[AlertV1]) -> None:
        """Batch insert multiple alerts in a single transaction."""
        if not alerts:
            return
        rows = []
        now = time.time()
        for a in alerts:
            tc_val = a.threat_class.value if hasattr(a.threat_class, "value") else str(a.threat_class)
            sih_cat = CLASS_TO_SIH.get(tc_val, "Botnet C2 Beaconing")
            sev_val = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            alert_status = getattr(a, "status", "New") or "New"
            ev_json = json.dumps([e.model_dump() if hasattr(e, "model_dump") else dict(e) for e in a.evidence])
            ts_str = a.timestamp.isoformat() if hasattr(a.timestamp, "isoformat") else str(a.timestamp)
            rows.append((
                a.alert_id, ts_str, a.flow_id, a.src_ip, a.dst_ip,
                a.src_port, a.dst_port, a.protocol.upper(), tc_val, sih_cat,
                sev_val, float(a.confidence), alert_status, a.detector, ev_json,
                a.model_version, float(a.observation_window_s), a.source_rate, now,
            ))

        with self._lock, self._get_connection() as conn:
            conn.executemany("""
                INSERT OR REPLACE INTO alerts (
                    alert_id, timestamp, flow_id, src_ip, dst_ip,
                    src_port, dst_port, protocol, threat_class, sih_category,
                    severity, confidence, status, detector, evidence_json,
                    model_version, observation_window_s, source_rate, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, rows)

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Query persistent alerts with pagination, filters, and full text search."""
        query = "SELECT * FROM alerts WHERE 1=1"
        params: List[Any] = []

        if severity and severity != "All":
            query += " AND severity = ?"
            params.append(severity.upper())

        if threat_class and threat_class != "All":
            query += " AND (threat_class = ? OR sih_category = ?)"
            params.extend([threat_class, threat_class])

        if status and status != "All":
            query += " AND status = ?"
            params.append(status)

        if search:
            query += " AND (alert_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? OR threat_class LIKE ? OR sih_category LIKE ?)"
            s_param = f"%{search}%"
            params.extend([s_param, s_param, s_param, s_param, s_param])

        query += " ORDER BY timestamp DESC, created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._lock, self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_dict(r) for r in rows]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single alert with full forensic evidence by ID."""
        with self._lock, self._get_connection() as conn:
            row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
            return self._row_to_dict(row) if row else None

    def update_status(self, alert_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Update lifecycle status in SQLite (New -> Investigating -> Acknowledged -> Resolved)."""
        valid_statuses = {"New", "Investigating", "Acknowledged", "Resolved"}
        if new_status not in valid_statuses:
            return None

        with self._lock, self._get_connection() as conn:
            conn.execute("UPDATE alerts SET status = ? WHERE alert_id = ?", (new_status, alert_id))
            conn.commit()

        return self.get_alert_by_id(alert_id)

    def count(self) -> int:
        """Total count of stored alerts."""
        with self._lock, self._get_connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

    def get_metrics(self) -> Dict[str, Any]:
        """Aggregate forensic summary metrics from cold database."""
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
        """Seed initial reference SIH alerts if the cold database is new."""
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
            AlertV1(
                alert_id="alt-dga-003",
                timestamp=now,
                flow_id="dns-dga-419",
                src_ip="10.0.1.12",
                dst_ip="1.1.1.1",
                src_port=58211,
                dst_port=53,
                protocol="DNS",
                threat_class=ThreatClass.DGA,
                severity=Severity.CRITICAL,
                confidence=0.95,
                status="New",
                detector="dga_domains",
                evidence=[
                    EvidenceItem(feature="domain_entropy", value=4.18, reason="Domain 'x9k3b8q2v1.ru' Shannon entropy 4.18 exceeds 3.8 threshold"),
                    EvidenceItem(feature="vowel_ratio", value=0.10, reason="Abnormally low vowel ratio indicates pseudo-random generation"),
                ],
                observation_window_s=30.0,
            ),
            AlertV1(
                alert_id="alt-tunnel-004",
                timestamp=now,
                flow_id="dns-tun-771",
                src_ip="10.0.2.88",
                dst_ip="8.8.8.8",
                src_port=61042,
                dst_port=53,
                protocol="DNS",
                threat_class=ThreatClass.DNS_TUNNEL,
                severity=Severity.HIGH,
                confidence=0.88,
                status="Investigating",
                detector="dns_tunnelling",
                evidence=[
                    EvidenceItem(feature="query_length", value=84.0, reason="DNS query length 84 characters exceeds 45 char anomaly limit"),
                    EvidenceItem(feature="txt_record_ratio", value=0.85, reason="85% TXT query payload ratio indicates data staging over DNS"),
                ],
                observation_window_s=30.0,
            ),
            AlertV1(
                alert_id="alt-mal-tls-005",
                timestamp=now,
                flow_id="tls-c2-901",
                src_ip="10.0.0.105",
                dst_ip="91.215.85.17",
                src_port=50123,
                dst_port=443,
                protocol="TLS",
                threat_class=ThreatClass.ENCRYPTED_MALWARE,
                severity=Severity.CRITICAL,
                confidence=0.94,
                status="Acknowledged",
                detector="encrypted_malware",
                evidence=[
                    EvidenceItem(feature="ja3_known_malware", value=1.0, reason="JA3 fingerprint matches Cobalt Strike HTTPS beaconing profile"),
                    EvidenceItem(feature="sni_entropy", value=3.92, reason="High-entropy SNI host with uniform record length sequence"),
                ],
                observation_window_s=30.0,
            ),
            AlertV1(
                alert_id="alt-scan-006",
                timestamp=now,
                flow_id="scan-h-003",
                src_ip="192.168.1.15",
                dst_ip="10.0.0.1",
                src_port=41902,
                dst_port=80,
                protocol="TCP",
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.HIGH,
                confidence=0.91,
                status="New",
                detector="reconnaissance_port_scan",
                evidence=[
                    EvidenceItem(feature="port_fanout", value=42.0, reason="42 unique destination ports probed in 10s window"),
                    EvidenceItem(feature="syn_only_ratio", value=1.0, reason="100% SYN-only probes with 0 completed handshakes"),
                ],
                observation_window_s=10.0,
            ),
            AlertV1(
                alert_id="alt-exfil-007",
                timestamp=now,
                flow_id="exfil-out-802",
                src_ip="10.0.3.52",
                dst_ip="198.51.100.8",
                src_port=54001,
                dst_port=443,
                protocol="TCP",
                threat_class=ThreatClass.EXFILTRATION,
                severity=Severity.CRITICAL,
                confidence=0.97,
                status="New",
                detector="data_exfiltration",
                evidence=[
                    EvidenceItem(feature="byte_ratio", value=14.8, reason="Outbound-to-inbound byte ratio 14.8:1 exceeds threshold 8.0:1"),
                    EvidenceItem(feature="burst_volume_mb", value=85.4, reason="85.4 MB transferred in 30s asymmetric burst"),
                ],
                observation_window_s=30.0,
            ),
        ]

        self.bulk_insert_alerts(seeds)
