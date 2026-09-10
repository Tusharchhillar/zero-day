"""Alert engine — orchestrates rule-based + NJ-ODE detection and manages 2-tier storage.

Architecture: 2-Tier "Hot + Cold" Storage Pattern
- Tier 1 (Hot Store - RAM): High-throughput in-memory ring buffer (collections.deque)
  enabling sub-millisecond WebSocket streaming & instantaneous dashboard updates.
- Tier 2 (Cold Store - Disk): Persistent SQLite database (WAL mode) for forensic
  retrieval, search filtering, and analyst lifecycle updates (New -> Resolved).
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any, Callable, Dict, List, Optional

from zero_day.contracts import AlertV1, FlowEvent, ThreatClass
from zero_day.db import AlertDB
from zero_day.features import D_X, FeaturePacket, events_to_feature_stream
from zero_day.njode import NJODE, THREAT_CLASS_MAP, attribute_error
from zero_day.rules import (
    DDoSDetector,
    BeaconDetector,
    DGADetector,
    DNSTunnelDetector,
    EncryptedMalwareDetector,
    ExfiltrationDetector,
    PortScanDetector,
)
from zero_day.windowing import LiveFeeder


class AlertEngine:
    """Dual-layer detection engine with 2-Tier (Hot RAM + Cold SQLite) storage.

    Usage:
        engine = AlertEngine(model_path="models/njode_v1.pt")
        for event in events:
            alerts = engine.process_event(event)
            for alert in alerts:
                print(alert.model_dump_json())
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        db_path: str = "data/alerts.db",
        max_hot_alerts: int = 1000,
        enable_njode: bool = True,
        on_alert: Optional[Callable[[AlertV1], None]] = None,
    ):
        self._lock = threading.Lock()
        # Tier 1 (Hot Store in RAM)
        self._hot_alerts: deque = deque(maxlen=max_hot_alerts)
        self._on_alert = on_alert
        self._event_count = 0
        self._alert_count = 0
        self._first_event_ts: Optional[float] = None
        self._last_event_ts: Optional[float] = None

        # Tier 2 (Cold Store in SQLite WAL)
        self.db = AlertDB(db_path=db_path)

        # Layer 1: Rule-based detectors
        self._rules = [
            DDoSDetector(window_s=10.0),
            BeaconDetector(window_s=60.0),
            DGADetector(window_s=30.0),
            DNSTunnelDetector(window_s=30.0),
            EncryptedMalwareDetector(window_s=30.0),
            PortScanDetector(window_s=10.0),
            ExfiltrationDetector(window_s=30.0),
        ]

        # Layer 2: NJ-ODE anomaly detector
        self._enable_njode = enable_njode
        self._feeder: Optional[LiveFeeder] = None
        self._njode_model: Optional[NJODE] = None
        if enable_njode and model_path:
            try:
                self._njode_model = NJODE.load(model_path)
                self._feeder = LiveFeeder(self._njode_model, window_s=10.0, stride_s=2.0)
                print(f"[AlertEngine] NJ-ODE loaded from {model_path} (τ={self._njode_model.threshold.item():.4f})")
            except Exception as e:
                print(f"[AlertEngine] NJ-ODE not available: {e}")
                self._enable_njode = False
        elif enable_njode:
            print("[AlertEngine] No model_path — NJ-ODE layer disabled (rules-only mode)")

    def process_event(self, event: FlowEvent) -> List[AlertV1]:
        """Process a single FlowEvent through both detection layers."""
        self._event_count += 1
        ts = event.timestamp.timestamp()
        if self._first_event_ts is None:
            self._first_event_ts = ts
        self._last_event_ts = ts

        all_alerts: List[AlertV1] = []

        # Layer 1: Rule-based detectors
        for detector in self._rules:
            try:
                alerts = detector.process(event)
                all_alerts.extend(alerts)
            except Exception as e:
                print(f"[AlertEngine] {detector.name} error: {e}")

        # Layer 2: NJ-ODE anomaly scoring
        if self._enable_njode and self._feeder:
            try:
                pkt = FeaturePacket(
                    t=ts,
                    size=event.bytes_src_to_dst + event.bytes_dst_to_src,
                    direction=1 if event.bytes_dst_to_src > event.bytes_src_to_dst else 0,
                    flow_key=event.flow_id.encode() if event.flow_id else b"",
                )
                je_alerts = self._feeder.ingest_packet(pkt)
                for ja in je_alerts:
                    if ja.is_anomaly and ja.confirmed and ja.attribution:
                        # Map NJ-ODE alert to AlertV1
                        threat_str = ja.attribution.get("threat_type", "unknown")
                        try:
                            tc = ThreatClass(threat_str)
                        except ValueError:
                            tc = ThreatClass.BENIGN
                        # Only emit NJ-ODE alert if no rule already caught it
                        rule_classes = {a.threat_class for a in all_alerts}
                        if tc not in rule_classes and tc != ThreatClass.BENIGN:
                            all_alerts.append(AlertV1(
                                flow_id=event.flow_id,
                                src_ip=event.src_ip,
                                dst_ip=event.dst_ip,
                                threat_class=tc,
                                confidence=min(1.0, ja.confidence),
                                evidence=[
                                    {"feature": "peak_anomaly_score", "value": ja.peak_score, "reason": f"NJ-ODE peak score {ja.peak_score:.3f} exceeds threshold {ja.threshold:.3f}"},
                                    {"feature": "attribution_channel", "value": 0, "reason": f"Anomaly attributed to '{ja.attribution.get('top_channel', '?')}' feature channel"},
                                ],
                                detector="njode_unsupervised",
                                observation_window_s=10.0,
                            ))
            except Exception as e:
                print(f"[AlertEngine] NJ-ODE error: {e}")

        # Store in Tier 1 (Hot RAM) and Tier 2 (Cold SQLite)
        for alert in all_alerts:
            # Tier 1 (Hot)
            with self._lock:
                self._hot_alerts.appendleft(alert)
                self._alert_count += 1

            # Tier 2 (Cold SQLite WAL)
            try:
                self.db.insert_alert(alert)
            except Exception as e:
                print(f"[AlertEngine] Cold DB insert error: {e}")

            # Notify WebSocket subscribers
            if self._on_alert:
                try:
                    self._on_alert(alert)
                except Exception:
                    pass

        return all_alerts

    def get_hot_alerts(self, limit: int = 50) -> List[AlertV1]:
        """Fetch latest alerts from Tier 1 Hot RAM buffer (fastest)."""
        with self._lock:
            return list(self._hot_alerts)[:limit]

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        threat_class: Optional[str] = None,
        status: Optional[str] = None,
        search: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Fetch alerts from Tier 2 Cold SQLite store (indexed, searchable, paginated)."""
        return self.db.get_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            threat_class=threat_class,
            status=status,
            search=search,
        )

    def update_alert_status(self, alert_id: str, new_status: str) -> Optional[Dict[str, Any]]:
        """Update lifecycle status in Cold SQLite store."""
        return self.db.update_status(alert_id, new_status)

    def clear_all_alerts(self) -> int:
        """Clear all alerts from both hot buffer and cold storage. Returns count deleted."""
        with self._lock:
            count = len(self._hot_alerts)
            self._hot_alerts.clear()
        deleted = self.db.clear_all_alerts()
        return count + deleted

    def get_metrics(self) -> Dict[str, Any]:
        """Combine live hot stream rate with persistent cold storage counts."""
        elapsed = (self._last_event_ts - self._first_event_ts) if self._first_event_ts and self._last_event_ts else 0
        rate = self._event_count / max(0.001, elapsed)

        # Merge Hot in-memory counts and Cold DB totals
        db_stats = self.db.get_metrics()
        with self._lock:
            hot_severity: Dict[str, int] = {}
            for a in self._hot_alerts:
                sev_str = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
                hot_severity[sev_str] = hot_severity.get(sev_str, 0) + 1

        return {
            "events_processed": self._event_count,
            "alerts_emitted": max(self._alert_count, db_stats.get("total_alerts", 0)),
            "events_per_sec": round(rate, 2),
            "elapsed_s": round(elapsed, 3),
            "severity_distribution": db_stats.get("severity_distribution", hot_severity),
            "category_distribution": db_stats.get("category_distribution", {}),
            "status_distribution": db_stats.get("status_distribution", {}),
            "njode_enabled": self._enable_njode and self._feeder is not None,
            "storage_tier": "2-Tier Hot RAM + Cold SQLite WAL",
        }

    def flush_njode(self) -> List[AlertV1]:
        """Flush NJ-ODE remaining window."""
        if self._feeder:
            je_alerts = self._feeder.flush()
            for ja in je_alerts:
                if ja.is_anomaly and ja.confirmed:
                    with self._lock:
                        self._alert_count += 1
        return []
