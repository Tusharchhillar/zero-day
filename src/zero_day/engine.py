"""Alert engine — orchestrates rule-based + NJ-ODE detection and manages alert store.

Layer 1: 6 rule-based detectors (fast, explainable, covers known patterns)
Layer 2: NJ-ODE unsupervised anomaly detector (catches zero-day, any deviation)

Both layers feed into a unified, bounded, thread-safe alert store.
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Callable, Dict, List, Optional

from zero_day.contracts import AlertV1, FlowEvent, ThreatClass
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
    """Dual-layer detection engine with bounded alert store.

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
        max_alerts: int = 500,
        enable_njode: bool = True,
        on_alert: Optional[Callable[[AlertV1], None]] = None,
    ):
        self._lock = threading.Lock()
        self._alerts: deque = deque(maxlen=max_alerts)
        self._on_alert = on_alert
        self._event_count = 0
        self._alert_count = 0
        self._first_event_ts: Optional[float] = None
        self._last_event_ts: Optional[float] = None

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

        # Store and notify
        for alert in all_alerts:
            with self._lock:
                self._alerts.appendleft(alert)
                self._alert_count += 1
            if self._on_alert:
                try:
                    self._on_alert(alert)
                except Exception:
                    pass

        return all_alerts

    def get_alerts(self, limit: int = 50) -> List[AlertV1]:
        with self._lock:
            return list(self._alerts)[:limit]

    def get_metrics(self) -> Dict:
        elapsed = (self._last_event_ts - self._first_event_ts) if self._first_event_ts and self._last_event_ts else 0
        rate = self._event_count / max(0.001, elapsed)
        with self._lock:
            severity_counts = {}
            for a in self._alerts:
                severity_counts[a.severity.value] = severity_counts.get(a.severity.value, 0) + 1
        return {
            "events_processed": self._event_count,
            "alerts_emitted": self._alert_count,
            "events_per_sec": round(rate, 2),
            "elapsed_s": round(elapsed, 3),
            "severity_distribution": severity_counts,
            "njode_enabled": self._enable_njode and self._feeder is not None,
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
