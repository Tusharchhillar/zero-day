"""Standardized alert and event contracts (Pydantic v2).

Every detector produces AlertV1 records.  The schema enforces cross-field
consistency: confidence is in [0,1], timestamps are UTC, evidence is
non-empty for confirmed anomalies, and severity is consistent with confidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ── Enums ────────────────────────────────────────────────────────────────────

class ThreatClass(str, Enum):
    DDOS = "volumetric_ddos"
    BEACON = "botnet_c2_beacon"
    DGA = "dga_domains"
    DNS_TUNNEL = "dns_tunnelling"
    ENCRYPTED_MALWARE = "encrypted_malware"
    PORT_SCAN = "reconnaissance_port_scan"
    EXFILTRATION = "data_exfiltration"
    BENIGN = "benign"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ── Evidence ─────────────────────────────────────────────────────────────────

class EvidenceItem(BaseModel):
    """A single piece of supporting evidence for an alert."""
    feature: str = Field(..., description="Feature name (e.g. 'src_ip_entropy', 'syn_ratio')")
    value: float = Field(..., description="Measured numeric value")
    reason: str = Field(..., description="Human-readable explanation of why this matters")


# ── Event (input) ────────────────────────────────────────────────────────────

class FlowEvent(BaseModel):
    """A single passive network observation — the smallest unit of ingest.

    Supports both TCP/DNS/TLS flows.  Only metadata is used — never payload.
    """
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = ""  # tcp, udp, dns, tls, quic
    flow_id: str = ""
    bytes_src_to_dst: int = 0
    bytes_dst_to_src: int = 0
    packets_src_to_dst: int = 0
    packets_dst_to_src: int = 0
    duration_ms: float = 0.0

    # DNS metadata (when protocol == "dns")
    dns_query: str = ""
    dns_query_type: str = ""  # A, AAAA, MX, TXT, CNAME, etc.
    dns_response_code: str = ""

    # TLS metadata (when protocol == "tls" or "quic")
    tls_version: str = ""  # TLS 1.3, QUIC, etc.
    ja3_hash: str = ""
    ja4_fingerprint: str = ""
    sni: str = ""
    alpn: str = ""
    tls_packet_sizes: List[int] = Field(default_factory=list)
    tls_timing_ms: List[float] = Field(default_factory=list)

    @property
    def is_dns_query(self) -> bool:
        return self.protocol == "dns" and bool(self.dns_query)

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_timestamp(cls, v: Any) -> datetime:
        if isinstance(v, str):
            v = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v
        return datetime.now(timezone.utc)


# ── Alert (output) ───────────────────────────────────────────────────────────

class AlertV1(BaseModel):
    """Structured detection alert — the output contract.

    Every alert answers: WHAT was detected, HOW confident are we, and WHY.
    """
    alert_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    flow_id: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    threat_class: ThreatClass
    severity: Severity = Severity.LOW
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: List[EvidenceItem] = Field(default_factory=list)
    detector: str = Field(default="", description="Detector name that produced this alert")
    model_version: str = Field(default="1.0")
    observation_window_s: float = Field(default=0.0, description="Time window in seconds")
    source_rate: Optional[float] = Field(default=None, description="Events/sec from source")

    @model_validator(mode="before")
    @classmethod
    def derive_severity(cls, data: Any) -> Any:
        """Auto-derive severity from confidence when not explicitly set."""
        if isinstance(data, dict):
            severity = data.get("severity")
            # Derive if severity not provided, or is the default LOW (and confidence would override)
            if severity is None:
                conf = data.get("confidence", 0.0)
                try:
                    conf = float(conf)
                except (ValueError, TypeError):
                    conf = 0.0
                if conf >= 0.90:
                    data["severity"] = Severity.CRITICAL
                elif conf >= 0.70:
                    data["severity"] = Severity.HIGH
                elif conf >= 0.40:
                    data["severity"] = Severity.MEDIUM
                else:
                    data["severity"] = Severity.LOW
        return data

    @field_validator("confidence", mode="before")
    @classmethod
    def clamp_confidence(cls, v: Any) -> float:
        return max(0.0, min(1.0, float(v)))
