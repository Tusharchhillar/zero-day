"""Rule-based detectors for all 6 threat classes in SIH26145.

Each detector implements the same interface:
  - accepts FlowEvents one at a time (streaming)
  - maintains bounded rolling-window state
  - emits AlertV1 records when thresholds are crossed
  - provides explainable evidence for every alert
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from typing import List, Optional

import numpy as np

from zero_day.contracts import AlertV1, EvidenceItem, FlowEvent, Severity, ThreatClass
from zero_day.features import event_features, dns_label_features, string_entropy


class DetectorBase:
    """Shared base: bounded per-key state + cooldown to prevent alert spam."""

    def __init__(self, name: str, window_s: float = 10.0, cooldown_s: float = 5.0):
        self.name = name
        self.window_s = window_s
        self.cooldown_s = cooldown_s
        self._last_alert_ts: dict[str, float] = {}

    def _prune(self, events: deque, now: float) -> None:
        cutoff = now - self.window_s
        while events:
            ts_val = events[0]["ts"] if isinstance(events[0], dict) else events[0]
            if ts_val < cutoff:
                events.popleft()
            else:
                break

    def _cooldown_ok(self, key: str, now: float) -> bool:
        last = self._last_alert_ts.get(key, -999.0)
        return (now - last) >= self.cooldown_s

    def _record_alert(self, key: str, ts: float) -> None:
        self._last_alert_ts[key] = ts

    def process(self, event: FlowEvent) -> List[AlertV1]:
        raise NotImplementedError


# ══════════════════════════════════════════════════════════════════════════════
# 1. Volumetric / Protocol DDoS (SYN flood + UDP amplification)
# ══════════════════════════════════════════════════════════════════════════════

class DDoSDetector(DetectorBase):
    """Detects SYN floods and UDP reflection/amplification.

    SYN flood: >= syn_threshold SYN-only packets from >= min_sources unique
    sources to one destination in window_s.
    UDP amp: >= udp_threshold packets to amplification ports (53, 123, 1900, etc.)
    from >= min_sources unique sources.
    """

    SYN_PORTS = {53, 80, 443, 8080, 8443}
    AMP_PORTS = {53, 123, 1900, 389, 5060}
    AMPLIFICATION_RATIO = 3.0  # response/request size ratio

    def __init__(
        self,
        syn_threshold: int = 100,
        min_sources: int = 20,
        udp_threshold: int = 50,
        **kwargs,
    ):
        super().__init__(name="volumetric_ddos", **kwargs)
        self.syn_threshold = syn_threshold
        self.min_sources = min_sources
        self.udp_threshold = udp_threshold
        self._syn_events: dict[str, deque] = defaultdict(lambda: deque())
        self._udp_events: dict[str, deque] = defaultdict(lambda: deque())

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        ts = event.timestamp.timestamp()

        # SYN flood detection
        if event.protocol == "tcp":
            is_syn = (
                event.packets_src_to_dst > 0
                and event.bytes_src_to_dst < 100  # SYN-only = small
                and event.bytes_dst_to_src == 0   # no ACK yet
            )
            if is_syn:
                key = event.dst_ip
                ev = {"ts": ts, "src": event.src_ip}
                self._syn_events[key].append(ev)
                self._prune(self._syn_events[key], ts)

                # Count unique sources
                sources = {e["src"] for e in self._syn_events[key]}
                syn_count = len(self._syn_events[key])

                if (
                    syn_count >= self.syn_threshold
                    and len(sources) >= self.min_sources
                    and self._cooldown_ok(key, ts)
                ):
                    # Source IP entropy
                    src_counts = [e["src"] for e in self._syn_events[key]]
                    unique = list(set(src_counts))
                    probs = [src_counts.count(s) / len(src_counts) for s in unique]
                    entropy = -sum(p * math.log2(p) for p in probs if p > 0)

                    # Confidence: higher entropy (more distributed) + higher rate = more confident
                    rate_conf = min(1.0, syn_count / (self.syn_threshold * 2))
                    entropy_conf = min(1.0, entropy / math.log2(max(2, len(sources))))
                    confidence = 0.6 * rate_conf + 0.4 * entropy_conf

                    alerts.append(AlertV1(
                        flow_id=event.flow_id,
                        src_ip=f"{len(sources)} unique sources",
                        dst_ip=event.dst_ip,
                        threat_class=ThreatClass.DDOS,
                        severity=Severity.CRITICAL if confidence >= 0.85 else Severity.HIGH,
                        confidence=confidence,
                        evidence=[
                            EvidenceItem(feature="syn_packet_count", value=syn_count, reason=f"{syn_count} SYN-only packets in {self.window_s}s window (threshold: {self.syn_threshold})"),
                            EvidenceItem(feature="unique_sources", value=len(sources), reason=f"{len(sources)} unique source IPs (threshold: {self.min_sources})"),
                            EvidenceItem(feature="source_entropy", value=round(entropy, 3), reason=f"Source IP distribution entropy: {entropy:.2f} bits"),
                        ],
                        detector=self.name,
                        observation_window_s=self.window_s,
                    ))
                    self._record_alert(key, ts)

        # UDP reflection/amplification detection
        if event.protocol == "udp" and event.dst_port in self.AMP_PORTS:
            key = f"{event.dst_ip}:{event.dst_port}"
            ev = {"ts": ts, "src": event.src_ip}
            self._udp_events[key].append(ev)
            self._prune(self._udp_events[key], ts)

            sources = {e["src"] for e in self._udp_events[key]}
            pkt_count = len(self._udp_events[key])

            if (
                pkt_count >= self.udp_threshold
                and len(sources) >= self.min_sources
                and self._cooldown_ok(key, ts)
            ):
                src_counts = [e["src"] for e in self._udp_events[key]]
                unique = list(set(src_counts))
                probs = [src_counts.count(s) / len(src_counts) for s in unique]
                entropy = -sum(p * math.log2(p) for p in probs if p > 0)

                confidence = min(1.0, 0.5 * (pkt_count / self.udp_threshold) + 0.5 * (len(sources) / self.min_sources))

                alerts.append(AlertV1(
                    flow_id=event.flow_id,
                    src_ip=f"{len(sources)} unique sources",
                    dst_ip=event.dst_ip,
                    threat_class=ThreatClass.DDOS,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    evidence=[
                        EvidenceItem(feature="udp_packet_count", value=pkt_count, reason=f"{pkt_count} UDP packets to amplification port {event.dst_port}"),
                        EvidenceItem(feature="unique_sources", value=len(sources), reason=f"{len(sources)} unique source IPs suggest reflection/amplification"),
                        EvidenceItem(feature="target_port", value=event.dst_port, reason=f"Port {event.dst_port} is a known amplification service"),
                    ],
                    detector=self.name,
                    observation_window_s=self.window_s,
                ))
                self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 2. Botnet C2 Beaconing
# ══════════════════════════════════════════════════════════════════════════════

class BeaconDetector(DetectorBase):
    """Detects periodic C2 beaconing via inter-arrival time analysis.

    Beacons: low IAT coefficient of variation (< cv_threshold) + repeated
    connections to a single destination.
    """

    def __init__(self, cv_threshold: float = 0.15, min_beacons: int = 5, **kwargs):
        kwargs.setdefault("window_s", 60.0)
        super().__init__(name="botnet_c2_beacon", **kwargs)
        self.cv_threshold = cv_threshold
        self.min_beacons = min_beacons
        self._flows: dict[str, deque] = defaultdict(lambda: deque())

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        if event.protocol not in ("tcp", "tls", "quic"):
            return alerts

        ts = event.timestamp.timestamp()
        key = f"{event.src_ip}->{event.dst_ip}:{event.dst_port}"
        self._flows[key].append(ts)
        self._prune(self._flows[key], ts)

        timestamps = list(self._flows[key])
        if len(timestamps) < self.min_beacons:
            return alerts

        iats = np.diff(timestamps)
        if len(iats) < 3 or iats.mean() == 0:
            return alerts

        cv = float(iats.std() / iats.mean())

        if cv < self.cv_threshold and self._cooldown_ok(key, ts):
            # Low CV = highly periodic = beacon
            confidence = min(1.0, max(0.0, (self.cv_threshold - cv) / self.cv_threshold * 0.8 + 0.2))

            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.BEACON,
                severity=Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM,
                confidence=confidence,
                evidence=[
                    EvidenceItem(feature="inter_arrival_cv", value=round(cv, 4), reason=f"IAT coefficient of variation = {cv:.4f} (threshold: {self.cv_threshold}) — highly periodic"),
                    EvidenceItem(feature="beacon_count", value=len(timestamps), reason=f"{len(timestamps)} periodic connections in {self.window_s}s window"),
                    EvidenceItem(feature="mean_interval_s", value=round(float(iats.mean()), 3), reason=f"Average beacon interval: {iats.mean():.3f}s"),
                    EvidenceItem(feature="destination_concentration", value=float(event.dst_port), reason=f"All beacons target {event.dst_ip}:{event.dst_port}"),
                ],
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 3. DGA Domains
# ══════════════════════════════════════════════════════════════════════════════

class DGADetector(DetectorBase):
    """Detects DGA domains via entropy/n-gram lexical analysis of DNS queries.

    DGA domains: high character entropy, high digit/consonant ratio,
    no meaningful dictionary words.
    """

    def __init__(self, score_threshold: float = 0.55, **kwargs):
        kwargs.setdefault("window_s", 30.0)
        super().__init__(name="dga_domains", **kwargs)
        self.score_threshold = score_threshold
        self._queries: dict[str, deque] = defaultdict(lambda: deque())

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        if not event.is_dns_query:
            return alerts

        ts = event.timestamp.timestamp()
        features = dns_label_features(event.dns_query)
        key = event.src_ip
        self._queries[key].append({"ts": ts, "query": event.dns_query, "features": features})
        self._prune(self._queries[key], ts)

        # Check if the lexical score exceeds threshold
        if features["lexical_score"] >= self.score_threshold and self._cooldown_ok(key, ts):
            confidence = min(1.0, features["lexical_score"])

            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.DGA,
                severity=Severity.HIGH if confidence >= 0.75 else Severity.MEDIUM,
                confidence=confidence,
                evidence=[
                    EvidenceItem(feature="lexical_score", value=round(features["lexical_score"], 4), reason=f"DGA lexical score = {features['lexical_score']:.4f} (threshold: {self.score_threshold})"),
                    EvidenceItem(feature="query_entropy", value=round(features["query_entropy"], 3), reason=f"Query name entropy: {features['query_entropy']:.2f} bits"),
                    EvidenceItem(feature="digit_ratio", value=round(features["digit_ratio"], 3), reason=f"Digit ratio: {features['digit_ratio']:.1%} — high digit content is DGA-typical"),
                    EvidenceItem(feature="query_name", value=0, reason=f"Suspicious domain: {event.dns_query}"),
                ],
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 4. DNS Tunnelling
# ══════════════════════════════════════════════════════════════════════════════

class DNSTunnelDetector(DetectorBase):
    """Detects DNS tunnelling via query length, record-type, and entropy anomalies.

    Tunnelling: unusually long DNS queries, high-entropy labels, unusual
    record types (TXT, NULL), high query volume per source.
    """

    SUSPICIOUS_TYPES = {"TXT", "NULL", "CNAME", "MX"}
    LONG_QUERY_THRESHOLD = 50  # chars
    VOLUME_THRESHOLD = 30  # queries in window

    def __init__(self, **kwargs):
        kwargs.setdefault("window_s", 30.0)
        super().__init__(name="dns_tunnelling", **kwargs)
        self._src_queries: dict[str, deque] = defaultdict(lambda: deque())

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        if not event.is_dns_query:
            return alerts

        ts = event.timestamp.timestamp()
        key = event.src_ip
        self._src_queries[key].append({"ts": ts, "query": event.dns_query, "type": event.dns_query_type})
        self._prune(self._src_queries[key], ts)

        queries = self._src_queries[key]
        if len(queries) < 3:
            return alerts

        # Check multiple signals
        signals = []
        reasons = []

        # Signal 1: Long query name
        if len(event.dns_query) > self.LONG_QUERY_THRESHOLD:
            signals.append(0.3)
            reasons.append(EvidenceItem(
                feature="query_length",
                value=len(event.dns_query),
                reason=f"DNS query length {len(event.dns_query)} chars exceeds {self.LONG_QUERY_THRESHOLD} — tunnelling apps embed data in labels",
            ))

        # Signal 2: High entropy in query labels
        entropy = string_entropy(event.dns_query.lower())
        if entropy > 3.5:
            signals.append(0.3)
            reasons.append(EvidenceItem(
                feature="query_entropy",
                value=round(entropy, 3),
                reason=f"Query entropy {entropy:.2f} bits — high entropy indicates encoded/tunnelled data",
            ))

        # Signal 3: Suspicious record type
        if event.dns_query_type in self.SUSPICIOUS_TYPES:
            signals.append(0.2)
            reasons.append(EvidenceItem(
                feature="record_type",
                value=0,
                reason=f"Record type {event.dns_query_type} is commonly abused for data exfiltration via DNS",
            ))

        # Signal 4: High query volume from single source
        if len(queries) >= self.VOLUME_THRESHOLD:
            signals.append(0.2)
            reasons.append(EvidenceItem(
                feature="query_volume",
                value=len(queries),
                reason=f"{len(queries)} DNS queries from {event.src_ip} in {self.window_s}s — high volume suggests tunnelling",
            ))

        if signals and self._cooldown_ok(key, ts):
            confidence = min(1.0, sum(signals))
            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.DNS_TUNNEL,
                severity=Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM,
                confidence=confidence,
                evidence=reasons,
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 5. Malware in Encrypted Sessions (metadata only)
# ══════════════════════════════════════════════════════════════════════════════

class EncryptedMalwareDetector(DetectorBase):
    """Detects malware indicators in TLS/QUIC sessions using metadata only.

    No payload decryption. Uses: packet-size uniformity, timing regularity,
    JA3/JA4 anomaly, and unusual ALPN patterns.
    """

    def __init__(self, size_cv_threshold: float = 0.15, timing_cv_threshold: float = 0.20, **kwargs):
        kwargs.setdefault("window_s", 30.0)
        super().__init__(name="encrypted_malware", **kwargs)
        self.size_cv_threshold = size_cv_threshold
        self.timing_cv_threshold = timing_cv_threshold
        self._tls_sessions: dict[str, dict] = {}

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        if event.protocol not in ("tls", "quic"):
            return alerts

        ts = event.timestamp.timestamp()
        key = event.flow_id or f"{event.src_ip}->{event.dst_ip}:{event.dst_port}"

        if key not in self._tls_sessions:
            self._tls_sessions[key] = {
                "sizes": [], "timings": [], "first_ts": ts, "last_ts": ts
            }

        session = self._tls_sessions[key]
        session["sizes"].append(event.bytes_src_to_dst + event.bytes_dst_to_src)
        if ts > session["last_ts"]:
            session["timings"].append(ts - session["last_ts"])
            session["last_ts"] = ts

        sizes = session["sizes"]
        timings = session["timings"]

        if len(sizes) < 5 or len(timings) < 3:
            return alerts

        signals = []
        reasons = []

        # Signal 1: Uniform packet sizes (malware often uses fixed-size frames)
        size_arr = np.array(sizes, dtype=float)
        if size_arr.mean() > 0:
            size_cv = float(size_arr.std() / size_arr.mean())
            if size_cv < self.size_cv_threshold:
                signals.append(0.35)
                reasons.append(EvidenceItem(
                    feature="size_cv",
                    value=round(size_cv, 4),
                    reason=f"Packet size coefficient of variation = {size_cv:.4f} — unusually uniform sizes suggest automated malware",
                ))

        # Signal 2: Regular timing intervals (periodic check-ins)
        timing_arr = np.array(timings, dtype=float)
        if timing_arr.mean() > 0:
            timing_cv = float(timing_arr.std() / timing_arr.mean())
            if timing_cv < self.timing_cv_threshold:
                signals.append(0.35)
                reasons.append(EvidenceItem(
                    feature="timing_cv",
                    value=round(timing_cv, 4),
                    reason=f"Timing coefficient of variation = {timing_cv:.4f} — regular intervals suggest C2 beaconing in encrypted session",
                ))

        # Signal 3: Known JA3 hash (if we had a threat intel database)
        if event.ja3_hash:
            signals.append(0.15)
            reasons.append(EvidenceItem(
                feature="ja3_hash",
                value=0,
                reason=f"JA3 fingerprint {event.ja3_hash} observed — compare against known malware fingerprints",
            ))

        # Signal 4: Small total session with high byte count
        session_duration = session["last_ts"] - session["first_ts"]
        total_bytes = sum(sizes)
        if session_duration > 0 and total_bytes / session_duration > 10000:  # >10KB/s
            signals.append(0.15)
            reasons.append(EvidenceItem(
                feature="throughput",
                value=round(total_bytes / session_duration, 1),
                reason=f"Sustained throughput {total_bytes / session_duration:.0f} B/s in encrypted session",
            ))

        if len(signals) >= 2 and self._cooldown_ok(key, ts):
            confidence = min(1.0, sum(signals))
            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.ENCRYPTED_MALWARE,
                severity=Severity.HIGH if confidence >= 0.7 else Severity.MEDIUM,
                confidence=confidence,
                evidence=reasons,
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 6. Reconnaissance / Port Scanning
# ══════════════════════════════════════════════════════════════════════════════

class PortScanDetector(DetectorBase):
    """Detects reconnaissance via fan-out across destination ports/hosts.

    Port scan: source sends SYNs to >= min_ports unique destination ports
    or >= min_hosts unique destination IPs within window_s.
    """

    def __init__(self, min_ports: int = 15, min_hosts: int = 15, **kwargs):
        super().__init__(name="reconnaissance_port_scan", **kwargs)
        self.min_ports = min_ports
        self.min_hosts = min_hosts
        self._src_events: dict[str, deque] = defaultdict(lambda: deque())

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        if event.protocol != "tcp":
            return alerts

        ts = event.timestamp.timestamp()
        key = event.src_ip
        self._src_events[key].append({
            "ts": ts,
            "dst_port": event.dst_port,
            "dst_ip": event.dst_ip,
            "is_syn": event.packets_src_to_dst > 0 and event.bytes_src_to_dst < 100,
        })
        self._prune(self._src_events[key], ts)

        evts = self._src_events[key]
        syn_evts = [e for e in evts if e["is_syn"]]
        if len(syn_evts) < self.min_ports:
            return alerts

        unique_ports = {e["dst_port"] for e in syn_evts}
        unique_hosts = {e["dst_ip"] for e in syn_evts}

        if (
            (len(unique_ports) >= self.min_ports or len(unique_hosts) >= self.min_hosts)
            and self._cooldown_ok(key, ts)
        ):
            port_conf = min(1.0, len(unique_ports) / self.min_ports)
            host_conf = min(1.0, len(unique_hosts) / self.min_hosts)
            confidence = max(port_conf, host_conf)

            # Fan-out ratio evidence
            fan_out_type = "ports" if len(unique_ports) >= self.min_ports else "hosts"

            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=", ".join(sorted(unique_hosts)[:3]),
                threat_class=ThreatClass.PORT_SCAN,
                severity=Severity.HIGH if confidence >= 0.8 else Severity.MEDIUM,
                confidence=confidence,
                evidence=[
                    EvidenceItem(feature="syn_attempts", value=len(syn_evts), reason=f"{len(syn_evts)} SYN attempts in {self.window_s}s window"),
                    EvidenceItem(feature="unique_dst_ports", value=len(unique_ports), reason=f"Fan-out to {len(unique_ports)} unique destination ports"),
                    EvidenceItem(feature="unique_dst_hosts", value=len(unique_hosts), reason=f"Fan-out to {len(unique_hosts)} unique destination hosts"),
                    EvidenceItem(feature="scan_type", value=0, reason=f"{'Horizontal' if len(unique_hosts) >= self.min_hosts else 'Vertical'} scan pattern detected"),
                ],
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts


# ══════════════════════════════════════════════════════════════════════════════
# 7. Data Exfiltration
# ══════════════════════════════════════════════════════════════════════════════

class ExfiltrationDetector(DetectorBase):
    """Detects data exfiltration via asymmetric flow volume and byte ratios.

    Exfiltration: high outbound-to-inbound byte ratio, unusual volume patterns,
    or sustained high-volume outbound data transfer.
    """

    def __init__(self, ratio_threshold: float = 5.0, volume_threshold: int = 1_000_000, **kwargs):
        kwargs.setdefault("window_s", 30.0)
        super().__init__(name="data_exfiltration", **kwargs)
        self.ratio_threshold = ratio_threshold
        self.volume_threshold = volume_threshold
        self._src_stats: dict[str, dict] = {}

    def process(self, event: FlowEvent) -> List[AlertV1]:
        alerts = []
        ts = event.timestamp.timestamp()
        key = f"{event.src_ip}->{event.dst_ip}"

        if key not in self._src_stats:
            self._src_stats[key] = {"out": 0, "in": 0, "count": 0, "first_ts": ts}

        stats = self._src_stats[key]
        stats["out"] += event.bytes_src_to_dst
        stats["in"] += event.bytes_dst_to_src
        stats["count"] += 1

        # Prune old stats
        if ts - stats["first_ts"] > self.window_s:
            self._src_stats[key] = {"out": event.bytes_src_to_dst, "in": event.bytes_dst_to_src, "count": 1, "first_ts": ts}
            return alerts

        total_out = stats["out"]
        total_in = stats["in"]
        ratio = total_out / max(1, total_in)

        signals = []
        reasons = []

        # Signal 1: Asymmetric byte ratio
        if ratio >= self.ratio_threshold and total_out > 10000:
            signals.append(0.5)
            reasons.append(EvidenceItem(
                feature="outbound_inbound_ratio",
                value=round(ratio, 3),
                reason=f"Outbound/inbound byte ratio = {ratio:.1f}:1 (threshold: {self.ratio_threshold}:1) — strongly asymmetric",
            ))

        # Signal 2: High total outbound volume
        if total_out >= self.volume_threshold:
            signals.append(0.3)
            reasons.append(EvidenceItem(
                feature="outbound_volume",
                value=total_out,
                reason=f"{total_out:,} bytes outbound in {self.window_s}s — unusual volume for passive monitoring",
            ))

        # Signal 3: Low return traffic (one-way transfer)
        if total_out > 50000 and total_in < total_out * 0.05:
            signals.append(0.2)
            reasons.append(EvidenceItem(
                feature="one_way_transfer",
                value=round(total_in / max(1, total_out), 4),
                reason=f"Only {total_in / max(1, total_out):.1%} return traffic — characteristic of one-way data exfiltration",
            ))

        if signals and self._cooldown_ok(key, ts):
            confidence = min(1.0, sum(signals))
            alerts.append(AlertV1(
                flow_id=event.flow_id,
                src_ip=event.src_ip,
                dst_ip=event.dst_ip,
                threat_class=ThreatClass.EXFILTRATION,
                severity=Severity.CRITICAL if confidence >= 0.85 else Severity.HIGH,
                confidence=confidence,
                evidence=reasons,
                detector=self.name,
                observation_window_s=self.window_s,
            ))
            self._record_alert(key, ts)

        return alerts
