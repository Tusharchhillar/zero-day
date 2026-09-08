"""Feature extraction — FlowEvents → numerical features.

Two consumers:
  1. Rule-based detectors: per-event features (src_entropy, syn_ratio, etc.)
  2. NJ-ODE: 5-channel stream (iat, bytes, entropy, burst, direction)
"""
from __future__ import annotations

import math
import string
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Sequence

import numpy as np

from zero_day.contracts import FlowEvent


# ── Shannon entropy (byte-level) ─────────────────────────────────────────────

def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits [0..8] of the byte-value distribution."""
    if not data:
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probs = counts[counts > 0] / len(data)
    return float(-(probs * np.log2(probs)).sum())


def string_entropy(s: str) -> float:
    """Shannon entropy of a string's character distribution."""
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    probs = [c / total for c in counts.values()]
    return -sum(p * math.log2(p) for p in probs if p > 0)


# ── DNS-specific features ────────────────────────────────────────────────────

_DNS_TYPES = {"A", "AAAA", "MX", "TXT", "CNAME", "NS", "SRV", "PTR", "SOA", "DNSKEY", "RRSIG"}


def dns_label_features(query: str) -> dict:
    """Extract lexical features from a DNS query name for DGA detection."""
    labels = query.rstrip(".").split(".")
    n_labels = len(labels)
    max_label_len = max((len(l) for l in labels), default=0)
    avg_label_len = sum(len(l) for l in labels) / max(1, n_labels)

    # Character-level stats
    chars = query.lower().replace(".", "")
    n_digits = sum(c.isdigit() for c in chars)
    n_consonants = sum(c.isalpha() and c not in "aeiou" for c in chars)
    digit_ratio = n_digits / max(1, len(chars))
    consonant_ratio = n_consonants / max(1, len(chars))

    # Shannon entropy of the full query
    query_entropy = string_entropy(query.lower())

    # Lexical score: higher = more DGA-like
    # DGA domains tend to have: high entropy, many digits, many consonants, long labels
    lexical_score = (
        0.3 * min(query_entropy / 3.5, 1.0)  # normalized entropy
        + 0.3 * min(digit_ratio / 0.3, 1.0)
        + 0.2 * min(consonant_ratio / 0.7, 1.0)
        + 0.2 * min(avg_label_len / 10.0, 1.0)
    )

    return {
        "n_labels": n_labels,
        "max_label_len": max_label_len,
        "avg_label_len": avg_label_len,
        "digit_ratio": digit_ratio,
        "consonant_ratio": consonant_ratio,
        "query_entropy": query_entropy,
        "lexical_score": lexical_score,
        "total_length": len(query),
    }


# ── TLS metadata features ────────────────────────────────────────────────────

def tls_metadata_features(event: FlowEvent) -> dict:
    """Extract features from TLS/QUIC metadata — NO payload decryption."""
    sizes = event.tls_packet_sizes or []
    timings = event.tls_timing_ms or []

    size_stats = {}
    if sizes:
        arr = np.array(sizes, dtype=float)
        size_stats = {
            "size_mean": float(arr.mean()),
            "size_std": float(arr.std()) if len(arr) > 1 else 0.0,
            "size_min": float(arr.min()),
            "size_max": float(arr.max()),
            "size_cv": float(arr.std() / arr.mean()) if arr.mean() > 0 else 0.0,
        }

    timing_stats = {}
    if timings and len(timings) > 1:
        arr = np.array(timings, dtype=float)
        iats = np.diff(arr)
        timing_stats = {
            "timing_iat_mean": float(iats.mean()),
            "timing_iat_std": float(iats.std()) if len(iats) > 1 else 0.0,
            "timing_cv": float(iats.std() / iats.mean()) if iats.mean() > 0 else 0.0,
        }

    return {
        "has_ja3": bool(event.ja3_hash),
        "has_ja4": bool(event.ja4_fingerprint),
        "tls_version": event.tls_version,
        "n_sized": len(sizes),
        **size_stats,
        **timing_stats,
    }


# ── Per-event features for rule detectors ────────────────────────────────────

@dataclass
class WindowState:
    """Rolling window state for a single source or destination IP."""
    events: List[FlowEvent] = field(default_factory=list)
    first_ts: float = 0.0
    last_ts: float = 0.0


def event_features(event: FlowEvent) -> dict:
    """Extract all features from a single event for rule-based detection."""
    total_out = event.bytes_src_to_dst
    total_in = event.bytes_dst_to_src
    total_pkts = event.packets_src_to_dst + event.packets_dst_to_src
    total_bytes = total_out + total_in

    return {
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "src_port": event.src_port,
        "dst_port": event.dst_port,
        "protocol": event.protocol,
        "total_bytes": total_bytes,
        "total_pkts": total_pkts,
        "bytes_out": total_out,
        "bytes_in": total_in,
        "byte_ratio": total_out / max(1, total_in),
        "is_syn": event.protocol == "tcp" and event.packets_src_to_dst > 0 and event.bytes_src_to_dst < 100,
        "is_dns": event.protocol == "dns",
        "is_tls": event.protocol in ("tls", "quic"),
        "duration_ms": event.duration_ms,
    }


# ── 5-feature stream for NJ-ODE ─────────────────────────────────────────────

D_X = 5
FEATURE_NAMES = ["iat", "bytes", "entropy", "burst", "direction"]
BURST_IAT_MS = 20.0  # gap ≤ 20 ms = burst


@dataclass
class FeaturePacket:
    """Minimal packet representation for NJ-ODE ingestion."""
    t: float  # seconds
    size: int  # wire bytes
    payload: bytes = b""
    direction: int = 0  # 0=outbound, 1=inbound
    flow_key: bytes = b""


@dataclass
class FeatureStream:
    """Ordered feature vectors for NJ-ODE windowing."""
    t: np.ndarray  # (n,) float64 sorted
    F: np.ndarray  # (n, 5) float32

    def __len__(self) -> int:
        return len(self.t)


def events_to_feature_stream(events: Sequence[FlowEvent]) -> FeatureStream:
    """Convert FlowEvents → FeatureStream for NJ-ODE ingestion."""
    if not events:
        t = np.array([], dtype=np.float64)
        F = np.zeros((0, D_X), dtype=np.float32)
        return FeatureStream(t=t, F=F)

    sorted_events = sorted(events, key=lambda e: e.timestamp.timestamp())
    n = len(sorted_events)
    t = np.array([e.timestamp.timestamp() for e in sorted_events], dtype=np.float64)
    F = np.zeros((n, D_X), dtype=np.float32)

    for i, e in enumerate(sorted_events):
        # iat
        iat_ms = 0.0
        if i > 0:
            iat_ms = (t[i] - t[i - 1]) * 1000.0
        F[i, 0] = iat_ms

        # bytes (total wire size)
        F[i, 1] = float(e.bytes_src_to_dst + e.bytes_dst_to_src + e.packets_src_to_dst * 20)

        # entropy (of combined payload if available, else 0)
        F[i, 2] = 0.0  # flow-level events don't carry payload

        # burst indicator
        F[i, 3] = 1.0 if iat_ms <= BURST_IAT_MS and i > 0 else 0.0

        # direction (0=out, 1=in based on bytes ratio)
        total_out = e.bytes_src_to_dst
        total_in = e.bytes_dst_to_src
        F[i, 4] = 1.0 if total_in > total_out else 0.0

    return FeatureStream(t=t, F=F)


def packets_to_feature_stream(packets: list[FeaturePacket]) -> FeatureStream:
    """Convert FeaturePackets → FeatureStream for NJ-ODE ingestion."""
    if not packets:
        t = np.array([], dtype=np.float64)
        F = np.zeros((0, D_X), dtype=np.float32)
        return FeatureStream(t=t, F=F)

    sorted_pkts = sorted(packets, key=lambda p: p.t)
    n = len(sorted_pkts)
    t = np.array([p.t for p in sorted_pkts], dtype=np.float64)
    F = np.zeros((n, D_X), dtype=np.float32)

    for i, p in enumerate(sorted_pkts):
        iat = max(0.0, t[i] - t[i - 1]) * 1000.0 if i > 0 else 0.0
        entropy = shannon_entropy(p.payload)
        F[i, 0] = iat
        F[i, 1] = float(p.size)
        F[i, 2] = entropy
        F[i, 3] = 1.0 if iat <= BURST_IAT_MS and i > 0 else 0.0
        F[i, 4] = float(p.direction)

    return FeatureStream(t=t, F=F)
