"""Synthetic traffic generators for training, evaluation, and demo fixtures.

Produces deterministic, reproducible packets that simulate:
  - Benign: normal SCADA telemetry + web sync
  - Attacks: 6 classes matching SIH26145 threat categories
"""
from __future__ import annotations

import hashlib
import random
from typing import List

import numpy as np

from zero_day.features import FeaturePacket


def _rng(seed: int) -> random.Random:
    return random.Random(seed)


# ── Benign traffic generators ────────────────────────────────────────────────

def generate_benign_events(duration_s: float = 600.0, seed: int = 42) -> List[FeaturePacket]:
    """Normal SCADA telemetry + periodic web sync packets.

    ~3 events/sec average — matches the demo fixture benign baseline density,
    so the NJ-ODE learns this rate as normal and only true attacks stand out.
    """
    rng = _rng(seed)
    np_rng = np.random.default_rng(seed)
    packets = []
    t = 0.0

    # SCADA telemetry: regular 0.2-1.5s intervals (3-5 evt/s), small packets
    while t < duration_s:
        iat = np_rng.exponential(0.33)
        t += max(0.05, min(iat, 2.0))
        if t >= duration_s:
            break
        size = int(np_rng.integers(60, 200))
        payload = bytes(rng.getrandbits(8) for _ in range(min(size, 32)))
        packets.append(FeaturePacket(t=t, size=size, payload=payload, direction=0))

    # Web sync: larger packets, 0.5-3s intervals
    t = 0.0
    while t < duration_s:
        iat = np_rng.exponential(0.9)
        t += max(0.1, min(iat, 3.0))
        if t >= duration_s:
            break
        size = int(np_rng.integers(200, 1400))
        payload = bytes(rng.getrandbits(8) for _ in range(min(size, 64)))
        packets.append(FeaturePacket(t=t, size=size, payload=payload, direction=1))

    packets.sort(key=lambda p: p.t)
    return packets


# ── Attack generators ────────────────────────────────────────────────────────

def generate_attack_events(attack_type: str, duration_s: float = 10.0, seed: int = 100) -> List[FeaturePacket]:
    """Generate synthetic attack traffic."""
    rng = _rng(seed)
    np_rng = np.random.default_rng(seed)
    packets = []

    if attack_type == "ddos":
        # SYN flood: many small packets at high rate
        t = 0.0
        while t < duration_s:
            t += np_rng.exponential(0.001)  # 1000 pkts/s
            if t >= duration_s:
                break
            packets.append(FeaturePacket(t=t, size=64, payload=b"\x00" * 4, direction=1))

    elif attack_type == "recon":
        # Port scan: sustained high-rate SYN bursts across the full duration
        # so every window contains attack traffic (no empty tail)
        t = 0.0
        port = 0
        while t < duration_s:
            # burst 40 scans at ~2ms spacing (approx 500 pkts/s sustained)
            for _ in range(40):
                t += np_rng.exponential(0.002)
                if t >= duration_s:
                    break
                size = int(np_rng.integers(60, 64))
                packets.append(FeaturePacket(t=t, size=size, payload=b"\x00" * 4, direction=0,
                                              flow_key=f"scan:{port}".encode()))
                port += 1
                if port >= 2000:
                    port = 0
            t += rng.uniform(0.005, 0.03)  # short gap, keeps rate high

    elif attack_type == "beacon":
        # C2 beacon: perfectly periodic small packets
        t = 0.0
        interval = 5.0  # 5-second beacon
        while t < duration_s:
            t += interval + np_rng.normal(0, 0.01)  # tiny jitter
            if t >= duration_s:
                break
            packets.append(FeaturePacket(t=t, size=128, payload=b"\x00" * 8, direction=0,
                                          flow_key=b"beacon_c2"))

    elif attack_type == "tunnel":
        # DNS tunnelling: high-rate DNS queries with long names — dense to fill slots
        t = 0.0
        while t < duration_s:
            t += np_rng.exponential(0.001)  # 1000 pkts/s
            if t >= duration_s:
                break
            fake_query = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=80))
            payload = fake_query.encode()[:32]
            packets.append(FeaturePacket(t=t, size=256, payload=payload, direction=0,
                                          flow_key=f"dns:{fake_query[:16]}".encode()))

    elif attack_type == "exfil":
        # Data exfil: large outbound packets, almost no inbound
        t = 0.0
        while t < duration_s:
            t += np_rng.exponential(0.01)
            if t >= duration_s:
                break
            size = int(np_rng.integers(1000, 1400))
            packets.append(FeaturePacket(t=t, size=size, payload=b"\xff" * 32, direction=0,
                                          flow_key=b"exfil_channel"))

    elif attack_type == "malware":
        # Encrypted C2: uniform 512B packets with regular timing
        t = 0.0
        while t < duration_s:
            t += np_rng.exponential(0.5)  # 2 pkts/s
            if t >= duration_s:
                break
            packets.append(FeaturePacket(t=t, size=512, payload=b"\xaa" * 32, direction=0,
                                          flow_key=b"tls_malware"))

    packets.sort(key=lambda p: p.t)
    return packets
