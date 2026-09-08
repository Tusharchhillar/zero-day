"""Shared windowing: FeatureStream → NJ-ODE tensors.

ONE implementation, TWO consumers (eliminates train/serve skew):
  1. Windower: batch consumer for training and evaluation
  2. LiveFeeder: streaming consumer for live detection
"""
from __future__ import annotations

import hashlib
import math
import struct
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch

from zero_day.features import D_X, FeaturePacket, FeatureStream, shannon_entropy
from zero_day.njode import ATTRIBUTION_MAP, FEATURES, NJODE, THREAT_CLASS_MAP


def aggregate_slots(
    t: np.ndarray, F: np.ndarray, t0: float, window_s: float,
    K: int, dt: float,
    mean: Optional[np.ndarray] = None, std: Optional[np.ndarray] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """Unified slot aggregation. Collision policy: bytes=sum, iat=min, entropy=max, burst=max, direction=majority."""
    d_x = len(mean) if mean is not None else (F.shape[1] if hasattr(F, "shape") and len(F) > 0 else D_X)
    values = np.zeros((K + 1, d_x), dtype=np.float32)
    mask = np.zeros(K + 1, dtype=bool)

    if len(t) > 0:
        t_arr = np.asarray(t, dtype=np.float64)
        F_arr = np.asarray(F, dtype=np.float32)
        m = (t_arr >= t0) & (t_arr < t0 + window_s)
        if m.any():
            t_win, F_win = t_arr[m], F_arr[m]
            j = np.minimum(((t_win - t0) / window_s / dt).astype(np.int64), K)
            order = np.argsort(j, kind="stable")
            j, F_win = j[order], F_win[order]
            starts = np.flatnonzero(np.r_[True, j[1:] != j[:-1]])
            slots = j[starts]
            if F_win.shape[1] >= 1:
                values[slots, 0] = np.minimum.reduceat(F_win[:, 0], starts)
            if F_win.shape[1] >= 2:
                values[slots, 1] = np.add.reduceat(F_win[:, 1], starts)
            if F_win.shape[1] >= 3:
                values[slots, 2] = np.maximum.reduceat(F_win[:, 2], starts)
            if F_win.shape[1] >= 4:
                values[slots, 3] = np.maximum.reduceat(F_win[:, 3], starts)
            if F_win.shape[1] >= 5 and d_x >= 5:
                inbound = (F_win[:, 4] >= 0.5).astype(np.int32)
                inbound_counts = np.add.reduceat(inbound, starts)
                slot_counts = np.diff(np.r_[starts, len(F_win)])
                values[slots, 4] = (inbound_counts >= ((slot_counts + 1) // 2)).astype(np.float32)
            mask[slots] = True

    if mean is not None and std is not None:
        values = np.clip((values - mean) / std, -30.0, 30.0)
        values[~mask] = 0.0

    return values, mask


class Windower:
    """Batch consumer: FeatureStream → NJ-ODE tensors."""

    def __init__(self, model: NJODE, window_s: float = 10.0):
        self.model = model
        self.window_s = float(window_s)
        self.K, self.dt = model.K, model.dt
        self.mean_: Optional[np.ndarray] = None
        self.std_: Optional[np.ndarray] = None

    @torch.no_grad()
    def fit_standardizer(self, *streams: FeatureStream) -> Tuple[np.ndarray, np.ndarray]:
        X = np.concatenate([s.F for s in streams if len(s)], axis=0)
        self.mean_ = X.mean(0).astype(np.float32)
        self.std_ = np.maximum(X.std(0), 0.1).astype(np.float32)
        # Binary channels (burst=3, direction=4) must NOT be standardized:
        # std-floor 0.1 turns a 0/1 value into 0/10 → massive false scores.
        # Keep them raw (mean=0, std=1) so 0/1 stays 0/1.
        if self.mean_.shape[0] >= 5:
            self.mean_[3:] = 0.0
            self.std_[3:] = 1.0
        self.model.x_mean.copy_(torch.tensor(self.mean_))
        self.model.x_std.copy_(torch.tensor(self.std_))
        return self.mean_, self.std_

    def windows(self, stream: FeatureStream) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        if self.mean_ is None:
            self.mean_ = self.model.x_mean.cpu().numpy()
            self.std_ = self.model.x_std.cpu().numpy()
        vals, masks = [], []
        if len(stream) == 0:
            empty = torch.zeros((0, self.K + 1, D_X), dtype=torch.float32)
            mask_empty = torch.zeros((0, self.K + 1), dtype=torch.bool)
            grid = torch.linspace(0.0, 1.0, self.K + 1, dtype=torch.float32)
            return empty, mask_empty, grid
        t0 = float(stream.t[0])
        while t0 < stream.t[-1]:
            v, m = aggregate_slots(
                stream.t, stream.F, t0, self.window_s, self.K, self.dt,
                mean=self.mean_, std=self.std_,
            )
            if m.any():
                vals.append(v)
                masks.append(m)
            t0 += self.window_s
        if not vals:
            empty = torch.zeros((0, self.K + 1, D_X), dtype=torch.float32)
            mask_empty = torch.zeros((0, self.K + 1), dtype=torch.bool)
            grid = torch.linspace(0.0, 1.0, self.K + 1, dtype=torch.float32)
            return empty, mask_empty, grid
        return (
            torch.from_numpy(np.stack(vals)),
            torch.from_numpy(np.stack(masks)),
            torch.linspace(0.0, 1.0, self.K + 1, dtype=torch.float32),
        )


@dataclass
class AlertEvent:
    """Structured alert emitted by LiveFeeder."""
    window_t0: float
    window_t1: float
    peak_score: float
    threshold: float
    is_anomaly: bool
    confirmed: bool
    confidence: float = 0.0
    severity: str = "LOW"
    threat_class: str = "calm-baseline"
    evidence: Optional[Dict] = None
    flow_ids: Optional[List[int]] = None
    attribution: Optional[Dict] = None


class LiveFeeder:
    """Streaming consumer: packets → sliding windows → alerts.

    Uses the same aggregate_slots() as Windower — zero train/serve skew.
    """

    def __init__(self, model: NJODE, window_s: float = 10.0, stride_s: float = 2.0,
                 hysteresis_n: int = 2, hysteresis_m: int = 3, device: str = "cpu"):
        self.model = model
        self.window_s = window_s
        self.stride_s = stride_s
        self.K, self.dt = model.K, model.dt
        self.device = device
        self.hysteresis_n = hysteresis_n
        self.hysteresis_m = hysteresis_m
        self.mean_ = model.x_mean.cpu().numpy()
        self.std_ = model.x_std.cpu().numpy()
        self._t_buf: List[float] = []
        self._F_buf: List[np.ndarray] = []
        self._flow_buf: List[int] = []
        self._last_pkt_t: Optional[float] = None
        self._first_t: Optional[float] = None
        self._next_window_end: Optional[float] = None
        self._alert_history: deque = deque(maxlen=hysteresis_m)

    def reset(self) -> None:
        self._t_buf.clear()
        self._F_buf.clear()
        self._flow_buf.clear()
        self._last_pkt_t = self._first_t = self._next_window_end = None
        self._alert_history.clear()

    def ingest_packet(self, packet: FeaturePacket) -> List[AlertEvent]:
        t = float(packet.t)
        if self._last_pkt_t is None:
            iat_ms = 0.0
        else:
            iat_ms = max(0.0, (t - self._last_pkt_t) * 1000.0)
        self._last_pkt_t = t
        entropy = shannon_entropy(packet.payload)
        direction = float(packet.direction)
        flow_hash = self._compute_flow_hash(packet.flow_key) if packet.flow_key else 0
        features = np.array([iat_ms, packet.size, entropy, 1.0 if iat_ms <= 20.0 else 0.0, direction], dtype=np.float32)[:self.model.d_x]
        if self._first_t is None:
            self._first_t = t
            self._next_window_end = t + self.window_s
        self._t_buf.append(t)
        self._F_buf.append(features)
        self._flow_buf.append(flow_hash)
        return self._evaluate_ready_windows(t)

    def flush(self) -> List[AlertEvent]:
        """Flush remaining window."""
        if self._next_window_end is not None and self._t_buf:
            return self._evaluate_ready_windows(self._t_buf[-1] + self.window_s + 1)
        return []

    def _evaluate_ready_windows(self, current_t: float) -> List[AlertEvent]:
        alerts = []
        if self._next_window_end is None:
            return alerts
        while current_t >= self._next_window_end:
            win_end = self._next_window_end
            win_start = win_end - self.window_s
            alert = self._score_window(win_start, win_end)
            alerts.append(alert)
            self._next_window_end += self.stride_s
            self._prune_buffer(self._next_window_end - self.window_s)
        return alerts

    def _score_window(self, t0: float, t1: float) -> AlertEvent:
        tau = float(self.model.threshold.item())
        if not self._t_buf:
            return self._empty_alert(t0, t1, tau)

        values, mask = aggregate_slots(
            self._t_buf, self._F_buf, t0, self.window_s, self.K, self.dt,
            mean=self.mean_, std=self.std_,
        )
        if not mask.any():
            self._alert_history.append(False)
            return self._empty_alert(t0, t1, tau)

        v_t = torch.from_numpy(values).unsqueeze(0).to(self.device)
        m_t = torch.from_numpy(mask).unsqueeze(0).to(self.device)
        t_grid = torch.linspace(0.0, 1.0, self.K + 1).unsqueeze(0).to(self.device)
        self.model.eval()
        with torch.no_grad():
            _, s = self.model._sweep(v_t, m_t, t_grid, collect_scores=True)

        scores_valid = s[0, ~torch.isnan(s[0])]
        peak_score = float(scores_valid.max().item()) if len(scores_valid) > 0 else 0.0
        is_anomaly = bool(peak_score > tau)
        self._alert_history.append(is_anomaly)
        confirmed = sum(self._alert_history) >= self.hysteresis_n
        confidence = self.model.compute_confidence(peak_score)

        if not is_anomaly:
            severity = "LOW"
        elif confidence >= 0.95 or peak_score > 3.0 * tau:
            severity = "CRITICAL"
        elif confidence >= 0.85 or peak_score > 1.5 * tau:
            severity = "HIGH"
        else:
            severity = "MEDIUM"

        attribution = None
        threat_class = "calm-baseline"
        if is_anomaly:
            top_ch, threat, errs = self._attribute_window(v_t, m_t, t_grid, s)
            attribution = {"top_channel": top_ch, "threat_type": threat, "feature_errors": errs}
            threat_class = THREAT_CLASS_MAP.get(threat, "unknown")
            attribution["threat_type"] = threat_class

        return AlertEvent(
            window_t0=t0, window_t1=t1, peak_score=peak_score,
            threshold=tau, is_anomaly=is_anomaly, confirmed=confirmed,
            confidence=round(confidence, 4), severity=severity,
            threat_class=threat_class, evidence=self._compute_evidence(t0, t1),
            attribution=attribution,
        )

    def _attribute_window(self, v_t, m_t, t_grid, s) -> Tuple[str, str, Dict[str, float]]:
        tau = float(self.model.threshold.item())
        scores_row = s[0]
        anom_mask = (scores_row > tau) & torch.isfinite(scores_row)
        if not anom_mask.any():
            anom_mask = torch.isfinite(scores_row)
        anom_indices = anom_mask.nonzero().flatten().tolist()
        if not anom_indices:
            peak_idx = int(torch.nan_to_num(scores_row, nan=float("-inf")).argmax().item())
            anom_indices = [peak_idx]

        cum_errs = np.zeros(self.model.d_x, dtype=np.float32)
        h = torch.zeros(1, self.model.d_h, device=self.device)
        last_idx = max(anom_indices)
        for j in range(last_idx + 1):
            obs = m_t[:, j]
            if obs.any():
                x = v_t[:, j]
                y_minus = self.model.outputNN(h)
                if j in anom_indices:
                    cum_errs += ((x[0] - y_minus[0]) ** 2).detach().cpu().numpy()
                h = torch.where(obs.unsqueeze(-1), self.model.jumpNN(x), h)

        top_idx = int(np.argmax(cum_errs))
        name, threat = ATTRIBUTION_MAP.get(top_idx, ("unknown", "unknown"))
        errs = {FEATURES[i]: float(cum_errs[i]) for i in range(len(cum_errs)) if i < len(FEATURES)}
        return name, threat, errs

    def _compute_evidence(self, t0: float, t1: float) -> Dict:
        indices = [i for i, t in enumerate(self._t_buf) if t0 <= t <= t1 + 1e-5]
        flows = [self._flow_buf[i] for i in indices if i < len(self._flow_buf)]
        f_counts = Counter(flows)
        return {
            "distinct_flows": len(f_counts),
            "packet_count": len(indices),
        }

    def _compute_flow_hash(self, flow_key: bytes) -> int:
        if not flow_key:
            return 0
        return struct.unpack(">H", hashlib.md5(flow_key).digest()[:2])[0]

    def _prune_buffer(self, min_t: float) -> None:
        idx = 0
        while idx < len(self._t_buf) and self._t_buf[idx] < min_t:
            idx += 1
        if idx > 0:
            del self._t_buf[:idx]
            del self._F_buf[:idx]
            del self._flow_buf[:idx]

    def _empty_alert(self, t0, t1, tau) -> AlertEvent:
        return AlertEvent(
            window_t0=t0, window_t1=t1, peak_score=0.0,
            threshold=tau, is_anomaly=False, confirmed=False,
            confidence=0.0, severity="LOW", threat_class="calm-baseline",
        )
