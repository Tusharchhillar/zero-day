"""Neural Jump ODE — unsupervised anomaly detection core.

Adapted from Herrera, Krach & Teichmann (ICLR 2021, arXiv:2006.04727).
Learns conditional expectation of BENIGN traffic; deviations = anomalies.

This is the X-factor: detects zero-day attacks without ever having seen them.
"""
from __future__ import annotations

import math
import warnings
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
import torch.nn as nn

MODEL_VERSION = "1.0"
FEATURES = ["iat", "bytes", "entropy", "burst", "direction"]


# ── Building blocks ──────────────────────────────────────────────────────────

class ResidualMLP(nn.Module):
    """2-hidden-layer tanh MLP with residual shortcut when dims match."""

    def __init__(self, in_dim: int, out_dim: int, hidden: int = 50, dropout: float = 0.1):
        super().__init__()
        self.body = nn.Sequential(
            nn.Linear(in_dim, hidden), nn.Tanh(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden), nn.Tanh(), nn.Dropout(dropout),
            nn.Linear(hidden, out_dim),
        )
        self.use_skip = in_dim == out_dim

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        y = self.body(x)
        return y + x if self.use_skip else y


class ODEVectorField(nn.Module):
    """f_θ(h, x_last, t_last, Δt) → dh/dt — the continuous dynamics."""

    def __init__(self, d_x: int, d_h: int, hidden: int = 50, dropout: float = 0.1):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(d_h + d_x + 2, hidden), nn.Tanh(), nn.Dropout(dropout),
            nn.Linear(hidden, hidden), nn.Tanh(), nn.Dropout(dropout),
            nn.Linear(hidden, d_h),
        )

    def forward(self, h: torch.Tensor, x_last: torch.Tensor,
                t_last: torch.Tensor, dt: torch.Tensor) -> torch.Tensor:
        z = torch.cat([torch.tanh(h), torch.tanh(x_last), t_last, dt], dim=-1)
        return self.net(z)


# ── NJ-ODE core ──────────────────────────────────────────────────────────────

class NJODE(nn.Module):
    """Neural Jump ODE for passive threat detection.

    The model learns E[X_t | A_t] of benign traffic. Anomaly score S = ||x - y⁻||²
    where y⁻ is the prediction just before the observation. Peaks in S past
    calibrated threshold τ indicate anomalous behavior.
    """

    def __init__(self, d_x: int = 5, d_h: int = 10, hidden: int = 50,
                 dropout: float = 0.1, grid_step: float = 0.01, horizon: float = 1.0):
        super().__init__()
        assert horizon / grid_step == int(horizon / grid_step), "grid must divide horizon"
        self.d_x = d_x
        self.d_h = d_h
        self.hidden = hidden
        self.dropout = dropout
        self.dt = grid_step
        self.K = int(round(horizon / grid_step))

        self.jumpNN = ResidualMLP(d_x, d_h, hidden, dropout)
        self.outputNN = ResidualMLP(d_h, d_x, hidden, dropout)
        self.f = ODEVectorField(d_x, d_h, hidden, dropout)

        self.register_buffer("threshold", torch.tensor(float("inf")))
        self.register_buffer("x_mean", torch.zeros(d_x))
        self.register_buffer("x_std", torch.ones(d_x))
        self.register_buffer("calibration_quantiles", torch.tensor([float("inf")] * 4))
        self._reset_stream()

    def _sweep(self, values: torch.Tensor, mask: torch.Tensor,
               t_grid: torch.Tensor, collect_scores: bool = False) -> Tuple[torch.Tensor, torch.Tensor]:
        """One pass over the time grid. Returns (objective, per-obs scores)."""
        if t_grid.dim() == 2:
            t_grid = t_grid[0]
        B = values.size(0)
        dev = values.device
        h = torch.zeros(B, self.d_h, device=dev)
        x_last = torch.zeros(B, self.d_x, device=dev)
        t_last = torch.zeros(B, 1, device=dev)
        seen = torch.zeros(B, dtype=torch.bool, device=dev)
        term_sum = torch.zeros(B, device=dev)
        obs_cnt = torch.zeros(B, device=dev)
        scores = torch.full((B, self.K + 1), float("nan"), device=dev)

        for j in range(self.K + 1):
            obs = mask[:, j]
            if obs.any():
                x = values[:, j]
                y_minus = self.outputNN(h)
                h_new = self.jumpNN(x)
                y_new = self.outputNN(h_new)
                jump_err = (x - y_new).norm(dim=-1)
                cont_err = (y_new - y_minus).norm(dim=-1)
                term = (jump_err + cont_err) ** 2
                term = torch.where(seen, term, jump_err ** 2)
                term_sum += torch.where(obs, term, torch.zeros_like(term))
                obs_cnt += obs.float()
                if collect_scores:
                    s = ((x - y_minus) ** 2).sum(-1)
                    scores[:, j] = torch.where(obs & seen, s, scores[:, j])
                upd = obs.unsqueeze(-1)
                h = torch.where(upd, h_new, h)
                x_last = torch.where(upd, x, x_last)
                t_last = torch.where(upd, t_grid[j].view(1, 1).expand(B, 1), t_last)
                seen = seen | obs
            if j < self.K:
                delta = t_grid[j] - t_last
                h = h + self.dt * self.f(h, x_last, t_last, delta)

        return (term_sum / obs_cnt.clamp(min=1.0)).mean(), scores

    def fit(self, loader, epochs: int = 200, lr: float = 1e-3,
            weight_decay: float = 5e-4, device: str = "cpu", log_every: int = 10) -> "NJODE":
        """Adam training with the paper's recipe."""
        self.to(device)
        opt = torch.optim.Adam(self.parameters(), lr=lr, weight_decay=weight_decay)
        for ep in range(1, epochs + 1):
            self.train()
            tot = 0.0
            for values, mask, t_grid in loader:
                values, mask, t_grid = values.to(device), mask.to(device), t_grid.to(device)
                opt.zero_grad()
                loss, _ = self._sweep(values, mask, t_grid)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.parameters(), 1.0)
                opt.step()
                tot += loss.item()
            if ep == 1 or ep % log_every == 0:
                print(f"    epoch {ep:3d}/{epochs}  loss = {tot / len(loader):.5f}")
        return self

    @torch.no_grad()
    def calibrate(self, loader, device: str = "cpu", quantile: float = 0.995) -> "NJODE":
        """Set τ from held-out benign window-peak scores."""
        self.to(device).eval()
        chunks = []
        for values, mask, t_grid in loader:
            _, s = self._sweep(values.to(device), mask.to(device),
                               t_grid.to(device), collect_scores=True)
            peaks = torch.nan_to_num(s, nan=float("-inf")).amax(dim=1)
            valid = (peaks != float("-inf")) & torch.isfinite(peaks)
            if valid.any():
                chunks.append(peaks[valid])
        if not chunks:
            raise ValueError("No valid window peaks during calibration.")
        s = torch.cat(chunks)
        tau_mean = s.mean() + 3.0 * s.std()
        tau_q = torch.quantile(s, quantile)
        self.threshold.copy_(torch.maximum(tau_mean, tau_q))
        q_levels = torch.tensor([0.5, 0.9, 0.99, 0.999], device=s.device)
        self.calibration_quantiles.copy_(torch.quantile(s, q_levels))
        print(f"[✓] window-peak τ = {self.threshold.item():.4f}")
        return self

    def compute_confidence(self, peak_score: float) -> float:
        """Calibrated confidence in [0, 1] monotonic with peak score."""
        if peak_score <= 0.0 or not math.isfinite(peak_score):
            return 0.0
        tau = float(self.threshold.item()) if torch.isfinite(self.threshold) else 2.81
        q = self.calibration_quantiles.cpu().tolist()
        if any(math.isinf(v) for v in q):
            if peak_score <= tau:
                return float(0.5 * (peak_score / max(1e-4, tau)))
            excess = (peak_score - tau) / max(1e-4, tau)
            return float(min(1.0, 0.5 + 0.5 * (1.0 - math.exp(-0.4 * excess))))
        q50, q90, q99, q999 = q
        if peak_score <= q50:
            return float(max(0.0, 0.10 * (peak_score / max(1e-4, q50))))
        elif peak_score <= q90:
            return float(0.10 + 0.50 * (peak_score - q50) / max(1e-4, q90 - q50))
        elif peak_score <= q99:
            return float(0.60 + 0.30 * (peak_score - q90) / max(1e-4, q99 - q90))
        elif peak_score <= q999:
            return float(0.90 + 0.08 * (peak_score - q99) / max(1e-4, q999 - q99))
        else:
            excess = (peak_score - q999) / max(1e-4, q999)
            return float(min(1.0, 0.98 + 0.02 * (1.0 - math.exp(-0.5 * excess))))

    @torch.no_grad()
    def compute_anomaly_scores(self, values: torch.Tensor, mask: torch.Tensor,
                               t_grid: torch.Tensor, device: str = "cpu") -> Tuple[torch.Tensor, torch.Tensor]:
        self.to(device).eval()
        _, s = self._sweep(values.to(device), mask.to(device),
                           t_grid.to(device), collect_scores=True)
        return s, s > self.threshold

    # ── Streaming mode ──────────────────────────────────────────────────────
    def _reset_stream(self) -> None:
        self._sh = self._sx = self._st = None

    @torch.no_grad()
    def score_packet(self, t_norm: float, x_std: torch.Tensor) -> Tuple[float, bool]:
        """Score one packet in streaming mode. NaN on first packet."""
        self.eval()
        x = x_std.view(1, -1)
        t = torch.tensor([[t_norm]], dtype=x.dtype, device=x.device)
        if self._sh is None:
            self._sh, self._sx, self._st = self.jumpNN(x), x, t
            return float("nan"), False
        n = max(int(round((t.item() - self._st.item()) / self.dt)), 0)
        for k in range(n):
            t_cur = self._st.item() + k * self.dt
            delta = torch.tensor([[t_cur - self._st.item()]])
            self._sh = self._sh + self.dt * self.f(self._sh, self._sx, self._st, delta)
        y_minus = self.outputNN(self._sh)
        score = ((x - y_minus) ** 2).sum().item()
        flag = score > self.threshold.item()
        self._sh, self._sx, self._st = self.jumpNN(x), x, t
        return score, flag

    # ── Persistence ─────────────────────────────────────────────────────────
    def save(self, path: str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        torch.save({
            "state_dict": self.state_dict(),
            "config": {
                "version": MODEL_VERSION,
                "features": list(FEATURES[: self.d_x]),
                "d_x": self.d_x, "d_h": self.d_h,
                "hidden": self.hidden, "dropout": self.dropout,
                "grid_step": self.dt, "horizon": self.dt * self.K,
            },
        }, path)

    @classmethod
    def load(cls, path: str, device: str = "cpu") -> "NJODE":
        ckpt = torch.load(path, map_location=device, weights_only=False)
        config = ckpt.get("config", {})
        if "version" not in config or "features" not in config:
            warnings.warn(
                f"Legacy checkpoint '{path}' — retrain via train.py for v{MODEL_VERSION}",
                UserWarning, stacklevel=2,
            )
        ckpt_features = config.get("features")
        d_x = config.get("d_x", len(ckpt_features) if ckpt_features else 5)
        expected = list(FEATURES[:d_x])
        if ckpt_features is not None and ckpt_features != expected:
            raise ValueError(f"Feature mismatch: {ckpt_features} vs {expected}")
        init_kw = {k: v for k, v in config.items()
                   if k in ("d_x", "d_h", "hidden", "dropout", "grid_step", "horizon")}
        m = cls(**init_kw)
        m.load_state_dict(ckpt["state_dict"])
        m.to(device)
        m._reset_stream()
        return m


# ── Channel attribution (unsupervised explainability) ────────────────────────

ATTRIBUTION_MAP = {
    0: ("iat", "beacon/recon"),
    1: ("bytes", "exfil-flood"),
    2: ("entropy", "tunnel/encrypted-c2"),
    3: ("burst", "exfil-flood"),
    4: ("direction", "volumetric-ddos"),
}

THREAT_CLASS_MAP = {
    "beacon/recon": "botnet_c2_beacon",
    "exfil-flood": "data_exfiltration",
    "tunnel/encrypted-c2": "dns_tunnelling",
    "volumetric-ddos": "volumetric_ddos",
}


def attribute_error(x: torch.Tensor, y_minus: torch.Tensor) -> Tuple[str, str, Dict[str, float]]:
    """Unsupervised channel attribution: which feature channel caused the anomaly?"""
    diff = ((x - y_minus) ** 2).detach().cpu().numpy().flatten()
    top_idx = int(np.argmax(diff))
    name = FEATURES[top_idx] if top_idx < len(FEATURES) else f"ch_{top_idx}"
    _, threat = ATTRIBUTION_MAP.get(top_idx, ("unknown", "unknown"))
    feature_names = FEATURES[: len(diff)]
    errs = {feature_names[i]: float(diff[i]) for i in range(len(diff))}
    return name, threat, errs
