"""Test suite for the Zero-Day SIH26145 detection engine."""
import json
import math
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pytest
import torch

from zero_day.contracts import AlertV1, FlowEvent, Severity, ThreatClass
from zero_day.engine import AlertEngine
from zero_day.features import (
    D_X,
    FeatureStream,
    dns_label_features,
    events_to_feature_stream,
    packets_to_feature_stream,
    shannon_entropy,
    string_entropy,
)
from zero_day.njode import ATTRIBUTION_MAP, FEATURES, MODEL_VERSION, NJODE, attribute_error
from zero_day.replay import read_jsonl_events, replay
from zero_day.windowing import AlertEvent, LiveFeeder, Windower, aggregate_slots
from zero_day._synthetic import generate_attack_events, generate_benign_events

DT = 0.01
K = 50
HORIZON = DT * K


# ── Contract tests ───────────────────────────────────────────────────────────

class TestContracts:
    def test_flow_event_defaults(self):
        e = FlowEvent()
        assert e.timestamp.tzinfo is not None
        assert e.protocol == ""

    def test_alert_confidence_clamped(self):
        a = AlertV1(threat_class=ThreatClass.DDOS, confidence=1.5)
        assert a.confidence == 1.0
        a2 = AlertV1(threat_class=ThreatClass.DDOS, confidence=-0.5)
        assert a2.confidence == 0.0

    def test_alert_severity_derived(self):
        a = AlertV1(threat_class=ThreatClass.PORT_SCAN, confidence=0.95)
        assert a.severity == Severity.CRITICAL
        a2 = AlertV1(threat_class=ThreatClass.PORT_SCAN, confidence=0.5)
        assert a2.severity == Severity.MEDIUM


# ── Feature tests ────────────────────────────────────────────────────────────

class TestFeatures:
    def test_shannon_entropy_uniform(self):
        # 256 distinct bytes → ~8 bits
        data = bytes(range(256))
        e = shannon_entropy(data)
        assert 7.9 < e <= 8.0

    def test_shannon_entropy_empty(self):
        assert shannon_entropy(b"") == 0.0

    def test_string_entropy(self):
        assert string_entropy("aaaa") == 0.0
        assert string_entropy("abcd") > 1.9

    def test_dns_label_features_dga_like(self):
        f = dns_label_features("xk3j9f2mab1c4d5.example.com")
        assert f["lexical_score"] > 0.3
        assert f["digit_ratio"] > 0.0

    def test_dns_label_features_benign(self):
        f = dns_label_features("www.google.com")
        assert f["lexical_score"] < 0.6

    def test_events_to_feature_stream(self):
        events = [
            FlowEvent(timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc), bytes_src_to_dst=100),
            FlowEvent(timestamp=datetime(2026, 1, 1, 0, 0, 1, tzinfo=timezone.utc), bytes_src_to_dst=200),
        ]
        stream = events_to_feature_stream(events)
        assert len(stream) == 2
        assert stream.F.shape == (2, D_X)


# ── NJ-ODE tests ─────────────────────────────────────────────────────────────

class TestNJODE:
    @pytest.fixture()
    def model(self):
        torch.manual_seed(7)
        return NJODE(d_x=4, d_h=6, hidden=16, grid_step=DT, horizon=HORIZON)

    def test_grid_must_divide_horizon(self):
        with pytest.raises(AssertionError):
            NJODE(d_x=4, grid_step=0.03, horizon=1.0)

    def test_sweep_shapes(self, model):
        model.eval()
        vals = torch.zeros(8, K + 1, 4)
        mask = torch.rand(8, K + 1) < 0.1
        mask[:, 0] = True
        loss, scores = model._sweep(vals, mask, torch.arange(K + 1) * DT)
        assert loss.ndim == 0 and torch.isfinite(loss)
        assert scores.shape == (8, K + 1)

    def test_uncalibrated_flags_nothing(self, model):
        model.eval()
        vals = torch.zeros(4, K + 1, 4)
        mask = torch.rand(4, K + 1) < 0.1
        mask[:, 0] = True
        _, flags = model.compute_anomaly_scores(vals, mask, torch.arange(K + 1) * DT)
        assert not flags.any()

    def test_calibration_reduces_fpr(self, model):
        model.eval()
        vals = torch.zeros(64, K + 1, 4)
        mask = torch.rand(64, K + 1, generator=torch.Generator().manual_seed(42)) < 0.1
        mask[:, 0] = True
        model.calibrate([(vals, mask, torch.arange(K + 1) * DT)], quantile=0.99)
        _, flags = model.compute_anomaly_scores(vals, mask, torch.arange(K + 1) * DT)
        assert flags.float().mean().item() < 0.03

    def test_save_load_roundtrip(self, model, tmp_path):
        model.eval()
        vals = torch.zeros(4, K + 1, 4)
        mask = torch.rand(4, K + 1, generator=torch.Generator().manual_seed(42)) < 0.2
        mask[:, 0] = True
        model.calibrate([(vals, mask, torch.arange(K + 1) * DT)])
        path = str(tmp_path / "test.pt")
        model.save(path)
        loaded = NJODE.load(path)
        assert torch.allclose(model.threshold, loaded.threshold)

    def test_fit_reduces_objective(self, model):
        torch.manual_seed(0)
        vals = torch.zeros(32, K + 1, 4)
        mask = torch.rand(32, K + 1, generator=torch.Generator().manual_seed(17)) < 0.1
        mask[:, 0] = True
        t = torch.arange(K + 1) * DT
        model.eval()
        loss0, _ = model._sweep(vals, mask, t)
        model.fit([(vals, mask, t)], epochs=15, log_every=1000)
        model.eval()
        loss1, _ = model._sweep(vals, mask, t)
        assert loss1 < loss0

    def test_attribute_error(self):
        x = torch.tensor([0.0, 25.0, 0.5, 0.0])
        y = torch.tensor([0.0, 0.0, 0.5, 0.0])
        name, threat, _ = attribute_error(x, y)
        assert name == "bytes"
        assert threat == "exfil-flood"


# ── Windowing tests ──────────────────────────────────────────────────────────

class TestWindowing:
    def test_aggregate_slots_collision(self):
        t = np.array([0.21, 0.24, 0.28], dtype=np.float64)
        F = np.array([
            [0.05, 100.0, 2.0, 0.0, 0.0],
            [0.03, 500.0, 4.5, 0.0, 1.0],
            [0.01, 800.0, 7.2, 1.0, 1.0],
        ], dtype=np.float32)
        values, mask = aggregate_slots(t, F, 0.0, 10.0, 100, 0.01)
        slot = 2
        assert mask[slot]
        assert values[slot, 0] == pytest.approx(0.01)  # iat min
        assert values[slot, 1] == pytest.approx(1400.0)  # bytes sum
        assert values[slot, 2] == pytest.approx(7.2)  # entropy max
        assert values[slot, 3] == pytest.approx(1.0)  # burst max
        assert values[slot, 4] == pytest.approx(1.0)  # direction majority

    def test_live_feeder_sliding_stride(self):
        torch.manual_seed(42)
        model = NJODE(d_x=5, d_h=6, hidden=16, grid_step=DT, horizon=HORIZON)
        model.x_mean.copy_(torch.tensor([0.5, 100.0, 3.0, 0.1, 0.0]))
        model.x_std.copy_(torch.tensor([0.2, 50.0, 1.0, 0.3, 1.0]))
        model.threshold.copy_(torch.tensor(10.0))
        model.eval()

        feeder = LiveFeeder(model, window_s=10.0, stride_s=2.0)
        emitted = 0
        for sec in range(16):
            from zero_day.features import FeaturePacket
            pkt = FeaturePacket(t=float(sec), size=80, payload=b"test")
            alerts = feeder.ingest_packet(pkt)
            emitted += len(alerts)

        # With 16 seconds of data, window_s=10, stride_s=2, we should emit 3+ windows
        assert emitted >= 3


# ── Rule detector tests ──────────────────────────────────────────────────────

class TestRules:
    def test_ddos_detector(self):
        from zero_day.rules import DDoSDetector
        det = DDoSDetector(syn_threshold=10, min_sources=5, window_s=10.0)
        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        # Generate 15 SYN-only packets from 6 sources
        all_alerts = []
        for i in range(15):
            e = FlowEvent(
                timestamp=now,
                src_ip=f"10.0.0.{i % 6}",
                dst_ip="192.168.1.1",
                protocol="tcp",
                packets_src_to_dst=1,
                bytes_src_to_dst=60,
                bytes_dst_to_src=0,
            )
            all_alerts.extend(det.process(e))
        assert len(all_alerts) >= 1
        assert all_alerts[0].threat_class == ThreatClass.DDOS

    def test_port_scan_detector(self):
        from zero_day.rules import PortScanDetector
        det = PortScanDetector(min_ports=10, min_hosts=10, window_s=10.0)
        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        alerts = []
        for port in range(20):
            e = FlowEvent(
                timestamp=now,
                src_ip="10.0.0.1",
                dst_ip=f"192.168.1.{port % 5 + 1}",
                dst_port=port + 1,
                protocol="tcp",
                packets_src_to_dst=1,
                bytes_src_to_dst=60,
            )
            alerts.extend(det.process(e))
        assert len(alerts) >= 1
        assert alerts[0].threat_class == ThreatClass.PORT_SCAN

    def test_beacon_detector(self):
        from zero_day.rules import BeaconDetector
        det = BeaconDetector(cv_threshold=0.2, min_beacons=5, window_s=60.0)
        base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        all_alerts = []
        for i in range(10):
            import datetime as dt
            e = FlowEvent(
                timestamp=base + dt.timedelta(seconds=i * 5.0),
                src_ip="10.0.0.1",
                dst_ip="192.168.1.1",
                dst_port=443,
                protocol="tcp",
                packets_src_to_dst=1,
                bytes_src_to_dst=128,
            )
            all_alerts.extend(det.process(e))
        assert len(all_alerts) >= 1
        assert all_alerts[0].threat_class == ThreatClass.BEACON

    def test_dga_detector(self):
        from zero_day.rules import DGADetector
        det = DGADetector(score_threshold=0.4)
        now = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        e = FlowEvent(
            timestamp=now,
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            protocol="dns",
            dns_query="xk3j9f2mab1c4d5e6f7g8h9.example.com",
            dns_query_type="A",
        )
        alerts = det.process(e)
        assert len(alerts) >= 1
        assert alerts[0].threat_class == ThreatClass.DGA


# ── Engine integration test ──────────────────────────────────────────────────

class TestEngine:
    def test_process_event(self):
        engine = AlertEngine(enable_njode=False)
        e = FlowEvent(
            src_ip="10.0.0.1", dst_ip="192.168.1.1",
            protocol="tcp", packets_src_to_dst=1, bytes_src_to_dst=60,
        )
        alerts = engine.process_event(e)
        assert isinstance(alerts, list)
        assert engine.get_metrics()["events_processed"] == 1

    def test_benchmark_synthetic(self):
        engine = AlertEngine(enable_njode=False)
        events = generate_benign_events(duration_s=30.0)
        for e_raw in events:
            e = FlowEvent(
                timestamp=datetime.fromtimestamp(e_raw.t, tz=timezone.utc),
                src_ip="10.0.0.1", dst_ip="192.168.1.1",
                protocol="tcp",
                bytes_src_to_dst=e_raw.size,
            )
            engine.process_event(e)
        metrics = engine.get_metrics()
        assert metrics["events_processed"] > 0

    def test_replay_jsonl(self, tmp_path):
        events = [
            FlowEvent(src_ip="10.0.0.1", dst_ip="192.168.1.1", protocol="tcp"),
            FlowEvent(src_ip="10.0.0.2", dst_ip="192.168.1.2", protocol="udp"),
        ]
        path = tmp_path / "test.jsonl"
        with open(path, "w") as f:
            for e in events:
                f.write(e.model_dump_json() + "\n")
        loaded = read_jsonl_events(str(path))
        assert len(loaded) == 2

    def test_live_feeder_integration(self):
        torch.manual_seed(42)
        model = NJODE(d_x=5, d_h=6, hidden=16, grid_step=DT, horizon=HORIZON)
        model.x_mean.copy_(torch.tensor([0.5, 100.0, 3.0, 0.1, 0.0]))
        model.x_std.copy_(torch.tensor([0.2, 50.0, 1.0, 0.3, 1.0]))
        model.threshold.copy_(torch.tensor(5.0))
        model.eval()

        from zero_day.features import FeaturePacket
        feeder = LiveFeeder(model, window_s=5.0, stride_s=2.0)
        for i in range(20):
            pkt = FeaturePacket(t=float(i), size=80 + (i * 100), payload=b"\x00" * 10, direction=i % 2)
            feeder.ingest_packet(pkt)
        alerts = feeder.flush()
        assert isinstance(alerts, list)
