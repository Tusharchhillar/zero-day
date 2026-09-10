"""CLI entry points for the Zero-Day detection engine."""
from __future__ import annotations

import argparse
import json
import sys


def run_api():
    """Launch the FastAPI server."""
    parser = argparse.ArgumentParser(description="Zero-Day SIH26145 API Server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()
    import uvicorn
    uvicorn.run("zero_day.api:app", host=args.host, port=args.port, reload=args.reload)


def run_replay():
    """Replay a JSONL file through the detection engine."""
    from zero_day.engine import AlertEngine
    from zero_day.replay import read_jsonl_events, replay

    parser = argparse.ArgumentParser(description="Replay events through detection engine")
    parser.add_argument("file", help="Path to JSONL event file")
    parser.add_argument("--speed", type=float, default=0, help="Playback speed (0=instant)")
    parser.add_argument("--model", default=None, help="Path to NJ-ODE checkpoint")
    parser.add_argument("--limit", type=int, default=None, help="Max events to replay")
    parser.add_argument("--json", action="store_true", help="Output alerts as JSON lines")
    args = parser.parse_args()

    engine = AlertEngine(model_path=args.model, enable_njode=args.model is not None)
    events = read_jsonl_events(args.file)

    def on_event(e):
        alerts = engine.process_event(e)
        for a in alerts:
            if args.json:
                print(a.model_dump_json())
            else:
                print(f"  [{a.severity.value}] {a.threat_class.value} conf={a.confidence:.2f} "
                      f"src={a.src_ip} dst={a.dst_ip} det={a.detector}")

    result = replay(events, on_event=on_event, speed=args.speed, max_events=args.limit)
    engine.flush_njode()
    metrics = engine.get_metrics()
    print(f"\n{'='*60}")
    print(f"Replayed {result['events_replayed']} events in {result['wall_time_s']:.3f}s")
    print(f"Alerts: {metrics['alerts_emitted']} | Rate: {metrics['events_per_sec']:.1f} evt/s")
    if args.json:
        print(json.dumps(metrics, indent=2))


def run_train():
    """Train the NJ-ODE model on synthetic benign traffic."""
    import torch
    from zero_day.features import FeatureStream, packets_to_feature_stream
    from zero_day.njode import NJODE
    from zero_day.windowing import Windower

    parser = argparse.ArgumentParser(description="Train Zero-Day NJ-ODE model")
    parser.add_argument("--epochs", type=int, default=60)
    parser.add_argument("--output", default="models/njode_v1.pt")
    parser.add_argument("--device", default="cpu")
    args = parser.parse_args()

    torch.manual_seed(0)

    print("[1/5] Generating synthetic benign traffic...")
    from zero_day._synthetic import generate_benign_events
    from zero_day.contracts import FlowEvent
    from zero_day.features import events_to_feature_stream
    from datetime import datetime, timezone
    events = generate_benign_events(duration_s=1200.0)
    # Convert to FlowEvents → flow-level features (entropy=0, matches serving)
    flow_events = []
    for pkt in events:
        flow_events.append(FlowEvent(
            timestamp=datetime.fromtimestamp(pkt.t, tz=timezone.utc),
            src_ip="10.0.0.1", dst_ip="192.168.1.1", protocol="tcp",
            bytes_src_to_dst=pkt.size, flow_id=f"flow-{len(flow_events)}",
        ))
    stream = events_to_feature_stream(flow_events)
    print(f"      {len(stream)} packets featurized (flow-level, entropy=0)")

    model = NJODE(d_x=5, d_h=10)
    win = Windower(model, window_s=10.0)
    win.fit_standardizer(stream)

    v_all, m_all, t_grid = win.windows(stream)
    n_windows = len(v_all)
    train_end = int(0.8 * n_windows)
    v_train, m_train = v_all[:train_end], m_all[:train_end]
    t_train = t_grid.expand(v_train.shape[0], -1)
    v_cal, m_cal = v_all[train_end:], m_all[train_end:]
    t_cal = t_grid.expand(v_cal.shape[0], -1)

    print(f"[2/5] {len(v_train)} training windows, {len(v_cal)} calibration windows")

    loader = torch.utils.data.DataLoader(
        torch.utils.data.TensorDataset(v_train, m_train, t_train),
        batch_size=32, shuffle=True,
    )

    print(f"[3/5] Training NJ-ODE ({args.epochs} epochs)...")
    model.fit(loader, epochs=args.epochs, log_every=10, device=args.device)

    print("[4/5] Calibrating threshold τ...")
    model.calibrate([(v_cal, m_cal, t_cal)], device=args.device)

    model.save(args.output)
    print(f"[5/5] Checkpoint saved → {args.output}")


def run_evaluate():
    """Evaluate the model against synthetic attack traffic."""
    import torch
    from datetime import datetime, timezone
    from zero_day.contracts import FlowEvent
    from zero_day.features import events_to_feature_stream
    from zero_day.njode import NJODE
    from zero_day.windowing import Windower

    parser = argparse.ArgumentParser(description="Evaluate Zero-Day detection")
    parser.add_argument("--checkpoint", default="models/njode_v1.pt")
    parser.add_argument("--output", default="results/eval.json")
    args = parser.parse_args()

    torch.manual_seed(0)

    from zero_day._synthetic import generate_benign_events, generate_attack_events
    from pathlib import Path

    def _to_flow_events(pkts):
        flow = []
        for pkt in pkts:
            flow.append(FlowEvent(
                timestamp=datetime.fromtimestamp(pkt.t, tz=timezone.utc),
                src_ip="10.0.0.1", dst_ip="192.168.1.1", protocol="tcp",
                bytes_src_to_dst=pkt.size, flow_id=f"f-{len(flow)}",
            ))
        return flow

    print("[1/3] Generating evaluation data...")
    benign = generate_benign_events(duration_s=480.0)
    ben_stream = events_to_feature_stream(_to_flow_events(benign))

    model = NJODE.load(args.checkpoint)
    win = Windower(model, window_s=10.0)
    win.fit_standardizer(ben_stream)

    attacks = {
        "syn_flood": "ddos",
        "port_scan": "recon",
        "dns_tunnel": "tunnel",
        "c2_beacon": "beacon",
        "exfil_burst": "exfil",
        "encrypted_c2": "malware",
    }

    print("[2/3] Evaluating per-attack detection...")
    results = {}
    for name, attack_type in attacks.items():
        atk_events = generate_attack_events(attack_type, duration_s=10.0)
        atk_stream = events_to_feature_stream(_to_flow_events(atk_events))
        v, m, t = win.windows(atk_stream)
        if len(v) == 0:
            results[name] = {"detection_rate": 0.0}
            continue
        t_exp = t.expand(v.shape[0], -1)
        s, flags = model.compute_anomaly_scores(v, m, t_exp)
        det_rate = flags.any(dim=1).float().mean().item()
        results[name] = {"detection_rate": det_rate}
        print(f"  {name}: {det_rate*100:.0f}% detection")

    print("[3/3] Saving results...")
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {args.output}")


def run_benchmark():
    """Benchmark the detection engine throughput."""
    import time
    from datetime import datetime, timezone
    from zero_day.contracts import FlowEvent
    from zero_day.engine import AlertEngine
    from zero_day._synthetic import generate_benign_events

    parser = argparse.ArgumentParser(description="Benchmark detection throughput")
    parser.add_argument("--events", type=int, default=10000, help="Number of events")
    parser.add_argument("--model", default=None, help="Path to NJ-ODE checkpoint")
    args = parser.parse_args()

    engine = AlertEngine(model_path=args.model, enable_njode=args.model is not None)
    raw = generate_benign_events(duration_s=600.0)[:args.events]

    # Convert FeaturePacket → FlowEvent
    events = []
    for pkt in raw:
        events.append(FlowEvent(
            timestamp=datetime.fromtimestamp(pkt.t, tz=timezone.utc),
            src_ip="10.0.0.1", dst_ip="192.168.1.1", protocol="tcp",
            bytes_src_to_dst=pkt.size, flow_id=f"flow-{len(events)}",
        ))

    print(f"Benchmarking {len(events)} events...")
    t0 = time.perf_counter()
    for e in events:
        engine.process_event(e)
    elapsed = time.perf_counter() - t0
    metrics = engine.get_metrics()

    print(f"\n{'='*60}")
    print(f"Events: {len(events)}")
    print(f"Wall time: {elapsed:.3f}s")
    print(f"Throughput: {len(events)/elapsed:.0f} events/sec")
    print(f"Alerts emitted: {metrics['alerts_emitted']}")
    print(f"{'='*60}")


def run_mock_target():
    """Launch the ApexGov mock banking target server."""
    from zero_day.db import AlertDB
    from zero_day.mock_target.server import app, set_cold_db

    parser = argparse.ArgumentParser(description="ApexGov Mock Banking Pentest Target")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    # Pass SQLite handle directly so mock-target can persist http_logs
    db = AlertDB("data/alerts.db")
    set_cold_db(db)

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port)


def main():
    """Dispatch subcommands: api, replay, train, evaluate, benchmark, mock-target."""
    parser = argparse.ArgumentParser(
        prog="zero-day",
        description="ZERO-DAY SIH26145 — AI-Based Cyber Threat Detection",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("api", help="Launch FastAPI detection API server")
    sub.add_parser("replay", help="Replay JSONL events through detection engine")
    sub.add_parser("train", help="Train NJ-ODE model on synthetic traffic")
    sub.add_parser("evaluate", help="Evaluate detection rates on attack scenarios")
    sub.add_parser("benchmark", help="Benchmark detection engine throughput")
    sub.add_parser("mock-target", help="Launch mock banking target portal on port 5000")

    args, remaining = parser.parse_known_args()

    # Reset sys.argv so subcommand parsers see their own args
    sys.argv = [sys.argv[0]] + remaining

    commands = {
        "api": run_api,
        "replay": run_replay,
        "train": run_train,
        "evaluate": run_evaluate,
        "benchmark": run_benchmark,
        "mock-target": run_mock_target,
    }
    commands[args.command]()


if __name__ == "__main__":
    main()
