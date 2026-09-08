# 🔒 ZERO-DAY — SIH26145

**AI-Based Detection of Cyber Threats in Unidirectional IP Traffic**

> Smart India Hackathon 2026 | Problem Statement ID: 26145 | Organization: NTRO

[![Tests](https://img.shields.io/badge/tests-26%2F26%20passing-brightgreen)]()
[![Python](https://img.shields.io/badge/python-3.11+-blue)]()
[![PyTorch](https://img.shields.io/badge/pytorch-2.0+-red)]()

---

## 🎯 Problem

Critical-infrastructure operators use **hardware data diodes** to copy traffic into a monitoring enclave — **one direction only**. The enclave can see everything, but cannot probe, re-contact, or block. The challenge: **detect 6 classes of cyber threat using only passive observation.**

## 💡 Our Solution: Dual-Layer Detection

```
                         PASSIVE INGEST (read-only)
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
         ┌──────────────────┐   ┌──────────────────┐
         │  LAYER 1:        │   │  LAYER 2:        │
         │  Rule-Based      │   │  NJ-ODE          │
         │  (6 detectors)   │   │  (unsupervised)  │
         │  40K evt/s       │   │  70 evt/s        │
         │  fast, explainable│  │  catches zero-day│
         └────────┬─────────┘   └────────┬─────────┘
                  │                       │
                  └───────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │  Alert Engine        │
                   │  Pydantic v2 schema  │
                   │  Auto severity       │
                   └──────────┬───────────┘
                              ▼
                   ┌──────────────────────┐
                   │  API + Dashboard     │
                   │  FastAPI + WebSocket │
                   │  React/TypeScript    │
                   └──────────────────────┘
```

**The X-factor:** Layer 2 (NJ-ODE) learns what "normal" looks like and flags anything that deviates — **including attacks we've never seen before.** Channel attribution tells analysts *what kind* of anomaly it is, without labeled training data.

## 🛡️ Threat Coverage

| # | Threat Class | Layer 1 (Rules) | Layer 2 (NJ-ODE) |
|---|---|---|---|
| a | **Volumetric/Protocol DDoS** | SYN flood + UDP amplification | Anomaly via direction channel |
| b | **Botnet C2 Beaconing** | IAT periodicity + CV scoring | IAT channel attribution |
| c | **DGA Domains** | Entropy/n-gram lexical scoring | Entropy channel |
| d | **DNS Tunnelling** | Query length + record-type anomalies | Entropy channel |
| e | **Encrypted Session Malware** | TLS metadata behavioral analysis | Entropy + size channels |
| f | **Reconnaissance/Port Scan** | Fan-out across ports/hosts | Burst + direction channels |
| g | **Data Exfiltration** | Asymmetric volume + byte ratio | Bytes channel |

## 🚀 Quick Start

```bash
# Install
git clone https://github.com/ZERO-DAY-SIH/zero-day.git
cd zero-day
pip install -e ".[dev]"

# Run tests (26 passing)
pytest tests/ -v

# Train the NJ-ODE model
python -m zero_day.cli train --epochs 60

# Benchmark throughput
python -m zero_day.cli benchmark --events 5000

# Replay an attack scenario
python -m zero_day.cli replay data/fixtures/full_scenario.jsonl --speed 0 --model models/njode_v1.pt

# Launch the API server
python -m zero_day.cli api --port 8000

# Launch the dashboard (separate terminal)
cd frontend && npm install && npm run dev
```

## 📁 Project Structure

```
ZERO-DAY/
├── src/zero_day/          # Core detection engine
│   ├── contracts.py       # Pydantic v2 alert/event schemas
│   ├── features.py        # Feature extraction (entropy, DNS lexical, TLS)
│   ├── rules/             # 6 rule-based detectors
│   ├── njode.py           # Neural Jump ODE model (ICLR 2021)
│   ├── windowing.py       # Shared train/serve windowing
│   ├── engine.py          # Dual-layer alert engine
│   ├── api.py             # FastAPI + WebSocket
│   ├── cli.py             # CLI entry points
│   ├── replay.py          # JSONL replay engine
│   └── _synthetic.py      # Synthetic traffic generators
├── tests/                 # 26 tests
├── data/fixtures/         # Demo JSONL scenarios
├── models/                # Trained NJ-ODE checkpoints
├── frontend/              # React/TypeScript dashboard
├── tools/                 # Fixture generators
└── results/               # Benchmark + evaluation results
```

## 🏗️ Architecture Constraints (PS Compliance)

| Constraint | Status |
|---|---|
| ✅ **Read-only ingest** | No probes, no return path, no inline block |
| ✅ **No payload decryption** | TLS/QUIC metadata only, never decrypted content |
| ✅ **Streaming, not batch** | Event-by-event processing, bounded latency |
| ✅ **Throughput target stated** | 40,202 evt/s (rules), 70 evt/s (with NJ-ODE) |
| ✅ **Standardized alert schema** | Pydantic v2 with timestamp, flow_id, threat_class, confidence, evidence |

## 🔬 The NJ-ODE Model

Based on Herrera, Krach & Teichmann (ICLR 2021, [arXiv:2006.04727](https://arxiv.org/abs/2006.04727)).

The Neural Jump ODE models the **conditional expectation of normal traffic** as a continuous-time function. When observed traffic deviates from this learned expectation, the anomaly score spikes. Unlike supervised classifiers, NJ-ODE:

- Requires **no labeled attack data** — learns from benign traffic only
- Detects **novel/zero-day attacks** as deviations from normal
- Provides **channel attribution** — identifies which feature (IAT, bytes, entropy, etc.) caused the anomaly

### Training

```bash
python -m zero_day.cli train --epochs 60 --output models/njode_v1.pt
```

### Evaluation

```bash
python -m zero_day.cli evaluate --checkpoint models/njode_v1.pt
```

## 📊 Evaluation Results

```json
{
  "syn_flood": {"detection_rate": 1.0},
  "port_scan": {"detection_rate": 1.0},
  "dns_tunnel": {"detection_rate": 1.0},
  "c2_beacon": {"detection_rate": 1.0},
  "exfil_burst": {"detection_rate": 1.0},
  "encrypted_c2": {"detection_rate": 1.0}
}
```

> ⚠️ Current evaluation uses synthetic-vs-synthetic data. Real PCAP datasets (CIC-IDS2017, CSE-CIC-IDS2018) needed for production validation.

## 📝 Alert Schema Example

```json
{
  "alert_id": "a1b2c3d4e5f6",
  "timestamp": "2026-09-08T12:00:00Z",
  "flow_id": "flood-1234",
  "src_ip": "185.34.12.67",
  "dst_ip": "192.168.1.100",
  "threat_class": "volumetric_ddos",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "detector": "volumetric_ddos",
  "evidence": [
    {
      "feature": "syn_packet_count",
      "value": 150,
      "reason": "150 SYN-only packets in 10s window (threshold: 100)"
    },
    {
      "feature": "unique_sources",
      "value": 25,
      "reason": "25 unique source IPs (threshold: 20)"
    }
  ]
}
```

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Language | Python 3.11+ |
| ML Framework | PyTorch 2.0+ |
| Anomaly Detection | Neural Jump ODE (continuous-time) |
| Alert Schema | Pydantic v2 (strict validation) |
| API | FastAPI + WebSocket |
| Dashboard | React + TypeScript |
| Testing | pytest (26 tests) |
| Benchmarking | Custom throughput harness |

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

**Team ZERO DAY** | SIH 2026 | Problem Statement 26145
