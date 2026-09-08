# Architecture — ZERO-DAY SIH26145

## System Overview

ZERO-DAY implements a **dual-layer detection architecture** for identifying cyber threats in unidirectional IP traffic. The system operates entirely within a passive monitoring enclave — it never probes, re-contacts, or blocks traffic.

```
┌─────────────────────────────────────────────────────────────────┐
│                    MONITORING ENCLAVE (Air-Gapped)              │
│                                                                 │
│  ┌──────────┐    ┌──────────────────────────────────────────┐   │
│  │  Data     │    │         DETECTION ENGINE                 │   │
│  │  Diode    │───►│                                          │   │
│  │  (HW/SW)  │    │  ┌──────────────┐  ┌──────────────────┐ │   │
│  └──────────┘    │  │  Layer 1:    │  │  Layer 2:       │ │   │
│                   │  │  Rule-Based  │  │  NJ-ODE         │ │   │
│  ┌──────────┐    │  │  Detectors   │  │  Anomaly        │ │   │
│  │  PCAP    │    │  │              │  │  Detection      │ │   │
│  │  Ingest  │───►│  │  • DDoS      │  │                  │ │   │
│  │  (Scapy) │    │  │  • Beacon    │  │  • Unsupervised  │ │   │
│  └──────────┘    │  │  • DGA       │  │  • Zero-day      │ │   │
│                   │  │  • DNS Tunnel│  │  • Channel       │ │   │
│                   │  │  • Port Scan │  │    Attribution   │ │   │
│                   │  │  • Exfil     │  │                  │ │   │
│                   │  └──────┬───────┘  └────────┬─────────┘ │   │
│                   │         │                    │            │   │
│                   │         └────────┬───────────┘            │   │
│                   │                  ▼                        │   │
│                   │  ┌──────────────────────────────────┐    │   │
│                   │  │        Alert Engine               │    │   │
│                   │  │  • Pydantic v2 strict schema      │    │   │
│                   │  │  • Auto severity from confidence  │    │   │
│                   │  │  • Thread-safe bounded store      │    │   │
│                   │  │  • on_alert callback              │    │   │
│                   │  └──────────┬───────────────────────┘    │   │
│                   │             │                             │   │
│                   └─────────────┼─────────────────────────────┘   │
│                                 ▼                                │
│                   ┌──────────────────────────┐                   │
│                   │     FastAPI Server        │                   │
│                   │  REST: /api/*             │                   │
│                   │  WS: /ws/alerts           │                   │
│                   └──────────┬───────────────┘                   │
│                              ▼                                   │
│                   ┌──────────────────────────┐                   │
│                   │   React Dashboard         │                   │
│                   │   (SOC-style UI)          │                   │
│                   └──────────────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Contracts Layer (`contracts.py`)

All data flowing through the system is validated by Pydantic v2 models:

- **`FlowEvent`** — Input contract. A single passive network observation with fields for timestamp, IPs, ports, protocol, DNS/TLS metadata. Severity is auto-derived from confidence.
- **`AlertV1`** — Output contract. Every alert answers WHAT (threat_class), HOW confident (confidence + severity), and WHY (evidence list).
- **`EvidenceItem`** — Single piece of supporting evidence with feature name, numeric value, and human-readable reason.

### 2. Feature Extraction (`features.py`)

Pure-function feature extraction — no state, no side effects:

- **Shannon entropy** of packet payloads and DNS query names
- **DNS lexical scoring** — digit ratio, consonant ratio, label length, entropy → composite DGA score
- **TLS metadata** — packet-size CV, timing CV, JA3/JA4 presence (metadata only, no decryption)
- **5-channel features** for NJ-ODE: IAT, bytes, entropy, burst indicator, direction

### 3. Rule-Based Detectors (`rules/`)

Six detectors implementing a common `DetectorBase` interface:

| Detector | Threat Class | Signals | Thresholds |
|---|---|---|---|
| `DDoSDetector` | Volumetric DDoS | SYN count, unique sources, source IP entropy | syn_threshold=100, min_sources=20 |
| `BeaconDetector` | C2 Beacon | IAT CV, destination concentration | cv_threshold=0.15, min_beacons=5 |
| `DGADetector` | DGA Domains | Lexical score, query entropy | score_threshold=0.55 |
| `DNSTunnelDetector` | DNS Tunnelling | Query length, record type, volume | long_query=50 chars, volume=30 |
| `PortScanDetector` | Port Scan | Fan-out across ports/hosts | min_ports=10, min_hosts=10 |
| `ExfiltrationDetector` | Data Exfil | Outbound/inbound ratio, volume | ratio=5.0, volume=1MB |

Each detector:
- Accepts `FlowEvent` one at a time (streaming)
- Maintains bounded rolling-window state (deque-based pruning)
- Produces `AlertV1` records with evidence
- Has configurable cooldown to prevent alert storms

### 4. NJ-ODE Model (`njode.py`)

Neural Jump ODE (Herrera, Krach & Teichmann, ICLR 2021):

- **Architecture**: InputNN (5→16) → Jumps (16→32→8) + Jumps&Holds (16→32→8) → GRU (16→16) → OutputNN (16→5)
- **Training**: Unsupervised — learns conditional expectation of BENIGN traffic
- **Inference**: Anomaly score = MSE between predicted and actual feature values
- **Calibration**: MLP-based quantile threshold (τ) via `QuantileCalibrator`
- **Channel Attribution**: Which feature channel (IAT/bytes/entropy/burst/direction) caused the anomaly → maps to threat class

### 5. Shared Windowing (`windowing.py`)

**One implementation, two consumers** — eliminates train/serve skew:

```python
# Same function used for both:
values, mask = aggregate_slots(t, F, t0, window_s, K, dt, mean, std)
```

- **`Windower`** — Batch consumer for training/evaluation
- **`LiveFeeder`** — Streaming consumer with sliding windows, hysteresis confirmation, calibrated confidence

### 6. Alert Engine (`engine.py`)

Orchestrates both detection layers:

```python
engine = AlertEngine(model_path="models/njode_v1.pt", on_alert=broadcast)
alerts = engine.process_event(event)  # Runs both layers
```

- Thread-safe bounded alert store (deque with maxlen)
- `on_alert` callback for WebSocket broadcasting
- NJ-ODE alerts only emitted when no rule already caught the same threat class
- Hysteresis: NJ-ODE requires N of M recent windows anomalous before confirming

### 7. API (`api.py`)

FastAPI application:

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | GET | Health check |
| `/api/metrics` | GET | Events processed, alerts, throughput |
| `/api/alerts` | GET | Recent alerts (bounded) |
| `/api/scenarios` | GET | Available replay scenarios |
| `/api/replay/{scenario}` | POST | Start replaying a JSONL scenario |
| `/api/replay/stop` | POST | Stop current replay |
| `/ws/alerts` | WS | Real-time alert stream |

## Data Flow

```
1. Packet/Event arrives (PCAP, JSONL, or live capture)
   │
2. FlowEvent created (Pydantic validated)
   │
3. Feature extraction (pure functions)
   │
4. Rule-based detectors process event
   │ ├── If threshold exceeded → AlertV1 created
   │ └── State updated (rolling window)
   │
5. NJ-ODE LiveFeeder ingests feature packet
   │ ├── Sliding window evaluated when full
   │ ├── Anomaly score computed
   │ ├── If anomalous + confirmed → AlertV1 created
   │ └── Channel attribution → threat_class mapping
   │
6. Alert Engine stores alert, fires on_alert callback
   │
7. WebSocket broadcasts to connected dashboards
   │
8. Dashboard displays alert with evidence
```

## Security Properties

| Property | Implementation |
|---|---|
| **Read-only ingest** | System never sends packets, probes, or responses |
| **No payload decryption** | TLS analysis uses metadata only (JA3/JA4, packet sizes, timing) |
| **Air-gap compatible** | No return path required; QR diode concept for one-way data transfer |
| **Evidence chain** | Every alert carries cited evidence with feature values and reasons |
| **Bounded state** | All detectors use deque-based pruning with configurable window sizes |
| **Thread-safe** | AlertEngine uses threading.lock for concurrent access |

## Performance

| Mode | Throughput | Latency |
|---|---|---|
| Rules-only | 40,202 events/sec | < 1ms per event |
| Rules + NJ-ODE | 70 events/sec | ~14ms per event |
| NJ-ODE training | 96 windows in 60 epochs | ~5s total |
