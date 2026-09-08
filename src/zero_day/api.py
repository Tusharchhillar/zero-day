"""FastAPI application — REST API + WebSocket for the Zero-Day detection engine."""
from __future__ import annotations

import asyncio
import json
import threading
from pathlib import Path
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from zero_day.contracts import AlertV1, FlowEvent
from zero_day.engine import AlertEngine
from zero_day.replay import read_jsonl_events

# ── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(title="Zero-Day SIH26145", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── State ────────────────────────────────────────────────────────────────────

engine: AlertEngine = None  # type: ignore
ws_clients: List[WebSocket] = []
replay_status = {"running": False, "scenario": None}


def _broadcast_alert(alert: AlertV1) -> None:
    """Send alert to all connected WebSocket clients."""
    payload = json.dumps({"type": "alert", "data": alert.model_dump(mode="json")})
    dead = []
    for ws in ws_clients:
        try:
            asyncio.get_event_loop().create_task(ws.send_text(payload))
        except Exception:
            dead.append(ws)
    for ws in dead:
        ws_clients.remove(ws)


# ── Lifecycle ────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    global engine
    model_path = None
    pt = Path("models/njode_v1.pt")
    if pt.exists():
        model_path = str(pt)
    engine = AlertEngine(
        model_path=model_path,
        max_alerts=500,
        enable_njode=True,
        on_alert=_broadcast_alert,
    )


# ── REST endpoints ───────────────────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "engine": "ready"}


@app.get("/api/metrics")
async def metrics():
    return engine.get_metrics()


@app.get("/api/alerts")
async def alerts(limit: int = 50):
    return [a.model_dump(mode="json") for a in engine.get_alerts(limit=limit)]


@app.post("/api/replay/stop")
async def stop_replay():
    replay_status["running"] = False
    return {"status": "stopped"}


@app.post("/api/replay/{scenario}")
async def replay_scenario(scenario: str):
    """Start replaying a JSONL scenario file from data/fixtures/."""
    if replay_status["running"]:
        return JSONResponse({"error": "replay already running"}, status_code=409)

    fixture_path = Path(f"data/fixtures/{scenario}.jsonl")
    if not fixture_path.exists():
        return JSONResponse({"error": f"scenario '{scenario}' not found"}, status_code=404)

    events = read_jsonl_events(str(fixture_path))
    replay_status["running"] = True
    replay_status["scenario"] = scenario

    def _run():
        try:
            for event in sorted(events, key=lambda e: e.timestamp.timestamp()):
                if not replay_status["running"]:
                    break
                alerts = engine.process_event(event)
        finally:
            replay_status["running"] = False
            replay_status["scenario"] = None

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    return {"status": "started", "scenario": scenario, "events": len(events)}


@app.get("/api/scenarios")
async def scenarios():
    fixtures_dir = Path("data/fixtures")
    if not fixtures_dir.exists():
        return []
    return [f.stem for f in sorted(fixtures_dir.glob("*.jsonl"))]


# ── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    ws_clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text(json.dumps({"type": "pong"}))
    except WebSocketDisconnect:
        if websocket in ws_clients:
            ws_clients.remove(websocket)
