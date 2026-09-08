"""JSONL replay engine — feeds events to the detection engine incrementally."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, List, Optional

from zero_day.contracts import FlowEvent


def read_jsonl_events(path: str) -> List[FlowEvent]:
    """Read FlowEvents from a JSONL file (one JSON object per line)."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                events.append(FlowEvent.model_validate(data))
            except json.JSONDecodeError as e:
                print(f"[replay] skip line {line_no}: JSON error: {e}")
            except Exception as e:
                print(f"[replay] skip line {line_no}: {e}")
    return events


def replay(
    events: List[FlowEvent],
    on_event: Callable[[FlowEvent], None],
    on_alert: Optional[Callable[[FlowEvent, List], None]] = None,
    speed: float = 1.0,
    max_events: Optional[int] = None,
) -> dict:
    """Replay events at the specified speed, calling on_event for each.

    Args:
        events: sorted FlowEvents
        on_event: called for each event
        on_alert: called with (event, alerts) when alerts are produced
        speed: 1.0 = real-time, >1 = faster, 0 = instant
        max_events: stop after this many events
    """
    count = 0
    t_start = time.time()
    prev_ts = None

    for event in events:
        if max_events and count >= max_events:
            break

        # Maintain real-time pacing
        if speed > 0 and prev_ts is not None:
            dt = event.timestamp.timestamp() - prev_ts
            if dt > 0:
                time.sleep(dt / speed)

        on_event(event)
        prev_ts = event.timestamp.timestamp()
        count += 1

    elapsed = time.time() - t_start
    return {"events_replayed": count, "wall_time_s": round(elapsed, 3), "speed": speed}
