"""SQLite to Supabase Migration & Database Client — ZERO-DAY SIH26145

This script:
1. Extracts all historical alerts from local SQLite ('data/alerts.db').
2. Transforms evidence JSON strings into native PostgreSQL JSONB formats.
3. Uploads/upserts all records directly into your Supabase PostgreSQL table via Supabase REST API or Python client.

Usage:
  python tools/migrate_to_supabase.py --url YOUR_SUPABASE_URL --key YOUR_SUPABASE_KEY
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


class SupabaseAlertDB:
    """Python handler to interact directly with Supabase alerts table."""

    def __init__(self, supabase_url: str, supabase_key: str, table_name: str = "alerts"):
        self.supabase_url = supabase_url.rstrip("/")
        self.supabase_key = supabase_key
        self.table_name = table_name
        self.endpoint = f"{self.supabase_url}/rest/v1/{self.table_name}"

    def _headers(self, prefer_upsert: bool = False) -> Dict[str, str]:
        headers = {
            "apikey": self.supabase_key,
            "Authorization": f"Bearer {self.supabase_key}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        if prefer_upsert:
            headers["Prefer"] = "resolution=merge-duplicates,return=representation"
        return headers

    def insert_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Upsert a list of alert dictionaries into Supabase."""
        if not alerts:
            return []

        data_bytes = json.dumps(alerts).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data_bytes,
            headers=self._headers(prefer_upsert=True),
            method="POST",
        )

        try:
            with urllib.request.urlopen(req) as resp:
                result_json = resp.read().decode("utf-8")
                return json.loads(result_json) if result_json else []
        except urllib.error.HTTPError as e:
            err_msg = e.read().decode("utf-8")
            raise RuntimeError(f"Supabase API Error ({e.code}): {err_msg}")

    def get_alerts(self, limit: int = 100, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetch alerts from Supabase."""
        params = f"?select=*&order=timestamp.desc&limit={limit}"
        if status and status != "All":
            params += f"&status=eq.{urllib.parse.quote(status)}"

        req = urllib.request.Request(
            f"{self.endpoint}{params}",
            headers=self._headers(),
            method="GET",
        )

        try:
            with urllib.request.urlopen(req) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            print(f"[Supabase] Error fetching alerts: {e}")
            return []


def migrate_sqlite_to_supabase(sqlite_db_path: str, supabase_url: str, supabase_key: str):
    """Extract alerts from SQLite database and migrate them into Supabase."""
    print(f"📦 Connecting to SQLite database at '{sqlite_db_path}'...")
    db_file = Path(sqlite_db_path)
    if not db_file.exists():
        print(f"❌ SQLite database file '{sqlite_db_path}' not found.")
        return

    conn = sqlite3.connect(str(db_file))
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM alerts")
    rows = cursor.fetchall()
    print(f"Found {len(rows)} alerts in SQLite database.")

    supabase_payloads = []
    for r in rows:
        row_dict = dict(r)

        # Format evidence_json string to native JSON array for PostgreSQL JSONB
        ev_raw = row_dict.pop("evidence_json", "[]")
        try:
            evidence_jsonb = json.loads(ev_raw)
        except Exception:
            evidence_jsonb = []

        # Convert epoch float to ISO timestamptz string if needed
        created_at_val = row_dict.get("created_at")
        if isinstance(created_at_val, (int, float)):
            created_at_iso = datetime.fromtimestamp(created_at_val, tz=timezone.utc).isoformat()
        else:
            created_at_iso = datetime.now(timezone.utc).isoformat()

        payload = {
            "alert_id": row_dict.get("alert_id"),
            "timestamp": row_dict.get("timestamp"),
            "flow_id": row_dict.get("flow_id"),
            "src_ip": row_dict.get("src_ip", "0.0.0.0"),
            "dst_ip": row_dict.get("dst_ip", "0.0.0.0"),
            "src_port": row_dict.get("src_port", 443),
            "dst_port": row_dict.get("dst_port", 443),
            "protocol": row_dict.get("protocol", "TCP"),
            "threat_class": row_dict.get("threat_class"),
            "sih_category": row_dict.get("sih_category"),
            "severity": row_dict.get("severity"),
            "confidence": float(row_dict.get("confidence", 0.0)),
            "status": row_dict.get("status", "New"),
            "detector": row_dict.get("detector"),
            "evidence": evidence_jsonb,
            "model_version": row_dict.get("model_version", "1.0"),
            "observation_window_s": float(row_dict.get("observation_window_s", 0.0)),
            "source_rate": float(row_dict.get("source_rate", 0.0)) if row_dict.get("source_rate") else None,
            "created_at": created_at_iso,
        }
        supabase_payloads.append(payload)

    print(f"🚀 Uploading {len(supabase_payloads)} records to Supabase...")
    db_client = SupabaseAlertDB(supabase_url=supabase_url, supabase_key=supabase_key)
    res = db_client.insert_alerts(supabase_payloads)
    print(f"✅ Migration complete! {len(res)} records successfully pushed to Supabase.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate ZERO-DAY SQLite alerts to Supabase")
    parser.add_argument("--sqlite", default="data/alerts.db", help="Path to SQLite db file")
    parser.add_argument("--url", default=os.getenv("SUPABASE_URL", "https://czvjvwtvmyvajhlbwrud.supabase.co"), help="Supabase Project URL")
    parser.add_argument("--key", default=os.getenv("SUPABASE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN6dmp2d3R2bXl2YWpobGJ3cnVkIiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODkwMDgxNzMsImV4cCI6MjEwNDU4NDE3M30.xNtvspUnHzaUGwD2DgHybHc64Xz52Ahd_dK3tcBvmjI"), help="Supabase API/Service Key")
    args = parser.parse_args()

    migrate_sqlite_to_supabase(args.sqlite, args.url, args.key)
