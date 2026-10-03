"""Idempotent upload of this PWA's local encrypted registry/evidence to Supabase.

Never imports live sessions or replays historical alerts. Use the SAME encryption
key in both environments. Existing cloud identities/events are never overwritten.
"""
import base64
import json
import sqlite3
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
load_dotenv()
from src.pwa.security import data_dir, unseal
from src.storage.supabase_client import SupabaseCloud


def sync():
    path = data_dir() / "vault-pwa.sqlite3"
    if not path.exists():
        raise SystemExit("No PWA SQLite database found. Legacy plaintext registries need a separately reviewed migration.")
    cloud = SupabaseCloud()
    people_count = event_count = 0
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
        people = [json.loads(row[0]) for row in connection.execute("SELECT payload FROM enrolled_users")]
        events = [json.loads(row[0]) for row in connection.execute("SELECT payload FROM access_audit_logs")]
    for person in people:
        if cloud.rows("enrolled_users", user_id="eq." + person["id"], select="user_id"):
            continue
        unseal(base64.b64decode(person["template"]), "person:" + person["id"])
        baseline = (data_dir() / person["baseline"]).read_bytes()
        unseal(baseline, "baseline:" + person["id"])
        cloud.upload(person["baseline"], baseline)
        cloud.request("POST", "/rest/v1/enrolled_users", json={"user_id": person["id"], "name": person["name"], "role": person["role"], "pwa_data": person})
        people_count += 1
    for event in events:
        if cloud.rows("access_audit_logs", event_id="eq." + event["id"], select="event_id"):
            continue
        proof = event.get("evidence", {})
        if proof.get("path"):
            blob = (data_dir() / proof["path"]).read_bytes()
            unseal(blob, "evidence:" + event["sha256_hash"])
            cloud.upload(proof["path"], blob)
        event["status"] = "CLOUD_STORED"
        cloud.request("POST", "/rest/v1/access_audit_logs", json={"event_id": event["id"], "timestamp": event["timestamp"], "mode": event["mode"],
            "verified_parties": json.dumps(event["parties"]), "verdict": event["verdict"], "sha256_hash": event.get("sha256_hash") or "",
            "encrypted_path": proof.get("path", ""), "status": "CLOUD_STORED", "pwa_data": event})
        event_count += 1
    print(f"Synced {people_count} encrypted identities and {event_count} historical events. No alerts replayed.")


if __name__ == "__main__":
    sync()
