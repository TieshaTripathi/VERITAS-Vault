"""Cloud CAS records or durable local SQLite. Cloud outages never fail open."""
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from urllib.parse import quote

from src.pwa.security import data_dir, ROOT
from src.storage.supabase_client import SupabaseCloud, CloudUnavailable


class Store:
    def __init__(self):
        url = os.environ.get("SUPABASE_URL")
        key = (
            os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY")
        )
        if bool(url) != bool(key):
            raise CloudUnavailable("Both Supabase settings must be configured")
        self.cloud = SupabaseCloud() if url and key else None
        if os.environ.get("VERCEL") and not self.cloud:
            raise CloudUnavailable("Vercel requires Supabase; ephemeral SQLite is not an access-control store")
        if os.environ.get("VERCEL") and not os.environ.get("APP_ORIGIN", "").startswith("https://"):
            raise CloudUnavailable("A fixed HTTPS APP_ORIGIN is required on Vercel")
        if not self.cloud:
            data_dir().mkdir(parents=True, exist_ok=True)
            with self.db() as conn:
                conn.executescript("""
                  CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, payload TEXT NOT NULL, version INTEGER NOT NULL);
                  CREATE TABLE IF NOT EXISTS enrolled_users(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                  CREATE TABLE IF NOT EXISTS access_audit_logs(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                  CREATE TABLE IF NOT EXISTS enrollment_requests(id TEXT PRIMARY KEY, payload TEXT NOT NULL);
                """)

    @contextmanager
    def db(self):
        conn = sqlite3.connect(data_dir() / "vault-pwa.sqlite3", timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def get(self, key):
        if self.cloud:
            rows = self.cloud.rows("vault_records", id=f"eq.{key}", select="payload,version")
            return (rows[0]["payload"], rows[0]["version"]) if rows else (None, -1)
        with self.db() as conn:
            row = conn.execute("SELECT payload,version FROM records WHERE id=?", (key,)).fetchone()
        return (json.loads(row[0]), row[1]) if row else (None, -1)

    def cas(self, key, version, payload, event=None, job=None):
        if self.cloud:
            return self.cloud.request("POST", "/rest/v1/rpc/vault_commit", json={
                "record_id": key, "expected_version": version, "new_payload": payload,
                "audit_event": event, "alert_job": job,
            }).json()
        with self.db() as conn:
            row = conn.execute("SELECT version FROM records WHERE id=?", (key,)).fetchone()
            if (row[0] if row else -1) != version:
                return False
            conn.execute("INSERT INTO records VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,version=excluded.version",
                         (key, json.dumps(payload), version + 1))
            if event:
                conn.execute("INSERT OR IGNORE INTO access_audit_logs VALUES(?,?)", (event["id"], json.dumps(event)))
            if job:
                conn.execute("INSERT OR IGNORE INTO records VALUES(?,?,0)", ("job:" + job["id"], json.dumps(job)))
        return True

    def put(self, key, payload):
        for _ in range(5):
            _, version = self.get(key)
            if self.cas(key, version, payload):
                return
        raise CloudUnavailable("Concurrent update; retry the operation")

    def records(self, prefix):
        if self.cloud:
            return [(r["id"], r["payload"], r["version"]) for r in self.cloud.rows(
                "vault_records", id=f"like.{prefix}*", select="id,payload,version", limit="1000")]
        with self.db() as conn:
            rows = conn.execute("SELECT id,payload,version FROM records WHERE id LIKE ? LIMIT 1000", (prefix + "%",)).fetchall()
        return [(key, json.loads(payload), version) for key, payload, version in rows]

    def personnel(self):
        if self.cloud:
            rows = [r["pwa_data"] for r in self.cloud.rows("enrolled_users", select="pwa_data", pwa_data="not.is.null", limit="1000")]
        else:
            with self.db() as conn:
                raw_rows = conn.execute("SELECT payload FROM enrolled_users").fetchall()
            rows = [json.loads(r[0]) for r in raw_rows]
        # Exclude revoked identities
        return [p for p in rows if p.get("status") != "REVOKED"]

    def enroll(self, person):
        # Personnel IDs are unique; enrollment must never silently overwrite an identity.
        if self.cloud:
            self.cloud.request("POST", "/rest/v1/enrolled_users", json={
                "user_id": person["id"], "name": person["name"], "role": person["role"], "pwa_data": person})
        else:
            with self.db() as conn:
                conn.execute("INSERT OR REPLACE INTO enrolled_users VALUES(?,?)", (person["id"], json.dumps(person)))

    def revoke_user(self, user_id: str, revoker: str) -> bool:
        people = self.personnel()
        match = next((p for p in people if p["id"] == user_id), None)
        if not match:
            return False
        match["status"] = "REVOKED"
        match["revoked_by"] = revoker
        match["revoked_at"] = time.time()
        self.enroll(match)
        return True

    def save_enrollment_request(self, request_record: dict):
        req_id = request_record["request_id"]
        if self.cloud:
            self.cloud.request("POST", "/rest/v1/enrollment_requests", json={
                "request_id": req_id, "user_id": request_record["user_id"],
                "name": request_record["name"], "role": request_record["role"],
                "created_by": request_record["created_by"], "status": request_record["status"],
                "template_data": json.dumps(request_record)
            })
        else:
            with self.db() as conn:
                conn.execute("INSERT OR REPLACE INTO enrollment_requests VALUES(?,?)",
                             (req_id, json.dumps(request_record)))

    def get_enrollment_request(self, req_id: str) -> dict | None:
        if self.cloud:
            rows = self.cloud.rows("enrollment_requests", request_id=f"eq.{req_id}", select="template_data")
            return json.loads(rows[0]["template_data"]) if rows else None
        with self.db() as conn:
            row = conn.execute("SELECT payload FROM enrollment_requests WHERE id=?", (req_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def enrollment_requests(self, status: str = "") -> list[dict]:
        if self.cloud:
            query = {"select": "template_data"}
            if status:
                query["status"] = f"eq.{status}"
            rows = self.cloud.rows("enrollment_requests", **query)
            return [json.loads(r["template_data"]) for r in rows]
        with self.db() as conn:
            rows = conn.execute("SELECT payload FROM enrollment_requests").fetchall()
        parsed = [json.loads(r[0]) for r in rows]
        return [r for r in parsed if not status or r.get("status") == status]

    def logs(self, limit=200):
        if self.cloud:
            return [r["pwa_data"] for r in self.cloud.rows("access_audit_logs", select="pwa_data", pwa_data="not.is.null", order="id.desc", limit=str(limit))]
        with self.db() as conn:
            rows = conn.execute("SELECT payload FROM access_audit_logs ORDER BY rowid DESC LIMIT ?", (limit,)).fetchall()
        return [json.loads(r[0]) for r in rows]

    def event(self, event_id):
        if self.cloud:
            rows = self.cloud.rows("access_audit_logs", event_id=f"eq.{event_id}", select="pwa_data")
            return rows[0]["pwa_data"] if rows else None
        with self.db() as conn:
            row = conn.execute("SELECT payload FROM access_audit_logs WHERE id=?", (event_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save_blob(self, path, blob):
        if self.cloud:
            self.cloud.upload(path, blob)
        else:
            target = data_dir() / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(blob)

    def read_blob(self, path):
        if self.cloud:
            return self.cloud.download(path)
        target = (data_dir() / path).resolve()
        if not target.is_relative_to(data_dir().resolve()):
            raise ValueError("Invalid evidence path")
        return target.read_bytes()

    def delete_blob(self, path: str):
        if self.cloud:
            try:
                self.cloud.request("DELETE", "/storage/v1/object/encrypted-evidence/" + quote(path, safe="/"))
            except Exception:
                pass
        else:
            target = (data_dir() / path).resolve()
            if target.is_relative_to(data_dir().resolve()) and target.exists():
                try:
                    target.unlink()
                except Exception:
                    pass

    def clear_personnel(self) -> int:
        people = self.personnel()
        count = len(people)
        for person in people:
            if person.get("baseline"):
                self.delete_blob(person["baseline"])
            local_kf = ROOT / "models" / "known_faces" / f"{person.get('id', '')}.enc"
            if local_kf.exists():
                try:
                    local_kf.unlink()
                except Exception:
                    pass

        baselines_dir = data_dir() / "baselines"
        if baselines_dir.exists():
            for p in baselines_dir.glob("*.enc"):
                try:
                    p.unlink()
                except Exception:
                    pass

        if self.cloud:
            try:
                self.cloud.request("DELETE", "/rest/v1/enrolled_users?id=not.is.null")
            except Exception:
                pass
        else:
            with self.db() as conn:
                cur = conn.execute("DELETE FROM enrolled_users")
                count = max(count, cur.rowcount)
        return count

