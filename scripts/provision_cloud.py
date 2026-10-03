"""Create/upgrade private tables and bucket, then verify a read and CAS round trip."""
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dotenv import load_dotenv
load_dotenv()


def main():
    import psycopg
    from src.storage.supabase_client import SupabaseCloud
    url = os.environ.get("DATABASE_URL")
    if not url:
        raise SystemExit("DATABASE_URL is required for schema provisioning. An API key cannot execute arbitrary DDL.")
    schema = Path(__file__).resolve().parents[1] / "supabase" / "schema.sql"
    with psycopg.connect(url, sslmode="require", connect_timeout=10) as connection:
        connection.execute(schema.read_text(encoding="utf-8"))
        policies = connection.execute("select tablename,rowsecurity from pg_tables where schemaname='public' and tablename in ('enrolled_users','access_audit_logs','vault_records')").fetchall()
        assert len(policies) == 3 and all(row[1] for row in policies)
    cloud = SupabaseCloud()
    cloud.rows("enrolled_users", select="user_id", limit="1")
    previous = cloud.rows("vault_records", id="eq.health:provision", select="version")
    assert cloud.request("POST", "/rest/v1/rpc/vault_commit", json={
        "record_id": "health:provision", "expected_version": previous[0]["version"] if previous else -1,
        "new_payload": {"provisioning_check": "passed"}, "audit_event": None, "alert_job": None,
    }).json() is True
    bucket = cloud.request("GET", "/storage/v1/bucket/encrypted-evidence").json()
    assert bucket["public"] is False
    print("Provisioned and verified: three RLS tables, atomic checkpoint RPC, private encrypted-evidence bucket.")


if __name__ == "__main__":
    main()
