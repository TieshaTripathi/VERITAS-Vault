import os
import time
from urllib.parse import quote
import httpx



class CloudUnavailable(RuntimeError):
    def __init__(self, message="Cloud unavailable; access stays locked", status_code=None, error_code=None, safe_diagnostic=None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code
        self.safe_diagnostic = safe_diagnostic


class SupabaseCloud:
    def __init__(self):
        self.url = (os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL", "")).rstrip("/")
        self.key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_KEY") or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY", "")
        if not self.url.startswith("https://") or not self.key:
            raise CloudUnavailable("Supabase URL and server secret key are required")

    def request(self, method, path, *, json=None, content=None, headers=None, params=None):
        auth = {
            "apikey": self.key,
            "User-Agent": "VERITAS-Vault-Backend/3.0",
        }
        if self.key.startswith("eyJ"):
            auth["Authorization"] = f"Bearer {self.key}"
        # sb_secret_ opaque keys are passed strictly in apikey header without Bearer JWT wrapping
        auth.update(headers or {})

        # Bounded retries for transient connection reset or 502/503/504
        max_attempts = 2 if method in ("GET", "HEAD") else 1
        last_exc = None
        for attempt in range(max_attempts):
            try:
                response = httpx.request(method, self.url + path, headers=auth, params=params,
                                         json=json, content=content, timeout=8)
                if response.status_code in (502, 503, 504) and attempt < max_attempts - 1:
                    time.sleep(0.25)
                    continue
                response.raise_for_status()
                return response
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.RemoteProtocolError) as exc:
                last_exc = exc
                if attempt < max_attempts - 1:
                    time.sleep(0.25)
                    continue
                raise CloudUnavailable(
                    "Cloud connection failed; access stays locked",
                    safe_diagnostic="Cloud connection failed or timed out",
                ) from exc
            except httpx.HTTPStatusError as exc:
                status_code = exc.response.status_code
                error_code = None
                safe_diag = None
                try:
                    data = exc.response.json()
                    error_code = str(data.get("code") or "")
                    msg = str(data.get("message") or "")
                except Exception:
                    data = {}
                    error_code = ""
                    msg = ""

                # Distinguish exact failure modes safely without leaking tokens or keys:
                if status_code == 404 or error_code in ("PGRST204", "42P01") or "does not exist" in msg.lower():
                    safe_diag = "Table 'push_subscriptions' does not exist in Supabase database. Apply migration 20261008_push_subscriptions.sql in Supabase SQL Editor."
                elif status_code in (401, 403) or error_code == "42501" or "permission denied" in msg.lower():
                    safe_diag = "Permission denied for 'push_subscriptions' in Supabase. Ensure SUPABASE_SERVICE_ROLE_KEY is set in Render environment and RLS permissions granted."
                elif status_code == 400:
                    safe_diag = f"Supabase schema error (HTTP 400, code {error_code or 'BAD_REQUEST'}). Check table columns."
                elif status_code == 409:
                    safe_diag = "Supabase conflict on push subscription."
                elif status_code >= 500:
                    safe_diag = f"Supabase upstream service error (HTTP {status_code})."
                else:
                    safe_diag = f"Supabase request failed with HTTP {status_code}."

                raise CloudUnavailable(
                    "Cloud request failed; access stays locked",
                    status_code=status_code,
                    error_code=error_code,
                    safe_diagnostic=safe_diag,
                ) from exc
            except httpx.HTTPError as exc:
                # Never include a URL, token or provider response in a public error.
                raise CloudUnavailable("Cloud request failed; access stays locked") from exc
        raise CloudUnavailable("Cloud request failed; access stays locked") from last_exc

    def check_health(self, timeout: float = 3.0) -> bool:
        """Lightweight database connectivity check with strict timeout."""
        try:
            auth = {
                "apikey": self.key,
                "User-Agent": "VERITAS-Vault-Backend/3.0",
            }
            if self.key.startswith("eyJ"):
                auth["Authorization"] = f"Bearer {self.key}"
            res = httpx.get(f"{self.url}/rest/v1/vault_records?select=id&limit=1", headers=auth, timeout=timeout)
            return res.status_code in (200, 206)
        except Exception:
            return False

    def rows(self, table, **params):
        return self.request("GET", f"/rest/v1/{table}", params=params).json()

    def put(self, table, value, conflict):
        self.request("POST", f"/rest/v1/{table}", json=value,
                     params={"on_conflict": conflict},
                     headers={"Prefer": "resolution=merge-duplicates"})

    def upload(self, path, blob):
        self.request("POST", "/storage/v1/object/encrypted-evidence/" + quote(path, safe="/"),
                     content=blob, headers={"Content-Type": "application/octet-stream", "x-upsert": "true"})

    def download(self, path):
        return self.request("GET", "/storage/v1/object/authenticated/encrypted-evidence/" + quote(path, safe="/")).content
