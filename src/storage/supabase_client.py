import os
import time
import httpx



class CloudUnavailable(RuntimeError):
    pass


class SupabaseCloud:
    def __init__(self):
        self.url = (os.environ.get("SUPABASE_URL") or os.environ.get("NEXT_PUBLIC_SUPABASE_URL", "")).rstrip("/")
        self.key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or os.environ.get("SUPABASE_KEY") or os.environ.get("NEXT_PUBLIC_SUPABASE_ANON_KEY", "")
        if not self.url.startswith("https://") or not self.key:
            raise CloudUnavailable("Supabase URL and server secret key are required")

    def request(self, method, path, *, json=None, content=None, headers=None, params=None):
        auth = {"apikey": self.key}
        if self.key.startswith("eyJ"):
            auth["Authorization"] = f"Bearer {self.key}"
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
                raise CloudUnavailable("Cloud connection failed; access stays locked") from exc
            except httpx.HTTPError as exc:
                # Never include a URL, token or provider response in a public error.
                raise CloudUnavailable("Cloud request failed; access stays locked") from exc
        raise CloudUnavailable("Cloud request failed; access stays locked") from last_exc

    def check_health(self, timeout: float = 3.0) -> bool:
        """Lightweight database connectivity check with strict timeout."""
        try:
            auth = {"apikey": self.key}
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
