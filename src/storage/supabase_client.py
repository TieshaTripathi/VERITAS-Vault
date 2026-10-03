"""Privileged server-only Supabase REST client. Never sent to the browser."""
import os
from urllib.parse import quote

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
        try:
            response = httpx.request(method, self.url + path, headers=auth, params=params,
                                     json=json, content=content, timeout=8)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            # Never include a URL, token or provider response in a public error.
            raise CloudUnavailable("Cloud request failed; access stays locked") from exc
        return response

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
