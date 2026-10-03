"""
API Caching Layer for Blockchain Forensic AI Side-Panel.

Implements lightweight in-memory TTL caching to eliminate redundant Alchemy/GoPlus & LLM API calls
for zero-history or recently analyzed wallet addresses.
"""

import time
from typing import Dict, Any, Optional


class ForensicCache:
    def __init__(self, default_ttl_seconds: int = 300):
        self.default_ttl = default_ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves cached result if not expired.
        """
        normalized_key = key.lower().strip()
        if normalized_key in self._cache:
            entry = self._cache[normalized_key]
            if time.time() < entry["expires_at"]:
                return entry["data"]
            else:
                # Remove expired entry
                del self._cache[normalized_key]
        return None

    def set(self, key: str, data: Dict[str, Any], ttl_seconds: Optional[int] = None) -> None:
        """
        Stores result in cache with expiration timestamp.
        """
        normalized_key = key.lower().strip()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        self._cache[normalized_key] = {
            "data": data,
            "cached_at": time.time(),
            "expires_at": time.time() + ttl
        }

    def clear(self) -> None:
        """Clears all cached entries."""
        self._cache.clear()

    def stats(self) -> Dict[str, int]:
        """Returns cache stats."""
        now = time.time()
        active_entries = sum(1 for e in self._cache.values() if e["expires_at"] > now)
        return {
            "total_keys": len(self._cache),
            "active_keys": active_entries
        }
