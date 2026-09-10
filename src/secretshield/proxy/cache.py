"""Deterministic response caching engine for AI completions and idempotent API requests."""

import hashlib
import json
import time
from collections import OrderedDict
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel


class CacheEntry(BaseModel):
    """Cached HTTP response."""

    status_code: int
    headers: Dict[str, str]
    content: bytes
    created_at: float
    ttl_seconds: int

    @property
    def is_expired(self) -> bool:
        """Check if entry has passed its TTL."""
        return (time.monotonic() - self.created_at) > self.ttl_seconds


class ResponseCache:
    """In-memory LRU cache for deterministic API and AI responses."""

    def __init__(self, max_entries: int = 1000, default_ttl_seconds: int = 3600):
        self.max_entries = max_entries
        self.default_ttl = default_ttl_seconds
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def generate_cache_key(
        profile_name: str,
        method: str,
        path: str,
        query_params: Optional[Dict[str, str]] = None,
        content: Optional[bytes] = None,
    ) -> str:
        """Generate deterministic SHA-256 cache key from request properties."""
        norm_method = method.upper()
        norm_path = "/" + path.lstrip("/")
        norm_query = json.dumps(sorted((query_params or {}).items()))

        # Normalize JSON body if valid JSON
        norm_body: bytes = b""
        if content:
            try:
                parsed = json.loads(content.decode("utf-8"))
                norm_body = json.dumps(parsed, sort_keys=True).encode("utf-8")
            except Exception:
                norm_body = content

        hasher = hashlib.sha256()
        hasher.update(profile_name.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(norm_method.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(norm_path.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(norm_query.encode("utf-8"))
        hasher.update(b"|")
        hasher.update(norm_body)

        return hasher.hexdigest()

    def get(self, cache_key: str) -> Optional[Tuple[int, Dict[str, str], bytes]]:
        """Retrieve response from cache if present and unexpired."""
        entry = self._cache.get(cache_key)
        if not entry:
            self.misses += 1
            return None

        if entry.is_expired:
            del self._cache[cache_key]
            self.misses += 1
            return None

        # Move to end for LRU policy
        self._cache.move_to_end(cache_key)
        self.hits += 1

        # Return a copy of headers with cache indicator
        cached_headers = dict(entry.headers)
        cached_headers["X-SecretShield-Cache"] = "HIT"
        return entry.status_code, cached_headers, entry.content

    def set(
        self,
        cache_key: str,
        status_code: int,
        headers: Dict[str, str],
        content: bytes,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store response in cache."""
        # Only cache successful 2xx responses
        if status_code < 200 or status_code >= 300:
            return

        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl
        entry = CacheEntry(
            status_code=status_code,
            headers=headers,
            content=content,
            created_at=time.monotonic(),
            ttl_seconds=ttl,
        )

        if cache_key in self._cache:
            self._cache.move_to_end(cache_key)
        self._cache[cache_key] = entry

        # Evict oldest if exceeding capacity
        if len(self._cache) > self.max_entries:
            self._cache.popitem(last=False)

    def clear(self) -> int:
        """Clear all cached entries. Returns number of purged items."""
        count = len(self._cache)
        self._cache.clear()
        return count

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics and hit ratio."""
        total = self.hits + self.misses
        hit_ratio = (self.hits / total * 100.0) if total > 0 else 0.0
        return {
            "total_entries": len(self._cache),
            "max_entries": self.max_entries,
            "hits": self.hits,
            "misses": self.misses,
            "hit_ratio_percent": round(hit_ratio, 2),
        }
