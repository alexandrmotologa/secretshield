"""Unit tests for ResponseCache."""

import time

import pytest

from secretshield.proxy.cache import ResponseCache


@pytest.fixture
def cache() -> ResponseCache:
    return ResponseCache(max_entries=3, default_ttl_seconds=10)


def test_cache_miss_then_hit(cache: ResponseCache):
    """Verify cache miss followed by store and cache hit."""
    key = cache.generate_cache_key(
        profile_name="openai",
        method="POST",
        path="v1/chat/completions",
        content=b'{"model": "gpt-4o", "temperature": 0}',
    )

    # Initial get is a miss
    assert cache.get(key) is None
    assert cache.misses == 1

    # Store entry
    cache.set(
        cache_key=key,
        status_code=200,
        headers={"Content-Type": "application/json"},
        content=b'{"result": "Hello world"}',
    )

    # Subsequent get is a hit
    result = cache.get(key)
    assert result is not None
    status, headers, body = result
    assert status == 200
    assert headers["X-SecretShield-Cache"] == "HIT"
    assert body == b'{"result": "Hello world"}'
    assert cache.hits == 1


def test_cache_ttl_expiration(cache: ResponseCache):
    """Verify entry expires after TTL."""
    key = "short-ttl-key"
    cache.set(
        cache_key=key,
        status_code=200,
        headers={},
        content=b"temporary",
        ttl_seconds=0,  # Expired immediately
    )

    time.sleep(0.01)
    assert cache.get(key) is None


def test_cache_lru_eviction(cache: ResponseCache):
    """Verify oldest item is evicted when capacity is exceeded."""
    cache.set("k1", 200, {}, b"c1")
    cache.set("k2", 200, {}, b"c2")
    cache.set("k3", 200, {}, b"c3")

    # k1, k2, k3 stored (capacity = 3)
    assert cache.get("k1") is not None  # accessing k1 moves it to MRU

    # adding k4 should evict k2 (oldest LRU item)
    cache.set("k4", 200, {}, b"c4")

    assert cache.get("k2") is None  # evicted
    assert cache.get("k1") is not None
    assert cache.get("k4") is not None


def test_cache_body_json_key_order_normalized(cache: ResponseCache):
    """Verify different JSON key orders produce identical cache key."""
    b1 = b'{"a": 1, "b": 2}'
    b2 = b'{"b": 2, "a": 1}'

    k1 = cache.generate_cache_key("test", "POST", "/calc", content=b1)
    k2 = cache.generate_cache_key("test", "POST", "/calc", content=b2)

    assert k1 == k2


def test_cache_clear_and_stats(cache: ResponseCache):
    """Verify clearing cache and retrieving stats."""
    cache.set("k1", 200, {}, b"data")
    assert cache.get("k1") is not None
    assert cache.get("missing") is None

    stats = cache.get_stats()
    assert stats["total_entries"] == 1
    assert stats["hits"] == 1
    assert stats["misses"] == 1
    assert stats["hit_ratio_percent"] == 50.0

    purged = cache.clear()
    assert purged == 1
    assert cache.get_stats()["total_entries"] == 0
