"""Audit record schema definitions."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class AuditEntry(BaseModel):
    """Immutable audit record representing a proxied request."""
    id: int
    timestamp: str
    service_id: str
    profile_name: str
    method: str
    path: str
    status_code: int
    latency_ms: float
    cost_usd: float
    client_ip: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    record_hash: str
