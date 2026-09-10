"""Cryptographically hash-chained immutable audit logger using SQLite."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import aiosqlite

from secretshield.audit.schema import AuditEntry
from secretshield.proxy.redactor import SecretRedactor

GENESIS_HASH = "0" * 64


def calculate_record_hash(
    prev_hash: str,
    timestamp: str,
    service_id: str,
    profile_name: str,
    method: str,
    path: str,
    status_code: int,
    cost_usd: float,
) -> str:
    """Compute deterministic SHA-256 block hash for an audit record."""
    canonical_str = (
        f"{prev_hash}|{timestamp}|{service_id}|{profile_name}|"
        f"{method.upper()}|{path}|{status_code}|{cost_usd:.6f}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class AuditLogger:
    """Non-blocking async audit logger with SHA-256 hash chaining."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._last_hash: str | None = None

    async def init_db(self) -> None:
        """Initialize audit table and recover last block hash."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_ledger (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    service_id TEXT NOT NULL,
                    profile_name TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    latency_ms REAL NOT NULL,
                    cost_usd REAL NOT NULL,
                    client_ip TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}',
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            # Create index for fast time-range querying
            await db.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger (timestamp)"
            )
            await db.commit()

            # Retrieve most recent record hash
            async with db.execute(
                "SELECT record_hash FROM audit_ledger ORDER BY id DESC LIMIT 1"
            ) as cursor:
                row = await cursor.fetchone()
                self._last_hash = row[0] if row else GENESIS_HASH

    async def log_request(
        self,
        service_id: str,
        profile_name: str,
        method: str,
        path: str,
        status_code: int,
        latency_ms: float,
        cost_usd: float,
        client_ip: str = "127.0.0.1",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Append a sanitized, hash-chained record to the audit ledger."""
        await self.init_db()

        # Sanitize metadata
        clean_metadata = SecretRedactor.redact_json(metadata or {})
        now = datetime.now(UTC).isoformat()
        prev_hash = self._last_hash or GENESIS_HASH

        record_hash = calculate_record_hash(
            prev_hash=prev_hash,
            timestamp=now,
            service_id=service_id,
            profile_name=profile_name,
            method=method,
            path=path,
            status_code=status_code,
            cost_usd=cost_usd,
        )

        meta_json = json.dumps(clean_metadata)

        async with aiosqlite.connect(self.db_path) as db:
            cursor = await db.execute(
                """
                INSERT INTO audit_ledger (
                    timestamp, service_id, profile_name, method, path,
                    status_code, latency_ms, cost_usd, client_ip,
                    metadata, prev_hash, record_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    service_id,
                    profile_name,
                    method.upper(),
                    path,
                    status_code,
                    latency_ms,
                    cost_usd,
                    client_ip,
                    meta_json,
                    prev_hash,
                    record_hash,
                ),
            )
            record_id = cursor.lastrowid
            await db.commit()

        self._last_hash = record_hash

        return AuditEntry(
            id=record_id,
            timestamp=now,
            service_id=service_id,
            profile_name=profile_name,
            method=method.upper(),
            path=path,
            status_code=status_code,
            latency_ms=latency_ms,
            cost_usd=cost_usd,
            client_ip=client_ip,
            metadata=clean_metadata,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

    async def get_recent_entries(self, limit: int = 50) -> list[AuditEntry]:
        """Fetch the most recent audit records."""
        await self.init_db()
        records: list[AuditEntry] = []
        async with (
            aiosqlite.connect(self.db_path) as db,
            db.execute(
                """
                SELECT id, timestamp, service_id, profile_name, method, path,
                       status_code, latency_ms, cost_usd, client_ip, metadata,
                       prev_hash, record_hash
                FROM audit_ledger ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ) as cursor,
        ):
            rows = await cursor.fetchall()
            for row in rows:
                records.append(
                    AuditEntry(
                        id=row[0],
                        timestamp=row[1],
                        service_id=row[2],
                        profile_name=row[3],
                        method=row[4],
                        path=row[5],
                        status_code=row[6],
                        latency_ms=row[7],
                        cost_usd=row[8],
                        client_ip=row[9],
                        metadata=json.loads(row[10]),
                        prev_hash=row[11],
                        record_hash=row[12],
                    )
                )
        return records
