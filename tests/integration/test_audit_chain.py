"""Integration tests for hash-chained audit ledger and tamper detection."""

from pathlib import Path
import aiosqlite
import pytest
from secretshield.audit.logger import AuditLogger
from secretshield.audit.verifier import AuditChainVerifier


@pytest.fixture
def audit_db(tmp_path: Path) -> Path:
    return tmp_path / "test_audit.db"


@pytest.mark.asyncio
async def test_audit_chain_creation_and_verification(audit_db: Path):
    """Verify multiple log entries form a valid cryptographic chain."""
    logger = AuditLogger(audit_db)

    # Log 3 requests
    e1 = await logger.log_request(
        service_id="checkout",
        profile_name="stripe",
        method="POST",
        path="/v1/charges",
        status_code=200,
        latency_ms=145.2,
        cost_usd=0.30,
        metadata={"customer": "cus_123"},
    )
    assert e1.id == 1
    assert e1.prev_hash == "0" * 64

    e2 = await logger.log_request(
        service_id="ai-assistant",
        profile_name="openai",
        method="POST",
        path="/v1/chat/completions",
        status_code=200,
        latency_ms=850.0,
        cost_usd=0.005,
    )
    assert e2.id == 2
    assert e2.prev_hash == e1.record_hash

    e3 = await logger.log_request(
        service_id="checkout",
        profile_name="stripe",
        method="POST",
        path="/v1/refunds",
        status_code=400,
        latency_ms=62.1,
        cost_usd=0.0,
    )
    assert e3.id == 3
    assert e3.prev_hash == e2.record_hash

    # Verify chain passes
    is_valid, err, count = await AuditChainVerifier.verify_chain(audit_db)
    assert is_valid is True
    assert err is None
    assert count == 3


@pytest.mark.asyncio
async def test_audit_chain_detects_record_tampering(audit_db: Path):
    """Verify unauthorized database modification breaks the chain and is detected."""
    logger = AuditLogger(audit_db)

    await logger.log_request(
        service_id="service-a",
        profile_name="stripe",
        method="POST",
        path="/v1/charges",
        status_code=200,
        latency_ms=100.0,
        cost_usd=0.30,
    )
    await logger.log_request(
        service_id="service-b",
        profile_name="openai",
        method="POST",
        path="/v1/completions",
        status_code=200,
        latency_ms=200.0,
        cost_usd=0.01,
    )

    # Attacker tampers directly with record #1 (e.g. changing status_code to hide error or cost)
    async with aiosqlite.connect(audit_db) as db:
        await db.execute("UPDATE audit_ledger SET cost_usd = 999.99 WHERE id = 1")
        await db.commit()

    # Verifier must detect tampering
    is_valid, err, verified_count = await AuditChainVerifier.verify_chain(audit_db)
    assert is_valid is False
    assert "Tamper detected at record #1" in err
    assert verified_count == 0
