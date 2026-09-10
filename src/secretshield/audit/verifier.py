"""Verification utility for audit ledger cryptographic hash chain."""

from pathlib import Path

import aiosqlite

from secretshield.audit.logger import GENESIS_HASH, calculate_record_hash


class AuditChainVerifier:
    """Validates the linear cryptographic chain of SQLite audit records."""

    @staticmethod
    async def verify_chain(db_path: Path) -> tuple[bool, str | None, int]:
        """Verify the integrity of the entire audit database.

        Returns:
            Tuple of (is_valid: bool, error_message: Optional[str], total_records_verified: int).
        """
        if not db_path.exists():
            return True, "Database file does not exist yet (empty ledger)", 0

        async with aiosqlite.connect(db_path) as db:
            # Check if audit_ledger table exists
            async with db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_ledger'"
            ) as cursor:
                if not await cursor.fetchone():
                    return True, "No audit_ledger table found (empty)", 0

            async with db.execute(
                """
                SELECT id, timestamp, service_id, profile_name, method, path,
                       status_code, cost_usd, prev_hash, record_hash
                FROM audit_ledger ORDER BY id ASC
                """
            ) as cursor:
                rows = await cursor.fetchall()

            if not rows:
                return True, "Ledger is empty", 0

            expected_prev_hash = GENESIS_HASH
            for idx, row in enumerate(rows):
                rec_id = row[0]
                timestamp = row[1]
                service_id = row[2]
                profile_name = row[3]
                method = row[4]
                path = row[5]
                status_code = row[6]
                cost_usd = row[7]
                stored_prev_hash = row[8]
                stored_record_hash = row[9]

                # 1. Verify prev_hash matches previous record
                if stored_prev_hash != expected_prev_hash:
                    return (
                        False,
                        f"Hash chain broken at record #{rec_id}: expected prev_hash '{expected_prev_hash}', "
                        f"found '{stored_prev_hash}'",
                        idx,
                    )

                # 2. Recalculate block hash
                computed_hash = calculate_record_hash(
                    prev_hash=stored_prev_hash,
                    timestamp=timestamp,
                    service_id=service_id,
                    profile_name=profile_name,
                    method=method,
                    path=path,
                    status_code=status_code,
                    cost_usd=cost_usd,
                )

                if computed_hash != stored_record_hash:
                    return (
                        False,
                        f"Tamper detected at record #{rec_id}: payload recomputed hash '{computed_hash}' "
                        f"does not match stored hash '{stored_record_hash}'",
                        idx,
                    )

                expected_prev_hash = stored_record_hash

            return True, None, len(rows)
