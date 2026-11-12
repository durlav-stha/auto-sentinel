"""Tamper-Evident Cryptographic Audit Ledger (Stage 4: The Black Box).

Persists an append-only JSONL audit trail where each entry is cryptographically
chained to the previous entry via SHA-256 (`hash_n = SHA256(record_n || hash_{n-1})`),
making post-compromise log modification immediately detectable.
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Tuple
from auto_sentinel.models import AuditRecord

GENESIS_HASH = "0" * 64


class TamperEvidentLedger:
    """Append-only JSONL ledger secured by a SHA-256 hash chain."""

    def __init__(self, ledger_path: str | Path):
        self.ledger_path = Path(ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        self._last_hash: str = GENESIS_HASH
        self._next_id: int = 1
        self._load_existing_state()

    def _load_existing_state(self) -> None:
        """Recover the last hash and record ID if the ledger file already exists."""
        if not self.ledger_path.exists():
            return
        with open(self.ledger_path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                self._last_hash = data["current_hash"]
                self._next_id = data["record_id"] + 1

    @staticmethod
    def compute_record_hash(
        record_id: int,
        timestamp_iso: str,
        event_type: str,
        payload: Dict[str, Any],
        prev_hash: str,
    ) -> str:
        """Compute deterministic SHA-256 hash chaining this record to `prev_hash`."""
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        canonical = f"{record_id}|{timestamp_iso}|{event_type}|{payload_str}|{prev_hash}"
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_record(self, event_type: str, payload: Dict[str, Any]) -> AuditRecord:
        """Create, hash-link, and persist a new AuditRecord to the ledger."""
        now = datetime.now(timezone.utc)
        ts_iso = now.isoformat()
        current_hash = self.compute_record_hash(
            record_id=self._next_id,
            timestamp_iso=ts_iso,
            event_type=event_type,
            payload=payload,
            prev_hash=self._last_hash,
        )

        record = AuditRecord(
            record_id=self._next_id,
            timestamp=now,
            event_type=event_type,
            payload=payload,
            prev_hash=self._last_hash,
            current_hash=current_hash,
        )

        with open(self.ledger_path, "a", encoding="utf-8") as fp:
            fp.write(record.model_dump_json() + "\n")

        self._last_hash = current_hash
        self._next_id += 1
        return record

    def verify_integrity(self) -> Tuple[bool, int]:
        """Verify the entire cryptographic hash chain from the Genesis block.

        Returns:
            (True, total_records) if intact, or (False, corrupted_record_id) if tampered.
        """
        if not self.ledger_path.exists():
            return (True, 0)

        expected_prev_hash = GENESIS_HASH
        count = 0

        with open(self.ledger_path, "r", encoding="utf-8") as fp:
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                data = json.loads(line)
                rec_id = data["record_id"]
                ts_iso = datetime.fromisoformat(data["timestamp"]).isoformat()
                ev_type = data["event_type"]
                payload = data["payload"]
                prev_hash = data["prev_hash"]
                stored_hash = data["current_hash"]

                if prev_hash != expected_prev_hash:
                    return (False, rec_id)

                recomputed = self.compute_record_hash(rec_id, ts_iso, ev_type, payload, prev_hash)
                if recomputed != stored_hash:
                    return (False, rec_id)

                expected_prev_hash = stored_hash
                count += 1

        return (True, count)
