"""Unit tests for ledger/tamper_evident.py (Core Task #5)."""

import json
from auto_sentinel.ledger.tamper_evident import TamperEvidentLedger, GENESIS_HASH


def test_ledger_hash_chain_and_tamper_detection(tmp_path):
    ledger_file = tmp_path / "audit.jsonl"
    ledger = TamperEvidentLedger(ledger_file)

    r1 = ledger.append_record("BLOCK_IP", {"ip": "203.0.113.42", "reason": "SSH Brute Force"})
    r2 = ledger.append_record("KILL_PROCESS", {"pid": 4444, "process": "bash"})

    assert r1.prev_hash == GENESIS_HASH
    assert r2.prev_hash == r1.current_hash
    assert len(r1.current_hash) == 64

    intact, count = ledger.verify_integrity()
    assert intact is True
    assert count == 2

    # Simulate an attacker tampering with record #1 on disk
    lines = ledger_file.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["payload"]["ip"] = "192.168.1.1"  # Attacker tries to hide their IP
    lines[0] = json.dumps(tampered)
    ledger_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    intact_after, corrupted_id = ledger.verify_integrity()
    assert intact_after is False
    assert corrupted_id == 1
