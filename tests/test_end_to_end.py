"""End-to-End Integration Test for AutoSentinelEngine across all 4 stages."""

import pytest
from auto_sentinel.main import AutoSentinelEngine


@pytest.mark.asyncio
async def test_end_to_end_ssh_brute_force_pipeline(tmp_path):
    """Verify full pipeline: LogTailer -> EventQueue -> DetectionEngine -> Remediation -> Ledger."""
    log_file = tmp_path / "auth.log"
    ledger_file = tmp_path / "audit.jsonl"

    # Write 5 failed SSH login attempts from attacker IP 198.51.100.44
    lines = [
        f"Nov 12 03:00:0{i} srv sshd[900]: Failed password for invalid user root from 198.51.100.44 port 22 ssh2\n"
        for i in range(1, 6)
    ]
    log_file.write_text("".join(lines), encoding="utf-8")

    engine = AutoSentinelEngine(log_file=log_file, ledger_file=ledger_file, dry_run=True)

    # Stage 1: Poll the log file into the bounded queue
    emitted = await engine.log_tailer.poll_once()
    assert emitted == 5
    assert engine.queue.qsize() == 5

    # Stage 2, 3, 4: Drain and process through Detector -> Remediation -> Ledger
    await engine.shutdown()

    # Verify Alert was generated (Stage 2)
    assert len(engine.detector.alerts_generated) == 1
    alert = engine.detector.alerts_generated[0]
    assert alert.mitre_technique_id == "T1110"
    assert alert.target_ip == "198.51.100.44"

    # Verify Firewall Block was executed (Stage 3)
    assert len(engine.remediation.history) == 1
    assert engine.remediation.history[0].target == "198.51.100.44"
    assert engine.remediation.history[0].success is True

    # Verify Cryptographic Audit Ledger is intact (Stage 4)
    intact, record_count = engine.ledger.verify_integrity()
    assert intact is True
    assert record_count == 1
