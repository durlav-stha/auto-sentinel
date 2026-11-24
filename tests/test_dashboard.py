"""Tests for the live Web SOC Dashboard (EventHub, aiohttp API, security headers, e2e)."""

from aiohttp.test_utils import TestClient, TestServer

from auto_sentinel.dashboard.hub import EventHub, HISTORY_LIMIT, SUBSCRIBER_QUEUE_MAXSIZE
from auto_sentinel.dashboard.server import create_app
from auto_sentinel.main import AutoSentinelEngine
from auto_sentinel.models import (
    ActionType,
    Alert,
    EventType,
    MitreTactic,
    RemediationResult,
    SecurityEvent,
    Severity,
)


def _build_event(idx: int = 1) -> SecurityEvent:
    return SecurityEvent(
        event_type=EventType.AUTH_FAILURE,
        source="auth.log",
        source_ip="203.0.113.10",
        user=f"user{idx}",
        raw_message=f"Failed password for user{idx} from 203.0.113.10 port 22 ssh2",
    )


async def test_event_hub_counters_bounds_and_drop_policy():
    hub = EventHub()
    sub = hub.subscribe()

    # Fill subscriber queue to capacity, then exceed it — must drop silently without raising.
    for i in range(SUBSCRIBER_QUEUE_MAXSIZE + 25):
        hub.record_event(_build_event(i))

    assert hub.events_total == SUBSCRIBER_QUEUE_MAXSIZE + 25
    assert sub.qsize() == SUBSCRIBER_QUEUE_MAXSIZE

    alert = Alert(
        rule_name="SSH Brute Force Attack",
        severity=Severity.HIGH,
        mitre_tactic=MitreTactic.CREDENTIAL_ACCESS,
        mitre_technique_id="T1110",
        description="Test alert",
        target_ip="203.0.113.10",
    )
    hub.record_alert(alert)
    assert hub.alerts_total == 1

    hub.record_remediation(
        RemediationResult(
            action_type=ActionType.BLOCK_IP,
            target="203.0.113.10",
            success=True,
            details="dry-run",
        )
    )
    hub.record_remediation(
        RemediationResult(
            action_type=ActionType.KILL_PROCESS,
            target="4444",
            success=True,
            details="dry-run",
        )
    )
    hub.record_remediation(
        RemediationResult(
            action_type=ActionType.KILL_PROCESS,
            target="4445",
            success=False,
            details="no such process",
        )
    )
    assert hub.ips_blocked == 1
    assert hub.procs_terminated == 1
    assert hub.remediation_failed == 1

    snap = hub.snapshot(queue_depth=0, queue_capacity=1000, ledger_intact=True, ledger_count=0)
    assert len(snap["events"]) == HISTORY_LIMIT


async def test_api_state_and_security_headers(tmp_path):
    hub = EventHub()
    engine = AutoSentinelEngine(
        log_file=tmp_path / "auth.log",
        ledger_file=tmp_path / "audit.jsonl",
        dry_run=True,
        hub=hub,
    )
    app = create_app(engine, hub, host="127.0.0.1", port=8765)

    async with TestClient(TestServer(app)) as client:
        index_resp = await client.get("/")
        assert index_resp.status == 200
        assert "Content-Security-Policy" in index_resp.headers
        assert index_resp.headers.get("X-Content-Type-Options") == "nosniff"
        assert index_resp.headers.get("X-Frame-Options") == "DENY"

        state_resp = await client.get("/api/state")
        assert state_resp.status == 200
        body = await state_resp.json()
        assert set(body.keys()) >= {"stats", "events", "alerts", "remediations", "ledger"}
        assert set(body["stats"].keys()) >= {
            "events_total",
            "alerts_total",
            "ips_blocked",
            "procs_terminated",
            "queue_depth",
            "queue_capacity",
            "ledger_intact",
            "ledger_count",
            "eps_series",
        }


async def test_simulate_bruteforce_csrf_and_end_to_end(tmp_path):
    log_file = tmp_path / "auth.log"
    ledger_file = tmp_path / "audit.jsonl"
    hub = EventHub()
    engine = AutoSentinelEngine(
        log_file=log_file,
        ledger_file=ledger_file,
        dry_run=True,
        hub=hub,
    )
    app = create_app(engine, hub, host="127.0.0.1", port=8765)

    async with TestClient(TestServer(app)) as client:
        # Cross-origin POST must be rejected with 403
        bad_resp = await client.post(
            "/api/simulate/bruteforce",
            headers={"Origin": "http://evil.example"},
        )
        assert bad_resp.status == 403

        # Valid POST appends 5 failed-login lines to the log file
        ok_resp = await client.post("/api/simulate/bruteforce")
        assert ok_resp.status == 200
        lines = log_file.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 5

    # Run tailer + engine drain to verify full pipeline into EventHub
    polled = await engine.log_tailer.poll_once()
    assert polled == 5
    await engine.shutdown()

    assert hub.events_total == 5
    assert hub.alerts_total == 1
    assert hub.ips_blocked == 1
