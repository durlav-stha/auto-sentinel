"""Unit tests for detector/ (SignatureMatcher, SlidingWindowCorrelator, DetectionEngine)."""

from datetime import datetime, timedelta, timezone
from auto_sentinel.models import SecurityEvent, EventType, Severity
from auto_sentinel.detector.signatures import SignatureMatcher
from auto_sentinel.detector.correlator import SlidingWindowCorrelator


def test_signature_matcher_detects_process_spawn():
    ev = SecurityEvent(
        event_type=EventType.PROCESS_SPAWNED,
        source="process_monitor",
        process_name="bash",
        process_pid=4444,
        raw_message="Parent=nginx spawned Child=bash",
    )
    alert = SignatureMatcher.match(ev)
    assert alert is not None
    assert alert.severity == Severity.CRITICAL
    assert alert.mitre_technique_id == "T1059"
    assert alert.target_pid == 4444


def test_correlator_sliding_window_brute_force():
    correlator = SlidingWindowCorrelator(threshold=5, window_seconds=60.0)
    base_time = datetime(2026, 11, 12, 3, 0, 0, tzinfo=timezone.utc)

    # First 4 failures within 20 seconds -> no alert yet
    for i in range(4):
        ev = SecurityEvent(
            timestamp=base_time + timedelta(seconds=i * 5),
            event_type=EventType.AUTH_FAILURE,
            source="auth.log",
            source_ip="203.0.113.5",
            user="root",
        )
        assert correlator.evaluate_brute_force(ev) is None

    # 5th failure at t=25s -> triggers T1110 Brute Force Alert!
    fifth = SecurityEvent(
        timestamp=base_time + timedelta(seconds=25),
        event_type=EventType.AUTH_FAILURE,
        source="auth.log",
        source_ip="203.0.113.5",
        user="root",
    )
    alert = correlator.evaluate_brute_force(fifth)
    assert alert is not None
    assert alert.mitre_technique_id == "T1110"
    assert alert.target_ip == "203.0.113.5"
    assert len(alert.triggering_events) == 5


def test_correlator_evicts_expired_events():
    correlator = SlidingWindowCorrelator(threshold=3, window_seconds=30.0)
    base_time = datetime(2026, 11, 12, 3, 0, 0, tzinfo=timezone.utc)

    # 2 events at t=0 and t=5
    for i in range(2):
        correlator.evaluate_brute_force(
            SecurityEvent(
                timestamp=base_time + timedelta(seconds=i * 5),
                event_type=EventType.AUTH_FAILURE,
                source="auth.log",
                source_ip="198.51.100.7",
            )
        )

    # Next event arrives at t=45s (outside the 30s window, so previous 2 should be evicted)
    late_event = SecurityEvent(
        timestamp=base_time + timedelta(seconds=45),
        event_type=EventType.AUTH_FAILURE,
        source="auth.log",
        source_ip="198.51.100.7",
    )
    assert correlator.evaluate_brute_force(late_event) is None
