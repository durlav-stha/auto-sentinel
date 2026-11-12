"""Stateful Sliding-Window Correlator (Stage 2: The Brain - Memory Rules).

Tracks events over time per IP address using bounded `collections.deque` structures
to detect high-frequency attacks such as SSH brute force (MITRE T1110).
"""

from collections import defaultdict, deque
from typing import Deque, Dict, Optional
from auto_sentinel.models import SecurityEvent, EventType, Alert, Severity, MitreTactic


class SlidingWindowCorrelator:
    """Detects multi-step or high-frequency attacks within a time window."""

    def __init__(self, threshold: int = 5, window_seconds: float = 60.0):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # Maps source_ip -> deque of failed SecurityEvent objects ordered by time
        self._failures_by_ip: Dict[str, Deque[SecurityEvent]] = defaultdict(deque)

    def evaluate_brute_force(self, event: SecurityEvent) -> Optional[Alert]:
        """Track AUTH_FAILURE events in a sliding time window and emit an Alert on threshold."""
        if event.event_type != EventType.AUTH_FAILURE or not event.source_ip:
            return None

        window = self._failures_by_ip[event.source_ip]
        window.append(event)

        # 1. Evict expired events outside the sliding window
        now_ts = event.timestamp.timestamp()
        while window and (now_ts - window[0].timestamp.timestamp()) > self.window_seconds:
            window.popleft()

        # 2. Check if active failures in the current window breach the threshold
        if len(window) >= self.threshold:
            triggered = list(window)
            window.clear()  # Reset window so the same burst doesn't fire duplicate alerts
            return Alert(
                rule_name="SSH Brute Force Attack",
                severity=Severity.HIGH,
                mitre_tactic=MitreTactic.CREDENTIAL_ACCESS,
                mitre_technique_id="T1110",
                description=f"Detected {len(triggered)} failed logins from {event.source_ip} within {self.window_seconds}s",
                target_ip=event.source_ip,
                triggering_events=triggered,
            )

        return None
