"""Stateless Signature Matcher (Stage 2: The Brain - Instant Rules).

Evaluates single events for immediate high-confidence indicators of compromise.
"""

from typing import Optional
from auto_sentinel.models import SecurityEvent, EventType, Alert, Severity, MitreTactic


class SignatureMatcher:
    """Evaluates single telemetry events against static threat rules."""

    @staticmethod
    def match(event: SecurityEvent) -> Optional[Alert]:
        """Return an Alert if a single event matches a high-severity signature."""
        if event.event_type == EventType.PROCESS_SPAWNED:
            return Alert(
                rule_name="Suspicious Shell / Command Execution",
                severity=Severity.CRITICAL,
                mitre_tactic=MitreTactic.EXECUTION,
                mitre_technique_id="T1059",
                description=(
                    f"Anomalous process execution detected: {event.process_name} "
                    f"(PID {event.process_pid}) — {event.raw_message}"
                ),
                target_pid=event.process_pid,
                target_process_name=event.process_name,
                triggering_events=[event],
            )
        return None
