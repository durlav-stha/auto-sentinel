"""Remediation Dispatcher (Stage 3: The Hands).

Coordinates active response actions for incoming Alerts and records outcomes.
"""

from typing import List, Optional
from auto_sentinel.models import Alert, RemediationResult
from auto_sentinel.remediation.network_blocker import NetworkBlocker
from auto_sentinel.remediation.process_killer import ProcessKiller
from auto_sentinel.ledger.tamper_evident import TamperEvidentLedger


class RemediationRunner:
    """Dispatches defensive actions based on Alert attributes."""

    def __init__(
        self,
        network_blocker: Optional[NetworkBlocker] = None,
        process_killer: Optional[ProcessKiller] = None,
        ledger: Optional[TamperEvidentLedger] = None,
    ):
        self.network_blocker = network_blocker or NetworkBlocker(dry_run=True)
        self.process_killer = process_killer or ProcessKiller(dry_run=True)
        self.ledger = ledger
        self.history: List[RemediationResult] = []

    async def handle_alert(self, alert: Alert) -> List[RemediationResult]:
        """Execute appropriate containment playbooks for a given Alert."""
        results: List[RemediationResult] = []

        if alert.target_ip:
            res = self.network_blocker.block_ip(alert.target_ip)
            results.append(res)
            self.history.append(res)

        if alert.target_pid is not None and alert.target_process_name:
            res = self.process_killer.kill_process(alert.target_pid, alert.target_process_name)
            results.append(res)
            self.history.append(res)

        if self.ledger is not None:
            self.ledger.append_record(
                event_type="ALERT_AND_REMEDIATION",
                payload={
                    "alert_id": alert.alert_id,
                    "rule_name": alert.rule_name,
                    "severity": alert.severity.value,
                    "mitre_technique": alert.mitre_technique_id,
                    "remediation_results": [r.model_dump(mode="json") for r in results],
                },
            )

        return results
