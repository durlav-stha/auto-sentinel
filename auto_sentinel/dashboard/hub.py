"""In-memory pub/sub telemetry hub for the live SOC dashboard.

Maintains bounded rolling history buffers (max 200 items each), atomic counters,
a 60-second events-per-second series, and non-blocking bounded subscriber queues
so slow or disconnected clients can never stall the detection pipeline or leak RAM.
"""

import asyncio
import time
from collections import deque
from typing import Any, Callable, Deque, Dict, Set
from auto_sentinel.models import ActionType, Alert, AuditRecord, RemediationResult, SecurityEvent

HISTORY_LIMIT = 200
SUBSCRIBER_QUEUE_MAXSIZE = 256
EPS_WINDOW_SECONDS = 60


class EventHub:
    """Thread-safe asyncio pub/sub hub for dashboard state and SSE streaming."""

    def __init__(self) -> None:
        self.events_total: int = 0
        self.alerts_total: int = 0
        self.ips_blocked: int = 0
        self.procs_terminated: int = 0
        self.remediation_failed: int = 0
        self.started_at: float = time.monotonic()

        self._events: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        self._remediations: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)
        self._ledger_records: Deque[Dict[str, Any]] = deque(maxlen=HISTORY_LIMIT)

        self._eps_series: Deque[int] = deque([0] * EPS_WINDOW_SECONDS, maxlen=EPS_WINDOW_SECONDS)
        self._current_sec_events: int = 0

        self._subscribers: Set[asyncio.Queue[Dict[str, Any]]] = set()

    def subscribe(self) -> asyncio.Queue[Dict[str, Any]]:
        """Register a new SSE subscriber with a bounded queue."""
        queue: asyncio.Queue[Dict[str, Any]] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_MAXSIZE)
        self._subscribers.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[Dict[str, Any]]) -> None:
        """Remove an SSE subscriber queue."""
        self._subscribers.discard(queue)

    def publish(self, msg_type: str, data: Any) -> None:
        """Broadcast a message to all active subscribers without blocking."""
        message = {"type": msg_type, "data": data}
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop message for slow clients instead of blocking the SOAR engine.
                continue

    def record_event(self, event: SecurityEvent) -> None:
        """Record an ingested SecurityEvent and broadcast it."""
        self.events_total += 1
        self._current_sec_events += 1
        payload = event.model_dump(mode="json")
        self._events.append(payload)
        self.publish("event", payload)

    def record_alert(self, alert: Alert) -> None:
        """Record a raised Alert and broadcast it."""
        self.alerts_total += 1
        payload = alert.model_dump(mode="json")
        self._alerts.append(payload)
        self.publish("alert", payload)

    def record_remediation(self, result: RemediationResult) -> None:
        """Record a RemediationResult, update outcome counters, and broadcast."""
        if result.success and result.action_type == ActionType.BLOCK_IP:
            self.ips_blocked += 1
        elif result.success and result.action_type == ActionType.KILL_PROCESS:
            self.procs_terminated += 1
        else:
            self.remediation_failed += 1

        payload = result.model_dump(mode="json")
        self._remediations.append(payload)
        self.publish("remediation", payload)

    def record_ledger(self, record: AuditRecord) -> None:
        """Record a newly appended AuditRecord and broadcast it."""
        payload = record.model_dump(mode="json")
        self._ledger_records.append(payload)
        self.publish("ledger", payload)

    def uptime_seconds(self) -> int:
        """Return engine uptime in whole seconds."""
        return max(0, int(time.monotonic() - self.started_at))

    def _build_stats(
        self,
        queue_depth: int,
        queue_capacity: int,
        ledger_intact: bool | None = None,
        ledger_count: int | None = None,
    ) -> Dict[str, Any]:
        stats: Dict[str, Any] = {
            "events_total": self.events_total,
            "alerts_total": self.alerts_total,
            "ips_blocked": self.ips_blocked,
            "procs_terminated": self.procs_terminated,
            "remediation_failed": self.remediation_failed,
            "uptime_seconds": self.uptime_seconds(),
            "queue_depth": queue_depth,
            "queue_capacity": queue_capacity,
            "eps_series": list(self._eps_series),
        }
        if ledger_intact is not None:
            stats["ledger_intact"] = ledger_intact
        if ledger_count is not None:
            stats["ledger_count"] = ledger_count
        return stats

    def snapshot(
        self,
        queue_depth: int,
        queue_capacity: int,
        ledger_intact: bool,
        ledger_count: int,
    ) -> Dict[str, Any]:
        """Return full dashboard hydration state with history newest-first."""
        return {
            "stats": self._build_stats(
                queue_depth=queue_depth,
                queue_capacity=queue_capacity,
                ledger_intact=ledger_intact,
                ledger_count=ledger_count,
            ),
            "events": list(reversed(self._events)),
            "alerts": list(reversed(self._alerts)),
            "remediations": list(reversed(self._remediations)),
            "ledger": list(reversed(self._ledger_records)),
        }

    async def run_ticker(
        self,
        get_queue_depth: Callable[[], int],
        queue_capacity: int = 1000,
    ) -> None:
        """Roll the 1-second EPS bucket and publish stats snapshots until cancelled."""
        try:
            while True:
                await asyncio.sleep(1.0)
                bucket = self._current_sec_events
                self._current_sec_events = 0
                self._eps_series.append(bucket)
                self.publish(
                    "stats",
                    self._build_stats(
                        queue_depth=get_queue_depth(),
                        queue_capacity=queue_capacity,
                    ),
                )
        except asyncio.CancelledError:
            return
