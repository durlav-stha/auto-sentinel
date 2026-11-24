"""Detection Engine Coordinator (Stage 2: The Brain).

Pulls SecurityEvents from the EventQueue, evaluates them against both stateless
signatures and stateful sliding-window correlation, and forwards generated Alerts.
"""

import asyncio
from typing import Awaitable, Callable, List, Optional
from auto_sentinel.models import SecurityEvent, Alert
from auto_sentinel.bus.queue import EventQueue
from auto_sentinel.detector.signatures import SignatureMatcher
from auto_sentinel.detector.correlator import SlidingWindowCorrelator

AlertCallback = Callable[[Alert], Awaitable[None]]
EventCallback = Callable[[SecurityEvent], Awaitable[None]]


class DetectionEngine:
    """Central worker that coordinates signature matching and event correlation."""

    def __init__(
        self,
        queue: EventQueue,
        correlator: Optional[SlidingWindowCorrelator] = None,
        on_alert: Optional[AlertCallback] = None,
        on_event: Optional[EventCallback] = None,
    ):
        self.queue = queue
        self.correlator = correlator or SlidingWindowCorrelator()
        self.on_alert = on_alert
        self.on_event = on_event
        self.alerts_generated: List[Alert] = []
        self._stop_event = asyncio.Event()

    async def process_event(self, event: SecurityEvent) -> List[Alert]:
        """Run a single SecurityEvent through all detection layers."""
        if self.on_event is not None:
            await self.on_event(event)

        triggered_alerts: List[Alert] = []

        # 1. Stateless Instant Signatures
        sig_alert = SignatureMatcher.match(event)
        if sig_alert is not None:
            triggered_alerts.append(sig_alert)

        # 2. Stateful Sliding-Window Correlation
        corr_alert = self.correlator.evaluate_brute_force(event)
        if corr_alert is not None:
            triggered_alerts.append(corr_alert)

        # Record and dispatch alerts
        for alert in triggered_alerts:
            self.alerts_generated.append(alert)
            if self.on_alert is not None:
                await self.on_alert(alert)

        return triggered_alerts

    async def run(self) -> None:
        """Continuously consume events from the queue until stopped."""
        while not self._stop_event.is_set():
            try:
                event = await asyncio.wait_for(self.queue.get(), timeout=0.2)
            except asyncio.TimeoutError:
                continue

            try:
                await self.process_event(event)
            finally:
                self.queue.task_done()

    def stop(self) -> None:
        """Signal the detection worker loop to stop."""
        self._stop_event.set()
