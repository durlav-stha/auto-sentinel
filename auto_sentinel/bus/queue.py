"""Asynchronous bounded event queue with backpressure handling (The Waiting Room).

Security & Systems Theory:
-------------------------
In an incident response engine, a log surge (e.g. 100,000 SSH attempts/sec during
a distributed denial of service or brute force) can easily cause unbounded memory
growth, leading to an Out-Of-Memory (OOM) kernel kill.

A bounded queue (`maxsize > 0`) provides backpressure: it slows down or blocks
upstream producers (collectors) until downstream consumers (detectors) can catch up.
"""

import asyncio  # Python library for asynchronous, non-blocking concurrency
from typing import List  # Type hinting for list return types
from auto_sentinel.models import SecurityEvent  # Normalized security event data model


class EventQueue:
    """Thread-safe asynchronous bounded queue wrapper for SecurityEvents."""

    def __init__(self, maxsize: int = 1000):
        # Creates Python's built-in async queue with a strict capacity bound (prevents OOM memory crashes)
        self._queue: asyncio.Queue[SecurityEvent] = asyncio.Queue(maxsize=maxsize)

    async def put(self, event: SecurityEvent) -> None:
        # Enqueues an event; pauses (awaits) if the queue is full until space is freed (Backpressure)
        await self._queue.put(event)

    async def get(self) -> SecurityEvent:
        # Dequeues the next event; pauses (awaits) if empty until an event arrives
        return await self._queue.get()

    def task_done(self) -> None:
        # Signals that a retrieved event has finished being processed by a worker
        self._queue.task_done()

    def qsize(self) -> int:
        # Returns the number of events currently buffered in line
        return self._queue.qsize()

    def empty(self) -> bool:
        # Returns True if the buffer contains 0 events, False otherwise
        return self._queue.empty()

    def full(self) -> bool:
        # Returns True if the buffer has reached maximum capacity, False otherwise
        return self._queue.full()

    async def drain(self) -> List[SecurityEvent]:
        # Safely empties and returns all remaining items during engine shutdown without dropping events
        items: List[SecurityEvent] = []
        while not self._queue.empty():
            item = self._queue.get_nowait()
            self._queue.task_done()
            items.append(item)
        return items
