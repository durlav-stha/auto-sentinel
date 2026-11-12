"""Unit tests for bus/queue.py (The Bounded Event Buffer)."""

import asyncio
import pytest
from auto_sentinel.models import SecurityEvent, EventType
from auto_sentinel.bus.queue import EventQueue


@pytest.fixture
def sample_event():
    return SecurityEvent(
        event_type=EventType.AUTH_FAILURE,
        source="auth.log",
        source_ip="192.168.1.100",
        raw_message="Failed password for invalid user admin",
    )


@pytest.mark.asyncio
async def test_queue_put_and_get(sample_event):
    """Test basic non-blocking ingestion and retrieval."""
    queue = EventQueue(maxsize=10)
    await queue.put(sample_event)
    assert queue.qsize() == 1

    event = await queue.get()
    assert event.event_id == sample_event.event_id
    assert event.source_ip == "192.168.1.100"
    queue.task_done()
    assert queue.qsize() == 0


@pytest.mark.asyncio
async def test_queue_bounded_backpressure(sample_event):
    """Test that a bounded queue enforces backpressure when full."""
    queue = EventQueue(maxsize=2)
    await queue.put(sample_event)
    await queue.put(sample_event)
    assert queue.full() is True

    # Attempting to put into a full queue with timeout should raise TimeoutError
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(queue.put(sample_event), timeout=0.1)


@pytest.mark.asyncio
async def test_queue_drain(sample_event):
    """Test that drain() clears remaining items during engine shutdown."""
    queue = EventQueue(maxsize=10)
    for _ in range(5):
        await queue.put(sample_event)

    drained_items = await queue.drain()
    assert len(drained_items) == 5
    assert queue.empty() is True
