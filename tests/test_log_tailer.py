"""Unit tests for collectors/log_tailer.py (Core Task #1)."""

import pytest
from auto_sentinel.models import EventType
from auto_sentinel.bus.queue import EventQueue
from auto_sentinel.collectors.log_tailer import AsyncLogTailer


def test_parse_failed_ssh_line():
    line = "Nov 12 03:00:01 server sshd[1234]: Failed password for invalid user admin from 203.0.113.42 port 22 ssh2\n"
    event = AsyncLogTailer.parse_auth_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_FAILURE
    assert event.user == "admin"
    assert event.source_ip == "203.0.113.42"
    assert event.source == "auth.log"


def test_parse_accepted_ssh_line():
    line = "Nov 12 03:01:00 server sshd[1235]: Accepted password for ubuntu from 192.168.1.10 port 51234 ssh2"
    event = AsyncLogTailer.parse_auth_line(line)
    assert event is not None
    assert event.event_type == EventType.AUTH_SUCCESS
    assert event.user == "ubuntu"
    assert event.source_ip == "192.168.1.10"


def test_parse_irrelevant_line_returns_none():
    assert AsyncLogTailer.parse_auth_line("Nov 12 03:02:00 systemd[1]: Started session.") is None
    assert AsyncLogTailer.parse_auth_line("   \n") is None


@pytest.mark.asyncio
async def test_tailer_file_polling_and_rotation(tmp_path):
    log_file = tmp_path / "auth.log"
    log_file.write_text(
        "Failed password for root from 10.0.0.99 port 22 ssh2\n",
        encoding="utf-8",
    )

    queue = EventQueue(maxsize=10)
    tailer = AsyncLogTailer(log_path=log_file, queue=queue)

    count = await tailer.poll_once()
    assert count == 1
    assert queue.qsize() == 1

    # Simulate log rotation by replacing the file with a fresh shorter log file
    rotated_tmp = tmp_path / "auth.log.new"
    rotated_tmp.write_text(
        "Accepted password for root from 10.0.0.1 port 22\n",
        encoding="utf-8",
    )
    rotated_tmp.replace(log_file)
    count2 = await tailer.poll_once()
    assert count2 == 1
    assert queue.qsize() == 2
