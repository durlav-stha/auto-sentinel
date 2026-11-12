"""Asynchronous Log Tailer with File Rotation Detection (Stage 1: The Eyes).

Watches authentication logs in real time, survives log rotation via file-ID
(inode) tracking, and normalizes raw SSH log lines into SecurityEvents.
"""

import asyncio
import os
import re
from pathlib import Path
from typing import Optional
from auto_sentinel.models import SecurityEvent, EventType
from auto_sentinel.bus.queue import EventQueue

# Matches: "Failed password for invalid user admin from 192.168.1.50 port 22 ssh2"
# Or:      "Failed password for root from 10.0.0.5 port 54321 ssh2"
FAILED_SSH_REGEX = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Matches: "Accepted password for ubuntu from 192.168.1.10 port 22 ssh2"
ACCEPTED_SSH_REGEX = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class AsyncLogTailer:
    """Non-blocking log watcher that survives log rotation via file-ID tracking."""

    def __init__(self, log_path: str | Path, queue: EventQueue, poll_interval: float = 0.2):
        self.log_path = Path(log_path)
        self.queue = queue
        self.poll_interval = poll_interval
        self._stop_event = asyncio.Event()
        self._offset: int = 0
        self._file_id: Optional[tuple[int, int]] = None

    @staticmethod
    def _get_file_identity(path: Path) -> Optional[tuple[int, int]]:
        """Return (st_dev, st_ino) to uniquely identify a file across rotations."""
        try:
            stat = os.stat(path)
            return (stat.st_dev, stat.st_ino)
        except FileNotFoundError:
            return None

    @staticmethod
    def parse_auth_line(raw_line: str) -> Optional[SecurityEvent]:
        """Parse a raw SSH/auth log line into a structured SecurityEvent."""
        line = raw_line.strip()
        if not line:
            return None

        # 1. Check for failed SSH authentication attempt
        failed_match = FAILED_SSH_REGEX.search(line)
        if failed_match:
            return SecurityEvent(
                event_type=EventType.AUTH_FAILURE,
                source="auth.log",
                source_ip=failed_match.group("ip"),
                user=failed_match.group("user"),
                raw_message=line,
            )

        # 2. Check for successful SSH authentication
        accepted_match = ACCEPTED_SSH_REGEX.search(line)
        if accepted_match:
            return SecurityEvent(
                event_type=EventType.AUTH_SUCCESS,
                source="auth.log",
                source_ip=accepted_match.group("ip"),
                user=accepted_match.group("user"),
                raw_message=line,
            )

        return None

    async def poll_once(self) -> int:
        """Read newly appended lines from the log file, handling truncation or rotation."""
        if not self.log_path.exists():
            return 0

        current_id = self._get_file_identity(self.log_path)
        file_size = self.log_path.stat().st_size

        # Detect file rotation (inode changed) or truncation (file shrank)
        if (self._file_id is not None and current_id != self._file_id) or file_size < self._offset:
            self._offset = 0

        self._file_id = current_id
        emitted = 0

        with open(self.log_path, "r", encoding="utf-8", errors="replace") as fp:
            fp.seek(self._offset)
            for line in fp:
                event = self.parse_auth_line(line)
                if event is not None:
                    await self.queue.put(event)
                    emitted += 1
            self._offset = fp.tell()

        return emitted

    async def start(self) -> None:
        """Continuously tail the log file until stopped."""
        while not self._stop_event.is_set():
            await self.poll_once()
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Signal the tailer loop to stop."""
        self._stop_event.set()
