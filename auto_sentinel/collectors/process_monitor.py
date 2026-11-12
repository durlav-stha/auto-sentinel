"""OS Process Table Monitor (Stage 1: The Eyes).

Periodically inspects running OS processes via `psutil` to detect suspicious
parent-child relationships (e.g. web servers spawning interactive shells) or
obfuscated command-line execution (MITRE T1059 / T1190).
"""

import asyncio
from typing import List, Set
import psutil
from auto_sentinel.models import SecurityEvent, EventType
from auto_sentinel.bus.queue import EventQueue

# Server binaries that should NEVER spawn an interactive shell
SERVER_PARENTS: Set[str] = {
    "nginx", "nginx.exe",
    "apache2", "httpd", "httpd.exe",
    "w3wp.exe", "tomcat", "node", "node.exe",
    "mysqld", "postgres", "sqlservr.exe",
}

# Shell binaries often spawned during RCE / Reverse Shell attacks
SHELL_BINARIES: Set[str] = {
    "sh", "bash", "dash", "zsh",
    "cmd.exe", "powershell.exe", "pwsh.exe",
}

# Dangerous command-line flags indicating obfuscated or reverse-shell execution
SUSPICIOUS_FLAGS: tuple[str, ...] = (
    "-enc", "-encodedcommand", "/dev/tcp/", "nc -e", "bash -i", "whoami /priv"
)


class ProcessMonitor:
    """Periodically inspects running OS processes for parent-child anomalies."""

    def __init__(self, queue: EventQueue, poll_interval: float = 1.0):
        self.queue = queue
        self.poll_interval = poll_interval
        self._seen_pids: Set[int] = set()
        self._stop_event = asyncio.Event()

    @staticmethod
    def is_suspicious_spawn(parent_name: str, child_name: str, cmdline: List[str]) -> bool:
        """Determine if a newly spawned process exhibits anomalous behavior."""
        parent_norm = parent_name.strip().lower()
        child_norm = child_name.strip().lower()

        # 1. Parent-Child Anomaly: Server binary spawning an interactive shell
        if parent_norm in SERVER_PARENTS and child_norm in SHELL_BINARIES:
            return True

        # 2. Suspicious Command-Line Flags: Encoded payloads or reverse shell redirects
        cmd_str = " ".join(cmdline).lower()
        if any(flag in cmd_str for flag in SUSPICIOUS_FLAGS):
            return True

        return False

    async def scan_once(self) -> int:
        """Scan current OS process table and emit SecurityEvents for new anomalies."""
        emitted = 0
        for proc in psutil.process_iter(["pid", "ppid", "name", "cmdline", "username"]):
            try:
                info = proc.info
                pid = info["pid"]
                if pid in self._seen_pids:
                    continue
                self._seen_pids.add(pid)

                child_name = info.get("name") or ""
                cmdline = info.get("cmdline") or []
                ppid = info.get("ppid")
                parent_name = ""
                if ppid:
                    try:
                        parent_name = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        parent_name = ""

                if self.is_suspicious_spawn(parent_name, child_name, cmdline):
                    event = SecurityEvent(
                        event_type=EventType.PROCESS_SPAWNED,
                        source="process_monitor",
                        user=info.get("username"),
                        process_name=child_name,
                        process_pid=pid,
                        raw_message=f"Parent={parent_name} spawned Child={child_name} (cmd={' '.join(cmdline)})",
                        metadata={"parent_name": parent_name, "cmdline": cmdline},
                    )
                    await self.queue.put(event)
                    emitted += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        return emitted

    async def start(self) -> None:
        """Continuously scan the process table until stopped."""
        while not self._stop_event.is_set():
            await self.scan_once()
            await asyncio.sleep(self.poll_interval)

    def stop(self) -> None:
        """Signal the process monitor loop to stop."""
        self._stop_event.set()
