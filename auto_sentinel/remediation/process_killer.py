"""Safe Process Terminator with PID-Reuse Protection (Stage 3: The Hands).

Verifies process binary identity before sending termination signals to prevent
Time-Of-Check to Time-Of-Use (TOCTOU) PID recycling race conditions and protect
critical operating system services.
"""

from typing import Set
import psutil
from auto_sentinel.models import RemediationResult, ActionType

# Critical system processes that must NEVER be terminated
PROTECTED_PROCESSES: Set[str] = {
    "systemd", "init", "sshd", "csrss.exe", "lsass.exe", "services.exe", "wininit.exe", "explorer.exe"
}


class ProcessKiller:
    """Safely terminates malicious processes after verifying PID identity."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run

    @staticmethod
    def verify_pid_identity(actual_name: str, expected_name: str) -> bool:
        """Verify PID identity and ensure the binary is not a protected OS process."""
        actual_norm = actual_name.strip().lower()
        expected_norm = expected_name.strip().lower()

        if not actual_norm or not expected_norm:
            return False

        if actual_norm in PROTECTED_PROCESSES:
            return False

        return actual_norm == expected_norm

    def kill_process(self, pid: int, expected_name: str) -> RemediationResult:
        """Verify and terminate the target process ID."""
        if pid <= 4:
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=False,
                details=f"Refused to kill reserved kernel/init PID: {pid}",
            )

        try:
            proc = psutil.Process(pid)
            actual_name = proc.name()
        except psutil.NoSuchProcess:
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=False,
                details=f"PID {pid} no longer exists.",
            )
        except psutil.AccessDenied:
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=False,
                details=f"Access denied inspecting PID {pid}.",
            )

        if not self.verify_pid_identity(actual_name, expected_name):
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=False,
                details=(
                    f"PID Reuse / Protection Guard triggered! Expected '{expected_name}', "
                    f"found '{actual_name}' at PID {pid}."
                ),
            )

        if self.dry_run:
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=True,
                details=f"[DRY-RUN] Verified and would terminate PID {pid} ({actual_name})",
            )

        try:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except psutil.TimeoutExpired:
                proc.kill()
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=True,
                details=f"Terminated PID {pid} ({actual_name})",
            )
        except psutil.Error as exc:
            return RemediationResult(
                action_type=ActionType.KILL_PROCESS,
                target=str(pid),
                success=False,
                details=f"Failed to terminate PID {pid}: {exc}",
            )
