"""Injection-Safe Firewall IP Blocker (Stage 3: The Hands).

Validates target IP addresses with `ipaddress.ip_address` (preventing command
injection), enforces loopback/whitelist blast-radius guards, and executes host
firewall commands with `shell=False`.
"""

import ipaddress
import platform
import subprocess
from typing import List, Optional, Set
from auto_sentinel.models import RemediationResult, ActionType

DEFAULT_WHITELIST: Set[str] = {"127.0.0.1", "::1", "10.0.0.1"}


class NetworkBlocker:
    """Safely blocks malicious IPs at the host firewall without shell injection."""

    def __init__(self, whitelist: Optional[Set[str]] = None, dry_run: bool = True):
        self.whitelist: Set[str] = whitelist if whitelist is not None else set(DEFAULT_WHITELIST)
        self.dry_run = dry_run

    def is_safe_to_block(self, ip_str: str) -> bool:
        """Validate IP string syntax and ensure it is not loopback or whitelisted."""
        if not ip_str or ip_str in self.whitelist:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            # Rejects malformed strings and command injection payloads like "1.2.3.4; rm -rf /"
            return False

        if ip_obj.is_loopback:
            return False

        return True

    @staticmethod
    def build_firewall_command(ip_str: str) -> List[str]:
        """Build an argument list (NEVER a shell string) for the host OS firewall."""
        if platform.system().lower().startswith("win"):
            return [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=AutoSentinel_Block_{ip_str}",
                "dir=in", "action=block", f"remoteip={ip_str}",
            ]
        return ["iptables", "-A", "INPUT", "-s", ip_str, "-j", "DROP"]

    def block_ip(self, ip_str: str) -> RemediationResult:
        """Validate and block the target IP address."""
        if not self.is_safe_to_block(ip_str):
            return RemediationResult(
                action_type=ActionType.BLOCK_IP,
                target=ip_str,
                success=False,
                details=f"Refused to block invalid, loopback, or whitelisted IP: {ip_str}",
            )

        cmd = self.build_firewall_command(ip_str)
        if self.dry_run:
            return RemediationResult(
                action_type=ActionType.BLOCK_IP,
                target=ip_str,
                success=True,
                details=f"[DRY-RUN] Firewall rule prepared: {' '.join(cmd)}",
            )

        proc = subprocess.run(cmd, shell=False, capture_output=True, text=True, timeout=5)
        return RemediationResult(
            action_type=ActionType.BLOCK_IP,
            target=ip_str,
            success=(proc.returncode == 0),
            details="Firewall rule applied" if proc.returncode == 0 else "Firewall command failed",
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
