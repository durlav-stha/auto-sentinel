"""Unit tests for remediation/ (Core Tasks #4A and #4B)."""

from auto_sentinel.remediation.network_blocker import NetworkBlocker
from auto_sentinel.remediation.process_killer import ProcessKiller


def test_network_blocker_rejects_command_injection_and_loopback():
    blocker = NetworkBlocker(whitelist={"10.0.0.1"}, dry_run=True)

    # Command injection attempt must be rejected
    assert blocker.is_safe_to_block("1.2.3.4; rm -rf /") is False
    assert blocker.is_safe_to_block("not-an-ip") is False

    # Loopback and whitelisted IPs must be rejected (prevent self-lockout)
    assert blocker.is_safe_to_block("127.0.0.1") is False
    assert blocker.is_safe_to_block("::1") is False
    assert blocker.is_safe_to_block("10.0.0.1") is False

    # Valid external attacker IP is safe to block
    assert blocker.is_safe_to_block("203.0.113.42") is True
    res = blocker.block_ip("203.0.113.42")
    assert res.success is True


def test_process_killer_pid_identity_verification():
    # Exact match of non-protected process -> True
    assert ProcessKiller.verify_pid_identity("nc.exe", "nc.exe") is True
    assert ProcessKiller.verify_pid_identity("  BASH ", "bash") is True

    # PID recycled by a different binary -> False (TOCTOU protection!)
    assert ProcessKiller.verify_pid_identity("python.exe", "nc.exe") is False

    # Critical OS process -> False (even if names match!)
    assert ProcessKiller.verify_pid_identity("sshd", "sshd") is False
    assert ProcessKiller.verify_pid_identity("lsass.exe", "lsass.exe") is False
    assert ProcessKiller.verify_pid_identity("", "bash") is False
