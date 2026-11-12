# 🛡️ auto-sentinel

**Lightweight Event-Driven SOAR & Automated Incident Response Engine**

`auto-sentinel` is an asynchronous Python 3.12 security orchestration, automation, and response (SOAR) engine that ingests live host and authentication telemetry, correlates attack patterns mapped to **MITRE ATT&CK**, executes injection-safe active containment, and seals forensic evidence in a **SHA-256 hash-chained audit ledger**.

---

## 🏗️ 4-Stage Pipeline Architecture

```text
[Stage 1: The Eyes]       -->  [Bounded EventQueue]  -->  [Stage 2: The Brain]
 - AsyncLogTailer               (Backpressure Guard)       - SignatureMatcher (T1059)
 - ProcessMonitor                                          - SlidingWindowCorrelator (T1110)
                                                                     |
[Stage 4: The Black Box]  <--  [Stage 3: The Hands]  <---------------+
 - TamperEvidentLedger          - NetworkBlocker (shell=False + Whitelist)
   (SHA-256 Hash Chain)         - ProcessKiller (TOCTOU PID-Reuse Guard)
```

---

## 🔒 Defensive Security Guarantees

1. **OOM Backpressure Protection (`bus/queue.py`)**: Bounded `asyncio.Queue(maxsize=N)` throttles upstream collectors during high-volume log floods (DDoS/brute-force surges) to prevent Out-Of-Memory crashes.
2. **Inode / File-ID Rotation Tracking (`collectors/log_tailer.py`)**: Tracks `(st_dev, st_ino)` and byte offsets to survive log rotation and truncation without dropping telemetry.
3. **Command Injection Immunity (`remediation/network_blocker.py`)**: Strictly validates IPv4/IPv6 addresses via Python's `ipaddress` module, enforces loopback/admin whitelist blast-radius guards, and invokes `iptables`/`netsh` via argument lists with `shell=False`.
4. **TOCTOU / PID-Recycling Protection (`remediation/process_killer.py`)**: Verifies the target PID's binary name against the expected malicious binary and blocks termination of critical OS processes (`sshd`, `systemd`, `lsass.exe`) before sending `SIGTERM`/`SIGKILL`.
5. **Cryptographic Tamper-Evident Logging (`ledger/tamper_evident.py`)**: Every incident record is chained to the previous record's SHA-256 digest (`H_n = SHA256(record_n || H_{n-1})`), immediately exposing any post-compromise log tampering.

---

## 🧪 Running the Test Suite

```bash
pytest
```
