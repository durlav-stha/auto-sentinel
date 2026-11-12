"""Main Engine Entrypoint & Orchestrator (auto_sentinel/main.py).

Connects all 4 stages into a single asynchronous pipeline:
Stage 1 (Collectors + EventQueue) -> Stage 2 (DetectionEngine) -> Stage 3 (RemediationRunner) -> Stage 4 (TamperEvidentLedger)
"""

import argparse
import asyncio
import logging
import signal
import sys
from pathlib import Path
from auto_sentinel.bus.queue import EventQueue
from auto_sentinel.collectors.log_tailer import AsyncLogTailer
from auto_sentinel.collectors.process_monitor import ProcessMonitor
from auto_sentinel.detector.correlator import SlidingWindowCorrelator
from auto_sentinel.detector.engine import DetectionEngine
from auto_sentinel.remediation.network_blocker import NetworkBlocker
from auto_sentinel.remediation.process_killer import ProcessKiller
from auto_sentinel.remediation.runner import RemediationRunner
from auto_sentinel.ledger.tamper_evident import TamperEvidentLedger

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("auto-sentinel")


class AutoSentinelEngine:
    """High-level SOAR runtime wiring all 4 stages together."""

    def __init__(self, log_file: str | Path, ledger_file: str | Path, dry_run: bool = True):
        self.log_file = Path(log_file)
        self.ledger_file = Path(ledger_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.ledger_file.parent.mkdir(parents=True, exist_ok=True)
        if not self.log_file.exists():
            self.log_file.touch()

        self.queue = EventQueue(maxsize=1000)
        self.ledger = TamperEvidentLedger(self.ledger_file)
        self.remediation = RemediationRunner(
            network_blocker=NetworkBlocker(dry_run=dry_run),
            process_killer=ProcessKiller(dry_run=dry_run),
            ledger=self.ledger,
        )
        self.correlator = SlidingWindowCorrelator(threshold=5, window_seconds=60.0)
        self.detector = DetectionEngine(
            queue=self.queue,
            correlator=self.correlator,
            on_alert=self._on_alert,
        )
        self.log_tailer = AsyncLogTailer(log_path=self.log_file, queue=self.queue)
        self.process_monitor = ProcessMonitor(queue=self.queue)

    async def _on_alert(self, alert) -> None:
        logger.warning(
            "🚨 ALERT [%s] (%s): %s",
            alert.severity.value,
            alert.mitre_technique_id,
            alert.description,
        )
        results = await self.remediation.handle_alert(alert)
        for res in results:
            logger.info("🥊 REMEDIATION [%s -> %s]: %s", res.action_type.value, res.target, res.details)

    async def start(self) -> None:
        """Start all async workers concurrently."""
        await asyncio.gather(
            self.log_tailer.start(),
            self.process_monitor.start(),
            self.detector.run(),
        )

    async def shutdown(self) -> None:
        """Gracefully stop collectors, drain remaining events, and verify ledger."""
        logger.info("🛑 Shutting down auto-sentinel workers...")
        self.log_tailer.stop()
        self.process_monitor.stop()
        self.detector.stop()

        leftover = await self.queue.drain()
        for event in leftover:
            await self.detector.process_event(event)

        intact, total = self.ledger.verify_integrity()
        logger.info("🔒 Shutdown complete. Ledger intact=%s (records=%d)", intact, total)


async def run_demo_simulation(log_path: Path):
    """Simulates an attacker attempting SSH brute force in real time."""
    await asyncio.sleep(2.0)
    attacker_ip = "203.0.113.199"
    logger.info("⚔️ [SIMULATION] Attacker from IP %s begins brute-forcing SSH...", attacker_ip)
    
    with open(log_path, "a", encoding="utf-8") as fp:
        for i in range(1, 6):
            fp.write(
                f"Nov 12 04:00:0{i} srv sshd[109{i}]: Failed password for invalid user root from {attacker_ip} port 22 ssh2\n"
            )
            fp.flush()
            await asyncio.sleep(0.5)

    await asyncio.sleep(2.0)
    logger.info("✅ [SIMULATION] Attack finished! Check logs above for Alert and Remediation.")


async def main():
    parser = argparse.ArgumentParser(description="auto-sentinel: Automated Incident Response SOAR Engine")
    parser.add_argument("--demo", action="store_true", help="Run with an automated live attack simulation")
    parser.add_argument("--log-file", default="data/auth.log", help="Path to auth.log to watch")
    parser.add_argument("--ledger-file", default="data/audit.jsonl", help="Path to audit ledger")
    args = parser.parse_args()

    print("=" * 65)
    print("  🛡️  AUTO-SENTINEL: Automated Incident Response SOAR Engine")
    print("=" * 65)
    print(f"[*] Telemetry Target : {args.log_file}")
    print(f"[*] Forensic Ledger  : {args.ledger_file}")
    print(f"[*] Response Mode    : DRY-RUN (Safe Simulation)")
    print(f"[*] Status           : ENGINE ARMED & LISTENING")
    print("=" * 65)

    engine = AutoSentinelEngine(
        log_file=args.log_file,
        ledger_file=args.ledger_file,
        dry_run=True,
    )

    tasks = [asyncio.create_task(engine.start())]
    if args.demo:
        tasks.append(asyncio.create_task(run_demo_simulation(Path(args.log_file))))

    try:
        if args.demo:
            # Run demo for 7 seconds then shutdown
            await asyncio.sleep(7.0)
        else:
            await asyncio.gather(*tasks)
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        await engine.shutdown()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
