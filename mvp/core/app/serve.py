"""Starts the core: the local API, and on a central panel a second HTTPS listener for machines' agents.

  python -m app.serve            (from mvp/core; the systemd unit runs this)

  SENTRAI_CORE_HOST / SENTRAI_CORE_PORT    the local API as before (default 127.0.0.1:8000): the dashboard,
                                         collector and notifier on this machine talk to it
  SENTRAI_PANEL_PORT                      the agents' HTTPS port (off when empty; install.sh --panel uses 8443)
  SENTRAI_PANEL_HOST                      its address (default 0.0.0.0)
  SENTRAI_PANEL_CERT / SENTRAI_PANEL_KEY   its certificate and key (install.sh --panel makes a self-signed pair;
                                         agents pin it, so it need not come from a public authority)

The agents' listener only answers what a machine key may do (main.AGENT_ROUTES) plus /fleet/enrol and
/health, and only to a machine key: the operator token and the rest of the API never face the network
through it. Both listeners serve the same app in one process, so they share one state.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import sys
from typing import Any

import uvicorn

from . import fleet

AGENT_OPEN = frozenset({("POST", "/fleet/enrol"), ("GET", "/health")})


def agents_only(app: Any, routes: frozenset[tuple[str, str]]) -> Any:
    """The app as the network sees it on the agents' port: machine-key routes only, everything else 404."""

    async def guarded(scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] == "http":
            want = (scope.get("method", ""), scope.get("path", ""))
            auth = dict(scope.get("headers") or []).get(b"authorization", b"").decode("latin-1")
            machine_key = auth[:7].lower() == "bearer " and auth[7:].strip().startswith(fleet.KEY_PREFIX)
            if want not in AGENT_OPEN and not (want in routes and machine_key):
                body = json.dumps({"detail": "not on the agents' port"}).encode()
                await send({"type": "http.response.start", "status": 404,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        elif scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        await app(scope, receive, send)

    return guarded


class _Follower(uvicorn.Server):
    """The agents' listener: the local server owns the signals and the start-up/shutdown work."""

    @contextlib.contextmanager
    def capture_signals(self):  # uvicorn >= 0.29
        yield

    def install_signal_handlers(self) -> None:  # older uvicorn
        pass


def panel_config(app: Any, env: dict[str, str]) -> uvicorn.Config | None:
    port = (env.get("SENTRAI_PANEL_PORT") or "").strip()
    if not port or port in ("0", "off"):
        return None
    cert, key = (env.get("SENTRAI_PANEL_CERT") or "").strip(), (env.get("SENTRAI_PANEL_KEY") or "").strip()
    if not (cert and key):
        raise SystemExit("SENTRAI_PANEL_PORT is set but SENTRAI_PANEL_CERT / SENTRAI_PANEL_KEY are not: agents only "
                         "talk HTTPS (sudo ./deploy/install.sh --panel makes a certificate)")
    from .main import AGENT_ROUTES

    return uvicorn.Config(agents_only(app, AGENT_ROUTES), host=env.get("SENTRAI_PANEL_HOST") or "0.0.0.0",
                          port=int(port), ssl_certfile=cert, ssl_keyfile=key, lifespan="off",
                          proxy_headers=False, server_header=False)


async def serve(env: dict[str, str] | None = None) -> None:
    env = dict(os.environ if env is None else env)
    from .main import app

    local = uvicorn.Server(uvicorn.Config(app, host=env.get("SENTRAI_CORE_HOST") or "127.0.0.1",
                                          port=int(env.get("SENTRAI_CORE_PORT") or 8000)))
    cfg = panel_config(app, env)
    if cfg is None:
        await local.serve()
        return
    panel = _Follower(cfg)
    print(f"[core] agents' HTTPS port {cfg.host}:{cfg.port} (pin {fleet.cert_pin(cfg.ssl_certfile) or '?'})",
          flush=True)
    follower = asyncio.create_task(panel.serve())
    try:
        await local.serve()
    finally:
        panel.should_exit = True
        await follower


def main() -> None:
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    sys.exit(0)


if __name__ == "__main__":
    main()
