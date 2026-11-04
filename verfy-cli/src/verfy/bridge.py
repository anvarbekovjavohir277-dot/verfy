"""A stdio MCP server that forwards everything to a remote server over Streamable HTTP.

The gateway guards a server it starts as a child process. Started as that child, this bridge puts a remote server
behind the same gateway: its rules, lock, receipts and redaction apply unchanged.

Headers come from the environment (HEADERS_ENV), so a key is not on a command line where other programs can read it.
Messages the server sends on its own, outside an answer to a request, need a separate stream that this does not open.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from typing import IO, Callable

from .mcp_client import PROTOCOL, HttpSession, MCPError, _messages, expand

HEADERS_ENV = "VERFY_BRIDGE_HEADERS"
TIMEOUT = 300.0  # a tool call can take minutes


def headers_from_env(env=os.environ) -> dict[str, str]:
    raw = env.get(HEADERS_ENV)
    if not raw:
        return {}
    try:
        headers = json.loads(raw)
    except json.JSONDecodeError:
        raise MCPError(f"{HEADERS_ENV} is not valid JSON") from None
    return {str(k): expand(str(v), env, f"header {k}") for k, v in headers.items()}


class Bridge:
    def __init__(self, url: str, headers: dict[str, str], *, inp: IO[bytes] | None = None, out: IO[bytes] | None = None,
                 log: Callable[[str], None] | None = None, timeout: float = TIMEOUT):
        self.http = HttpSession(url, headers, timeout)
        self.inp = inp or sys.stdin.buffer
        self.out = out or sys.stdout.buffer
        self.log = log or (lambda text: print(f"[verfy bridge] {text}", file=sys.stderr, flush=True))
        self.lock = threading.Lock()

    def send(self, msg: dict) -> None:
        data = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self.lock:
            self.out.write(data)
            self.out.flush()

    def forward(self, msg: dict) -> None:
        """Post one message and pass on everything the server answers. A request that fails gets a JSON-RPC error,
        so the client is not left waiting."""
        try:
            with self.http.open("POST", msg) as resp:
                for answer in _messages(resp):
                    if msg.get("method") == "initialize" and isinstance(answer, dict) and answer.get("id") == msg.get("id"):
                        result = answer.get("result")
                        version = result.get("protocolVersion") if isinstance(result, dict) else None
                        self.http.sent["MCP-Protocol-Version"] = str(version or PROTOCOL)
                    self.send(answer)
        except (MCPError, OSError) as e:
            self.log(str(e))
            if "method" in msg and "id" in msg:
                self.send({"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32000, "message": f"remote server: {e}"}})

    def run(self) -> int:
        calls: list[threading.Thread] = []
        for line in iter(self.inp.readline, b""):
            if not line.strip():
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                self.log("ignored a line that is not JSON")
                continue
            if not isinstance(msg, dict):
                continue
            if msg.get("method") == "initialize":
                self.forward(msg)  # later messages need the session id it returns
                continue
            # a long tool call must not hold up the messages behind it
            t = threading.Thread(target=self.forward, args=(msg,), daemon=True)
            t.start()
            calls.append(t)
            calls = [c for c in calls if c.is_alive()]
        for t in calls:
            t.join(timeout=10)
        self.http.close()
        return 0
