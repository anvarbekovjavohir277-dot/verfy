"""A minimal MCP client that fetches a live tool list: stdio servers are started as a child
process, remote servers are asked over Streamable HTTP. Used by ``verfy scan`` and ``verfy lock check``."""

from __future__ import annotations

import json
import queue
import re
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator, Mapping

PROTOCOL = "2025-06-18"
MAX_BODY = 16 * 1024 * 1024
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


class MCPError(RuntimeError):
    pass


def expand(text: str, env: Mapping[str, str], where: str) -> str:
    """Fill in ``${VAR}`` and ``${VAR:-default}`` the way Claude Code does in .mcp.json."""
    def sub(m: re.Match) -> str:
        if m.group(1) in env:
            return env[m.group(1)]
        if m.group(2) is not None:
            return m.group(2)
        raise MCPError(f"{where} uses ${{{m.group(1)}}}, which is not set")
    return VAR.sub(sub, text)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # reported, never followed: the request may carry the server's key


def _where(url: str) -> str:
    """An address without its query string, safe to print."""
    p = urllib.parse.urlsplit(url)
    return urllib.parse.urlunsplit((p.scheme, p.netloc.rpartition("@")[2], p.path, "", ""))


def _http_problem(e: urllib.error.HTTPError) -> str:
    if 300 <= e.code < 400:
        to = e.headers.get("Location")
        return (f"the server redirected to {_where(to) if to else 'another address'} (HTTP {e.code}); put that address in the config. "
                "Verfy does not follow redirects, so a key is never sent anywhere else")
    if e.code in (401, 403):
        return f"the server refused the request (HTTP {e.code}): give it a key in the config's headers, for example ${{MCP_TOKEN}} from a CI secret"
    if e.code in (404, 405):
        return f"no MCP endpoint at this address (HTTP {e.code}). Servers that only speak the older SSE transport are not supported yet"
    return f"the server answered HTTP {e.code} {e.reason}"


def _messages(resp) -> Iterator[Any]:
    """JSON-RPC messages in an HTTP answer: one JSON body, or the data of each server-sent event."""
    if (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "text/event-stream":
        body = resp.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise MCPError("the server's answer is larger than 16 MB")
        texts: Iterator[str] = iter([body.decode("utf-8", "replace")])
    else:
        texts = _events(resp)
    for text in texts:
        try:
            msg = json.loads(text)
        except json.JSONDecodeError:
            continue
        yield from msg if isinstance(msg, list) else [msg]


def _events(resp) -> Iterator[str]:
    data: list[str] = []
    size = 0
    for raw in resp:
        size += len(raw)
        if size > MAX_BODY:
            raise MCPError("the server's answer is larger than 16 MB")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data:
                yield "\n".join(data)
            data = []
        elif line.startswith("data:"):
            data.append(line[6:] if line.startswith("data: ") else line[5:])
    if data:
        yield "\n".join(data)


def list_tools_http(url: str, headers: Mapping[str, str] | None = None, timeout: float = 30.0) -> dict:
    """Run the MCP handshake with a remote server over Streamable HTTP and return ``{"server": info, "tools": [...]}``."""
    host = urllib.parse.urlsplit(url).hostname
    if urllib.parse.urlsplit(url).scheme not in ("http", "https") or not host:
        raise MCPError("the server's url must start with https:// or http://")
    opener = urllib.request.build_opener(_NoRedirect)
    sent = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": "verfy", **(headers or {})}

    def open_(method: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        try:
            return opener.open(urllib.request.Request(url, data=data, method=method, headers=sent), timeout=timeout)
        except urllib.error.HTTPError as e:
            raise MCPError(_http_problem(e)) from None
        except (urllib.error.URLError, OSError) as e:  # timeouts are OSErrors too
            raise MCPError(f"cannot reach {host}: {getattr(e, 'reason', None) or e}") from None
        except ValueError:  # http.client's message would quote the header, which may be a key
            raise MCPError("the url or a header in the config is not valid (for example a line break in it)") from None

    def call(mid: int, method: str, params: dict) -> dict:
        with open_("POST", {"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) as resp:
            if resp.headers.get("Mcp-Session-Id"):
                sent["Mcp-Session-Id"] = resp.headers["Mcp-Session-Id"]
            try:
                for m in _messages(resp):
                    if isinstance(m, dict) and m.get("id") == mid and "method" not in m:
                        if "error" in m:
                            err = m["error"]
                            raise MCPError(f"server error: {err.get('message', err) if isinstance(err, dict) else err}")
                        return m["result"] if isinstance(m.get("result"), dict) else {}
            except OSError as e:
                raise MCPError(f"{host} stopped answering: {e}") from None
        raise MCPError(f"{host} closed the answer to `{method}` without a result")

    try:
        init = call(1, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "verfy-scan", "version": "0.2.0"}})
        sent["MCP-Protocol-Version"] = str(init.get("protocolVersion") or PROTOCOL)
        open_("POST", {"jsonrpc": "2.0", "method": "notifications/initialized"}).close()
        tools: list = []
        cursor = None
        mid = 2
        while True:
            res = call(mid, "tools/list", {"cursor": cursor} if cursor else {})
            tools.extend(res.get("tools") or [])
            cursor = res.get("nextCursor")
            mid += 1
            if not cursor or mid > 100:
                break
        return {"server": init.get("serverInfo", {}), "tools": tools}
    finally:
        if "Mcp-Session-Id" in sent:
            try:
                open_("DELETE").close()  # end the session; a server may refuse, which is fine
            except MCPError:
                pass


def list_tools(command: list[str], timeout: float = 30.0, env: dict | None = None) -> dict:
    """Start ``command``, run the MCP handshake and return ``{"server": info, "tools": [...]}``."""
    if not command or not command[0]:
        raise MCPError("the server has no command to start")
    try:
        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, bufsize=0)
    except FileNotFoundError:
        raise MCPError(f"cannot start `{command[0]}`: command not found") from None
    except OSError as e:
        raise MCPError(f"cannot start `{command[0]}`: {e.strerror or e}") from None
    q: "queue.Queue[Any]" = queue.Queue()

    def reader():
        assert proc.stdout
        for line in iter(proc.stdout.readline, b""):
            try:
                q.put(json.loads(line))
            except json.JSONDecodeError:
                continue
        q.put(None)

    threading.Thread(target=reader, daemon=True).start()

    def send(msg: dict) -> None:
        assert proc.stdin
        proc.stdin.write((json.dumps(msg) + "\n").encode())
        proc.stdin.flush()

    def wait_for(mid: int) -> dict:
        while True:
            try:
                m = q.get(timeout=timeout)
            except queue.Empty:
                raise MCPError(f"server did not answer within {timeout:g}s") from None
            if m is None:
                raise MCPError("server exited before answering")
            if isinstance(m, dict) and m.get("id") == mid and "method" not in m:
                if "error" in m:
                    raise MCPError(f"server error: {m['error'].get('message', m['error'])}")
                return m.get("result") or {}

    try:
        send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "verfy-scan", "version": "0.2.0"}}})
        init = wait_for(1)
        send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        tools: list = []
        cursor = None
        mid = 2
        while True:
            send({"jsonrpc": "2.0", "id": mid, "method": "tools/list", "params": {"cursor": cursor} if cursor else {}})
            res = wait_for(mid)
            tools.extend(res.get("tools") or [])
            cursor = res.get("nextCursor")
            mid += 1
            if not cursor or mid > 100:
                break
        return {"server": init.get("serverInfo", {}), "tools": tools}
    finally:
        try:
            proc.stdin.close()  # type: ignore[union-attr]
        except OSError:
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
