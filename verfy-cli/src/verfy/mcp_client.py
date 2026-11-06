"""A minimal MCP client that fetches a live tool list: stdio servers are started as a child
process, remote servers are asked over Streamable HTTP, or the older HTTP+SSE transport for a server
that has nothing else. Used by ``verfy scan`` and ``verfy lock check``."""

from __future__ import annotations

import json
import queue
import re
import subprocess
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Iterator, Mapping
from .scanner import prompt_tool

PROTOCOL = "2025-06-18"
MAX_BODY = 16 * 1024 * 1024
VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
SSE_HINT = (400, 404, 405)  # what a server without Streamable HTTP answers to a POST: try the older transport


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
        return f"no MCP endpoint at this address (HTTP {e.code})"
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


def _sse(resp, long_lived: bool = False) -> Iterator[tuple[str, str]]:
    """(event name, data) for each server-sent event. The size limit is per answer, or per event on a stream that stays open."""
    name, data, size = "message", [], 0
    for raw in resp:
        size += len(raw)
        if size > MAX_BODY:
            raise MCPError("the server's answer is larger than 16 MB")
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if not line:
            if data:
                yield name, "\n".join(data)
            name, data = "message", []
            size = 0 if long_lived else size
        elif line.startswith("event:"):
            name = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[6:] if line.startswith("data: ") else line[5:])
    if data:
        yield name, "\n".join(data)


def _events(resp) -> Iterator[str]:
    return (data for _, data in _sse(resp))


class HttpSession:
    """One Streamable HTTP session with a remote server: sends the headers, keeps the session id, follows no redirect."""

    def __init__(self, url: str, headers: Mapping[str, str] | None = None, timeout: float = 30.0):
        self.url = url
        self.host = urllib.parse.urlsplit(url).hostname
        if urllib.parse.urlsplit(url).scheme not in ("http", "https") or not self.host:
            raise MCPError("the server's url must start with https:// or http://")
        self.timeout = timeout
        self.opener = urllib.request.build_opener(_NoRedirect)
        self.sent = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream", "User-Agent": "verfy", **(headers or {})}

    def open(self, method: str, body: dict | None = None):
        data = None if body is None else json.dumps(body).encode()
        try:
            resp = self.opener.open(urllib.request.Request(self.url, data=data, method=method, headers=self.sent), timeout=self.timeout)
        except urllib.error.HTTPError as e:
            problem = MCPError(_http_problem(e))
            problem.status = e.code
            raise problem from None
        except (urllib.error.URLError, OSError) as e:  # timeouts are OSErrors too
            raise MCPError(f"cannot reach {self.host}: {getattr(e, 'reason', None) or e}") from None
        except ValueError:  # http.client's message would quote the header, which may be a key
            raise MCPError("the url or a header in the config is not valid (for example a line break in it)") from None
        if resp.headers.get("Mcp-Session-Id"):
            self.sent["Mcp-Session-Id"] = resp.headers["Mcp-Session-Id"]
        return resp

    def close(self) -> None:
        """End the session; a server may refuse, which is fine."""
        if "Mcp-Session-Id" in self.sent:
            try:
                self.open("DELETE").close()
            except MCPError:
                pass


class SseSession:
    """The older HTTP+SSE transport: answers come on one long GET stream, and messages go by POST to the address the
    server names in its first event. That address must be on the same server, so a key is never sent anywhere else.

    Each message is passed to ``on_message``, and ``None`` when the stream ends. With ``stream_timeout`` None the stream
    may stay quiet for as long as it likes, as a tool call can."""

    def __init__(self, url: str, headers: Mapping[str, str] | None, on_message: Callable[[Any], None], timeout: float = 30.0,
                 stream_timeout: float | None = None):
        self.url, self.headers, self.on_message, self.timeout = url, headers, on_message, timeout
        self.stream = HttpSession(url, headers, stream_timeout)
        self.stream.sent.pop("Content-Type")
        self.stream.sent["Accept"] = "text/event-stream"
        self.posts: HttpSession | None = None
        self.problem: MCPError | None = None
        self.ready = threading.Event()
        threading.Thread(target=self._read, daemon=True).start()
        if not self.ready.wait(timeout):
            raise MCPError(f"{self.stream.host} did not open an event stream in time")
        if self.problem:
            raise self.problem

    def _endpoint(self, data: str) -> HttpSession:
        target = urllib.parse.urljoin(self.url, data.strip())
        a, b = urllib.parse.urlsplit(self.url), urllib.parse.urlsplit(target)
        if (a.scheme, a.hostname, a.port) != (b.scheme, b.hostname, b.port):
            raise MCPError(f"the server named another address for its messages ({_where(target)}). Verfy sends a key only to the address in the config")
        return HttpSession(target, self.headers, self.timeout)

    def _read(self) -> None:
        try:
            resp = self.stream.open("GET")
            if (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "text/event-stream":
                raise MCPError(f"no MCP endpoint at this address: {self.stream.host} did not answer with an event stream")
            for name, data in _sse(resp, long_lived=True):
                if name == "endpoint" and self.posts is None:
                    self.posts = self._endpoint(data)
                    self.ready.set()
                elif name == "message":
                    try:
                        msg = json.loads(data)
                    except json.JSONDecodeError:
                        continue
                    for m in msg if isinstance(msg, list) else [msg]:
                        self.on_message(m)
        except MCPError as e:
            self.problem = e
        except OSError as e:  # the stream broke or timed out
            self.problem = MCPError(f"{self.stream.host} stopped answering: {e}")
        if not self.ready.is_set():
            self.problem = self.problem or MCPError(f"{self.stream.host} closed the event stream without naming an address for messages")
            self.ready.set()
        self.on_message(None)

    def post(self, msg: dict) -> None:
        self.posts.open("POST", msg).close()


def _list_tools_sse(url: str, headers: Mapping[str, str] | None, timeout: float) -> dict:
    got: queue.Queue = queue.Queue()
    sse = SseSession(url, headers, got.put, timeout, stream_timeout=timeout)
    host = sse.stream.host

    def call(mid: int, method: str, params: dict) -> dict:
        sse.post({"jsonrpc": "2.0", "id": mid, "method": method, "params": params})
        while True:
            try:
                m = got.get(timeout=timeout)
            except queue.Empty:
                raise MCPError(f"{host} did not answer `{method}` in time") from None
            if m is None:
                raise sse.problem or MCPError(f"{host} closed the stream without answering `{method}`")
            if isinstance(m, dict) and m.get("id") == mid and "method" not in m:
                return _result(m)

    return _handshake(call, lambda: sse.post({"jsonrpc": "2.0", "method": "notifications/initialized"}))


def _result(m: dict) -> dict:
    if "error" in m:
        err = m["error"]
        raise MCPError(f"server error: {err.get('message', err) if isinstance(err, dict) else err}")
    return m["result"] if isinstance(m.get("result"), dict) else {}


def _handshake(call: Callable[[int, str, dict], dict], initialized: Callable[[], None], on_init: Callable[[dict], None] | None = None) -> dict:
    init = call(1, "initialize", {"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "verfy-scan", "version": "0.2.0"}})
    if on_init:
        on_init(init)
    initialized()
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
    if isinstance(init.get("capabilities"), dict) and "prompts" in init["capabilities"]:
        tools.extend(_prompts(lambda method, params: call(mid + 1, method, params)))
    return {"server": init.get("serverInfo", {}), "tools": tools}


def _prompts(ask: Callable[[str, dict], dict]) -> list[dict]:
    """A server's prompts as lock entries. One that will not list them just has none to pin."""
    out: list[dict] = []
    cursor = None
    try:
        for _ in range(100):
            res = ask("prompts/list", {"cursor": cursor} if cursor else {})
            out.extend(prompt_tool(p) for p in res.get("prompts") or [] if isinstance(p, dict) and isinstance(p.get("name"), str))
            cursor = res.get("nextCursor")
            if not cursor:
                break
    except MCPError:
        return []
    return out


def list_tools_http(url: str, headers: Mapping[str, str] | None = None, timeout: float = 30.0) -> dict:
    """Run the MCP handshake with a remote server and return ``{"server": info, "tools": [...]}``: over Streamable HTTP,
    or over HTTP+SSE if the server refuses the first POST the way the MCP specification describes."""
    http = HttpSession(url, headers, timeout)
    host = http.host

    def call(mid: int, method: str, params: dict) -> dict:
        with http.open("POST", {"jsonrpc": "2.0", "id": mid, "method": method, "params": params}) as resp:
            try:
                for m in _messages(resp):
                    if isinstance(m, dict) and m.get("id") == mid and "method" not in m:
                        return _result(m)
            except OSError as e:
                raise MCPError(f"{host} stopped answering: {e}") from None
        raise MCPError(f"{host} closed the answer to `{method}` without a result")

    began = False

    def on_init(init: dict) -> None:
        nonlocal began
        began = True
        http.sent["MCP-Protocol-Version"] = str(init.get("protocolVersion") or PROTOCOL)

    try:
        return _handshake(call, lambda: http.open("POST", {"jsonrpc": "2.0", "method": "notifications/initialized"}).close(), on_init)
    except MCPError as e:
        if began or getattr(e, "status", None) not in SSE_HINT:
            raise
    finally:
        http.close()
    return _list_tools_sse(url, headers, timeout)


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
        if isinstance(init.get("capabilities"), dict) and "prompts" in init["capabilities"]:
            ids = iter(range(mid, mid + 200))

            def ask(method: str, params: dict) -> dict:
                n = next(ids)
                send({"jsonrpc": "2.0", "id": n, "method": method, "params": params})
                return wait_for(n)
            tools.extend(_prompts(ask))
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
