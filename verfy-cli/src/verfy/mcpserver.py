"""``verfy mcp``: Verfy as an MCP server, so an agent can ask Verfy before it acts.

It speaks MCP over stdio (one JSON message per line) and offers read-only tools: would a command or a tool call be
allowed, what is risky in an MCP config or in tool definitions, which agent settings are risky here, and the latest
signed receipts. It changes nothing, starts no server and makes no network call. An answer here is advice to the
agent; the hook and the gateway are what stop a call.

Add it to an agent like any other server::

    {"mcpServers": {"verfy": {"command": "verfy", "args": ["mcp"]}}}
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Callable, TextIO

from . import __version__
from . import discover as cfgscan
from . import posture as posturelib
from .precheck import check
from .receipts import public_from, read_ledger, verify_ledger
from .scanner import scan

PROTOCOL = "2025-06-18"
READ_ONLY = {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True, "openWorldHint": False}
MAX_TEXT = 2_000_000


def _obj(properties: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": properties, "required": required or [], "additionalProperties": False}


TOOLS = [
    # named and worded so that it does not read as a tool that runs things: Verfy's scanner flags a tool whose name says
    # "command" while it claims to be read-only (VFY-SCAN-012), and this one must pass its own scanner
    {"name": "check_line", "title": "Check a shell command",
     "description": "Say what Verfy's rules decide for a terminal line before an agent uses it: allow, ask or deny, and which rule decides. The line is only read.",
     "inputSchema": _obj({"line": {"type": "string", "description": "The line, as written"}}, ["line"])},
    {"name": "check_tool_call", "title": "Check a tool call",
     "description": "Say whether Verfy's rules would allow, ask about or deny a call to a tool with these arguments. Nothing is called.",
     "inputSchema": _obj({"tool": {"type": "string", "description": "The tool's name"},
                          "arguments": {"type": "object", "description": "The arguments of the call"},
                          "server": {"type": "string", "description": "The MCP server the tool belongs to, if any"}}, ["tool"])},
    {"name": "scan_mcp_config", "title": "Check an MCP config",
     "description": "Check how the MCP servers in a config are started: packages without a version, a download piped into a shell, "
                    "plain http, a key written into the file, a privileged container. Give the config's JSON text, or leave it out "
                    "to check the configs found on this computer. No server is started.",
     "inputSchema": _obj({"config": {"type": "string", "description": "The JSON text of an MCP config (optional)"}})},
    {"name": "scan_tools", "title": "Scan tool definitions",
     "description": "Scan MCP tool definitions (a tools/list result) for warning signs such as hidden instructions and odd parameters. "
                    "Returns a grade and the findings per tool.",
     "inputSchema": _obj({"tools": {"type": "array", "items": {"type": "object"}, "description": "The tool definitions"},
                          "server": {"type": "string", "description": "A name for the server (optional)"}}, ["tools"])},
    {"name": "agent_settings", "title": "Risky agent settings",
     "description": "List the settings of the coding agents on this computer that weaken them or switch Verfy off, with the fix for each. Reads only.",
     "inputSchema": _obj({})},
    {"name": "recent_receipts", "title": "Latest receipts",
     "description": "Show the latest signed receipts of checked calls (time, verdict, tool and rules; arguments are not stored) and whether the chain verifies.",
     "inputSchema": _obj({"count": {"type": "integer", "minimum": 1, "maximum": 100, "description": "How many (default 20)"}})},
]
for _t in TOOLS:
    _t["annotations"] = READ_ONLY


class Bad(ValueError):
    """What the caller sent cannot be used; the message is shown to the agent."""


def _decision(r: dict) -> dict:
    return {"verdict": r["verdict"], "kind": r.get("kind"), "findings": [{"rule": f["rule"], "verdict": f["verdict"], "message": f["message"]} for f in r["findings"]],
            "note": "This is what Verfy's rules say. Verfy's hook or gateway decides when the call is really made."}


def _config_report(args: dict, home: Path, cwd: Path) -> dict:
    text = args.get("config")
    if text is None or text == "":
        found = cfgscan.discover(home, cwd)
    else:
        if not isinstance(text, str) or len(text) > MAX_TEXT:
            raise Bad("`config` must be the JSON text of an MCP config, at most 2 MB")
        try:
            data = json.loads(text)
        except ValueError as e:
            raise Bad(f"`config` is not JSON: {e}") from None
        found = [{"source": "given", "path": "", "servers": cfgscan.servers_in(data)}]
    rep = cfgscan.scan_configs(found)
    return {"configs": rep["configs"], "summary": rep["summary"], "note": rep["note"],
            "servers": [{"server": s["server"], "config": s["config"], "transport": s["transport"], "findings": s["findings"]} for s in rep["servers"]]}


def receipts_summary(args: dict, verfy_home: Path) -> dict:
    """The latest receipts and whether the chain verifies with this computer's key (also used by `verfy report`)."""
    n = args.get("count", 20)
    if not isinstance(n, int) or isinstance(n, bool) or not 1 <= n <= 100:
        raise Bad("`count` must be a whole number from 1 to 100")
    path = verfy_home / "ledger.jsonl"
    if not path.exists():
        return {"count": 0, "receipts": [], "note": "No receipts yet: none are written until Verfy's hook or gateway has checked a call."}
    entries = read_ledger(path)
    out: dict[str, Any] = {"count": len(entries), "receipts": [
        {"seq": r.get("seq"), "at": r.get("issued_at"), "agent": r.get("agent"), "verdict": (r.get("decision") or {}).get("verdict"),
         "status": (r.get("outcome") or {}).get("status"), "tool": "/".join(x for x in ((r.get("action") or {}).get("server"), (r.get("action") or {}).get("tool")) if x),
         "rules": (r.get("decision") or {}).get("rules", [])} for r in entries[-n:] if isinstance(r, dict)]}
    key = verfy_home / "key.json"
    try:
        pub = public_from({"public": json.loads(key.read_text("utf-8"))["public"]})  # the public half only
        res = verify_ledger(entries, pub)
        out["chain"] = {"verified": bool(res["ok"]), "head": res.get("head"), "problems": len(res.get("errors", []))}
    except (OSError, ValueError, KeyError):
        out["chain"] = {"verified": None, "note": "the public key could not be read"}
    return out


def call(name: str, args: dict, *, policy: Callable[[], dict], home: Path, cwd: Path, verfy_home: Path) -> dict:
    """Run one tool and return its result as plain data. Raises Bad for input that cannot be used."""
    if not isinstance(args, dict):
        raise Bad("arguments must be an object")
    if name == "check_line":
        command = args.get("line")
        if not isinstance(command, str) or not command.strip():
            raise Bad("`line` must be the terminal line to check")
        return _decision(check({"tool": "shell", "server": "", "arguments": {"command": command}}, policy(), {}))
    if name == "check_tool_call":
        tool = args.get("tool")
        if not isinstance(tool, str) or not tool:
            raise Bad("`tool` must be the tool's name")
        arguments = args.get("arguments") or {}
        if not isinstance(arguments, dict):
            raise Bad("`arguments` must be an object")
        return _decision(check({"tool": tool, "server": str(args.get("server") or ""), "arguments": arguments}, policy(), {}))
    if name == "scan_mcp_config":
        return _config_report(args, home, cwd)
    if name == "scan_tools":
        tools = args.get("tools")
        if not isinstance(tools, list) or len(json.dumps(tools)) > MAX_TEXT:
            raise Bad("`tools` must be a list of tool definitions, at most 2 MB")
        rep = scan([t for t in tools if isinstance(t, dict)], str(args.get("server") or "server"))
        return {"grade": rep["grade"], "score": rep["score"], "summary": rep["summary"],
                "tools": [{"name": t["name"], "grade": t["grade"], "findings": t["findings"]} for t in rep["tools"]],
                "note": "The scanner finds known warning signs. A clean scan does not mean a tool is safe."}
    if name == "agent_settings":
        found = posturelib.check(home, cwd)
        return {"summary": posturelib.summary(found), "findings": posturelib.as_json(found)["findings"], "read": [str(p) for p in posturelib.files(home, cwd)]}
    if name == "recent_receipts":
        return receipts_summary(args, verfy_home)
    raise Bad(f"unknown tool {name}")


def serve(stdin: TextIO, stdout: TextIO, *, policy: Callable[[], dict], home: Path, cwd: Path, verfy_home: Path) -> int:
    """Answer MCP requests until the input ends. One JSON-RPC message per line, as MCP's stdio transport sends them."""
    def send(mid: Any, result: dict | None = None, error: dict | None = None) -> None:
        msg: dict[str, Any] = {"jsonrpc": "2.0", "id": mid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result if result is not None else {}
        stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
        stdout.flush()

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            send(None, error={"code": -32700, "message": "parse error"})
            continue
        if not isinstance(msg, dict) or "id" not in msg or msg.get("id") is None:
            continue  # a notification (notifications/initialized, cancelled): nothing to answer
        mid, method, params = msg["id"], msg.get("method"), msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "initialize":
            wanted = params.get("protocolVersion")
            send(mid, {"protocolVersion": wanted if isinstance(wanted, str) and wanted else PROTOCOL, "capabilities": {"tools": {}},
                       "serverInfo": {"name": "verfy", "title": "Verfy", "version": __version__},
                       "instructions": "Read-only checks from Verfy: ask before running a risky command, adding an MCP server or trusting a tool. "
                                       "These tools advise; they do not approve anything."})
        elif method == "ping":
            send(mid, {})
        elif method == "tools/list":
            send(mid, {"tools": TOOLS})
        elif method == "tools/call":
            try:
                result = call(str(params.get("name")), params.get("arguments") or {}, policy=policy, home=home, cwd=cwd, verfy_home=verfy_home)
                send(mid, {"content": [{"type": "text", "text": json.dumps(result, indent=1, ensure_ascii=False)}], "structuredContent": result, "isError": False})
            except Bad as e:
                send(mid, {"content": [{"type": "text", "text": str(e)}], "isError": True})
            except Exception as e:  # noqa: BLE001 - one bad call must not end the server
                send(mid, {"content": [{"type": "text", "text": f"Verfy could not answer: {type(e).__name__}"}], "isError": True})
        else:
            send(mid, error={"code": -32601, "message": f"unknown method {method}"})
    return 0


def main(policy: Callable[[], dict], verfy_home: Path) -> int:
    for stream in (sys.stdin, sys.stdout):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")  # MCP is UTF-8, whatever the console's code page is
    return serve(sys.stdin, sys.stdout, policy=policy, home=Path.home(), cwd=Path.cwd(), verfy_home=verfy_home)
