"""Put the MCP servers in an agent's config behind the Verfy gateway: ``verfy wrap`` and ``verfy setup``.

A local server's launch becomes ``verfy proxy --name NAME -- <the old command>``. A remote one becomes the gateway
in front of ``verfy bridge --url URL``, with its headers moved to the environment, so a key is never on a command
line. JSON configs (Claude Code, Cursor, VS Code, Gemini CLI, Copilot CLI, Windsurf, Claude Desktop) are rewritten
whole. Codex CLI's config.toml is edited in place, line by line, and the result is parsed again and compared with
what was meant before anything is written, so comments and the rest of the file stay as they were.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

from . import discover as cfgscan
from .bridge import HEADERS_ENV

REMOTE_KEYS = ("url", "serverUrl", "httpUrl", "type", "transport", "headers", "http_headers", "env_http_headers", "bearer_token_env_var")


def bridge_headers(spec: dict) -> dict[str, str]:
    """A remote server's headers as written in its config, with ${VAR} left for the bridge to fill in."""
    headers = {str(k): str(v) for key in ("headers", "http_headers") for k, v in (spec.get(key) or {}).items()}
    headers.update({str(k): "${" + str(var) + "}" for k, var in (spec.get("env_http_headers") or {}).items()})
    if spec.get("bearer_token_env_var"):
        headers["Authorization"] = "Bearer ${" + str(spec["bearer_token_env_var"]) + "}"
    return headers


def is_wrapped(spec: dict, exe: str = "verfy") -> bool:
    command = str(spec.get("command") or "")
    return command in ("verfy", exe) or Path(command).name.lower().removesuffix(".exe") == "verfy"


def wrap_spec(spec: dict, name: str, exe: str, extra: list[str], skip_signin: bool = False) -> str | None:
    """Change one server's entry in place. Returns why it was left alone, or None when it was wrapped."""
    if is_wrapped(spec, exe):
        return "already behind the gateway"
    if "command" not in spec:
        url = cfgscan.server_url(spec)
        if not url:
            return "no command and no address"
        headers = bridge_headers(spec)
        if skip_signin and not headers:
            # no key in the config: the client most likely signs in with OAuth, which the bridge cannot do yet
            return "signs in with OAuth, which the gateway does not support yet (verfy proxy --url when it has a key)"
        for key in REMOTE_KEYS:
            spec.pop(key, None)
        spec["command"] = exe
        spec["args"] = ["proxy", "--name", name, *extra, "--", exe, "bridge", "--url", str(url)]
        if headers:
            spec["env"] = {**(spec.get("env") or {}), HEADERS_ENV: json.dumps(headers)}
        return None
    args = spec.get("args") or []
    if not isinstance(args, list):
        return "its args are not a list"
    spec["args"] = ["proxy", "--name", name, *extra, "--", str(spec["command"]), *[str(a) for a in args]]
    spec["command"] = exe
    return None


def servers_key(cfg: dict) -> str | None:
    for key in ("mcpServers", "servers", "mcp_servers"):
        if isinstance(cfg.get(key), dict):
            return key
    return None


def wrap_text(path: Path, text: str, exe: str, extra: list[str] | None = None, skip_signin: bool = False) -> tuple[str, dict, list[str], dict[str, str]]:
    """The config with its servers wrapped. Returns (new text, new config, wrapped names, {name: why it was left})."""
    extra = extra or []
    if path.suffix.lower() == ".toml":
        return _wrap_toml(text, exe, extra, skip_signin)
    cfg = json.loads(text.removeprefix("﻿"))
    if not isinstance(cfg, dict):
        raise ValueError(f"{path} does not hold a JSON object")
    key = servers_key(cfg)
    wrapped, left = [], {}
    for name, spec in (cfg.get(key) or {}).items() if key else ():
        if not isinstance(spec, dict):
            continue
        why = wrap_spec(spec, name, exe, extra, skip_signin)
        if why:
            left[name] = why
        else:
            wrapped.append(name)
    return json.dumps(cfg, indent=2, ensure_ascii=False) + "\n", cfg, wrapped, left


# ---------------------------------------------------------------- Codex CLI's config.toml

def toml_string(s: str) -> str:
    """A TOML basic string. JSON's escapes are TOML's, except that TOML also wants DEL escaped."""
    return json.dumps(s, ensure_ascii=False).replace("\x7f", "\\u007F")


def _header_name(line: str) -> str | None:
    """The server name of a `[mcp_servers.NAME]` header, or None."""
    m = re.match(r"""^\s*\[\s*mcp_servers\s*\.\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*\]\s*(?:#.*)?$""", line)
    if not m:
        return None
    if m.group(1) is not None:
        return json.loads('"' + m.group(1) + '"')
    return m.group(2) if m.group(2) is not None else m.group(3)


def _value_end(lines: list[str], i: int) -> int:
    """The index after the last line of the `key = value` that starts on line i (an array may span lines)."""
    depth, quote = 0, None
    j = i
    while j < len(lines):
        line = lines[j]
        k = line.index("=") + 1 if j == i else 0
        while k < len(line):
            ch = line[k]
            if quote:
                if line.startswith(quote * 3, k):
                    raise ValueError("a multi-line string in a server's command or args")
                if ch == "\\" and quote == '"':
                    k += 2
                    continue
                if ch == quote:
                    quote = None
            elif ch in "\"'":
                if line.startswith(ch * 3, k):
                    raise ValueError("a multi-line string in a server's command or args")
                quote = ch
            elif ch == "#":
                break
            elif ch in "[{":
                depth += 1
            elif ch in "]}":
                depth -= 1
            k += 1
        j += 1
        if depth <= 0 and quote is None:
            return j
    raise ValueError("a value that does not end")


def _wrap_toml(text: str, exe: str, extra: list[str], skip_signin: bool) -> tuple[str, dict, list[str], dict[str, str]]:
    try:
        import tomllib
    except ModuleNotFoundError:
        raise ValueError("editing Codex CLI's config.toml needs Python 3.11 or newer") from None
    text = text.removeprefix("﻿")
    before = tomllib.loads(text)
    servers = before.get("mcp_servers") if isinstance(before.get("mcp_servers"), dict) else {}
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    headers = {_header_name(l): i for i, l in enumerate(lines) if _header_name(l) is not None}
    expected = copy.deepcopy(before)
    wrapped, left = [], {}
    edits: list[tuple[int, int, list[str]]] = []  # (first line, end line, new lines) per server, applied bottom up
    for name, spec in servers.items():
        if not isinstance(spec, dict):
            continue
        if is_wrapped(spec, exe):
            left[name] = "already behind the gateway"
            continue
        if "command" not in spec:
            left[name] = "remote: Codex keeps it in config.toml, so put it behind the gateway by hand with verfy proxy --url"
            continue
        if name not in headers:
            left[name] = "not written as a [mcp_servers.NAME] table, so Verfy does not edit it"
            continue
        new = dict(spec)
        why = wrap_spec(new, name, exe, extra, skip_signin)
        if why:
            left[name] = why
            continue
        start = headers[name]
        end = next((i for i in range(start + 1, len(lines)) if re.match(r"^\s*\[", lines[i])), len(lines))
        body, i = [], start + 1
        while i < end:
            if re.match(r"^\s*(?:command|args)\s*=", lines[i]):
                i = _value_end(lines, i)
                continue
            body.append(lines[i])
            i += 1
        head = lines[start] if lines[start].endswith(("\n", "\r")) else lines[start] + newline
        mine = [f"command = {toml_string(new['command'])}{newline}", f"args = [{', '.join(toml_string(a) for a in new['args'])}]{newline}"]
        edits.append((start, end, [head, *mine, *body]))
        expected["mcp_servers"][name] = new
        wrapped.append(name)
    for start, end, new_lines in sorted(edits, reverse=True):
        lines[start:end] = new_lines
    out = "".join(lines)
    if tomllib.loads(out) != expected:
        raise ValueError("the edited config.toml would not say what was meant, so it was left alone")
    return out, expected, wrapped, left


def hidden_values(v: Any, key: str = "") -> Any:
    """The config as printed: a preview must not put keys in a terminal or a CI log."""
    if isinstance(v, dict):
        return {k: ("***" if key in ("env", "headers", "http_headers") and not isinstance(x, (dict, list)) else hidden_values(x, k)) for k, x in v.items()}
    return [hidden_values(x, key) for x in v] if isinstance(v, list) else v
