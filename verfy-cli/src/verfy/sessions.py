"""Which agent sessions have read outside text.

A web page or a tool's answer can carry instructions for the agent (prompt injection). No rule can tell whether the
agent obeyed them, but it can notice the order of events: once a session has read text from outside, what it does next
may come from that text. With ``session.after_outside_text`` on, the actions that can do harm from then on (the network,
messages, payments, deletes) need a person. It is a fact about the session, so no model has to judge the text.

The hook runs as a new process for every tool call, so the state is a file in ``~/.verfy/sessions``, named by a hash of
the session id. Only the tool's name is kept, never its arguments.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from ._util import name_match
from .fileio import atomic_write

KEEP_SECONDS = 7 * 86400


def _file(home: Path, session: str) -> Path:
    return home / "sessions" / (hashlib.sha256(session.encode("utf-8")).hexdigest()[:32] + ".json")


def source_of(home: Path, session: str) -> str | None:
    """What first brought outside text into this session, or None."""
    try:
        return str(json.loads(_file(home, session).read_text("utf-8"))["source"])
    except (OSError, ValueError, KeyError, TypeError):
        return None


def mark(home: Path, session: str, source: str, now: float | None = None) -> None:
    now = time.time() if now is None else now
    path = _file(home, session)
    if not path.exists():
        atomic_write(path, json.dumps({"source": source, "at": now}) + "\n", mode=0o600)
    for old in path.parent.glob("*.json"):
        try:
            if now - old.stat().st_mtime > KEEP_SECONDS:
                old.unlink()
        except OSError:
            pass


def trusted(policy: dict, full: str, tool: str) -> bool:
    return any(name_match(p, full) or name_match(p, tool) for p in (policy.get("tools") or {}).get("trust", []))


def outside_text(action: dict, decision: dict, policy: dict) -> str | None:
    """The tool's name if this call brings text from outside into the session, otherwise None."""
    tool = str(action.get("tool") or "")
    server = str(action.get("server") or "")
    full = f"{server}/{tool}" if server else tool
    if trusted(policy, full, tool):
        return None
    if decision.get("reaches_network") or server not in ("", "claude-code"):  # what an MCP server answers is outside text
        return full
    sources = (policy.get("session") or {}).get("sources", [])
    return tool if any(name_match(p, tool) for p in sources) else None
