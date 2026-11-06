"""Verfy Lock: pin every MCP tool definition and notice when it changes.

``verfy.lock`` is a JSON file::

    {
      "version": 1,
      "servers": {
        "filesystem": {
          "package": "pkg@1.2.3",              # the pinned package from the config, when it has one
          "server_version": "1.2.3",           # what the server reported when it was locked, for `verfy lock rollback`
          "tools": {
            "read_file": {
              "digest": "sha256:...",          # sha256 of canonical {name, description, inputSchema}, and title, annotations, outputSchema if sent
              "definition": {...},             # the exact definition that was approved, for diffs
              "approved_at": "2026-10-11T09:00:00.000Z",
              "approved_by": "first-use" | "user" | "team"
            }
          }
        }
      }
    }

The digest is recomputed from ``definition`` on every load, so a hand-edited
lock whose digest and definition disagree is rejected instead of trusted.
The file is written deterministically (sorted keys, two-space indent), so
locking the same tools twice gives the same bytes.
"""

from __future__ import annotations

import difflib
import json
import os
import re
from pathlib import Path
from typing import Any, Iterable

from ._util import flatten_strings, real_file
from .canonical import digest
from .fileio import FileLock, atomic_write
from .receipts import now_iso
from .scanner import PINNED_EXTRAS, scan_tool, tool_pin

LOCK_VERSION = 1
APPROVERS = ("first-use", "user", "team")


class LockError(ValueError):
    """verfy.lock is missing required fields or was tampered with."""


def definition(tool: dict) -> dict:
    """The part of a tool definition that Verfy pins."""
    return {
        "name": tool.get("name", ""),
        "description": tool.get("description", "") or "",
        "inputSchema": tool.get("inputSchema", None),
        **{k: tool[k] for k in PINNED_EXTRAS if tool.get(k) is not None},
    }


def empty_lock() -> dict:
    return {"version": LOCK_VERSION, "servers": {}}


def validate_lock(data: Any) -> dict:
    if not isinstance(data, dict) or data.get("version") != LOCK_VERSION or not isinstance(data.get("servers"), dict):
        raise LockError("verfy.lock must be an object with version 1 and a `servers` object")
    for server, entry in data["servers"].items():
        if not isinstance(entry, dict) or not isinstance(entry.get("tools"), dict):
            raise LockError(f"verfy.lock: server `{server}` has no `tools` object")
        for name, t in entry["tools"].items():
            if not isinstance(t, dict) or not isinstance(t.get("digest"), str) or not isinstance(t.get("definition"), dict):
                raise LockError(f"verfy.lock: `{server}/{name}` needs `digest` and `definition`")
            if t["definition"].get("name") != name:
                raise LockError(f"verfy.lock: `{server}/{name}` definition has a different name")
            if tool_pin(t["definition"]) != t["digest"]:
                raise LockError(f"verfy.lock: digest of `{server}/{name}` does not match its definition (edited by hand?)")
            if t.get("approved_by") not in APPROVERS:
                raise LockError(f"verfy.lock: `{server}/{name}` has an unknown approved_by value")
    files = data.get("files")
    if files is not None:
        if not isinstance(files, dict):
            raise LockError("verfy.lock: `files` must be an object")
        for path, f in files.items():
            if not isinstance(f, dict) or not isinstance(f.get("sha256"), str) or not f["sha256"].startswith("sha256:"):
                raise LockError(f"verfy.lock: file `{path}` needs a `sha256`")
            if f.get("approved_by") not in APPROVERS:
                raise LockError(f"verfy.lock: file `{path}` has an unknown approved_by value")
            if path.startswith(("/", "~")) or ".." in path.split("/"):
                raise LockError(f"verfy.lock: file `{path}` must be a path inside the repository")
    return data


def load_lock(path: str | os.PathLike) -> dict:
    p = Path(path)
    if not real_file(p):
        return empty_lock()
    try:
        data = json.loads(p.read_text("utf-8"))
    except json.JSONDecodeError as e:
        raise LockError(f"verfy.lock is not valid JSON: {e}") from None
    return validate_lock(data)


def dumps_lock(lock: dict) -> str:
    return json.dumps(validate_lock(lock), indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def save_lock(path: str | os.PathLike, lock: dict) -> None:
    atomic_write(path, dumps_lock(lock))


def server_pins(lock: dict, server: str) -> dict[str, str] | None:
    """``{tool: digest}`` for a server, or None if the server was never locked."""
    entry = lock["servers"].get(server)
    if entry is None:
        return None
    return {name: t["digest"] for name, t in entry["tools"].items()}


def pin(lock: dict, server: str, tool: dict, by: str, at: str | None = None) -> dict:
    if by not in APPROVERS:
        raise ValueError(f"approved_by must be one of {APPROVERS}")
    d = definition(tool)
    entry = lock["servers"].setdefault(server, {"tools": {}})
    entry["tools"][d["name"]] = {"digest": tool_pin(d), "definition": d, "approved_at": at or now_iso(), "approved_by": by}
    return entry["tools"][d["name"]]


def update(path: str | os.PathLike, fn) -> dict:
    """Read, change and write verfy.lock under a file lock. ``fn(lock)`` mutates it."""
    with FileLock(path):
        lock = load_lock(path)
        fn(lock)
        save_lock(path, lock)
        return lock


# ---------------------------------------------------------------- comparing

def compare(lock: dict, server: str, tools: Iterable[dict]) -> list[dict]:
    """Status of every current and locked tool: ok, drift, new or removed."""
    locked = (lock["servers"].get(server) or {}).get("tools", {})
    out = []
    seen = set()
    for t in tools:
        d = definition(t)
        name = d["name"]
        seen.add(name)
        cur = tool_pin(d)
        if name not in locked:
            out.append({"tool": name, "status": "new", "locked": None, "current": cur})
        elif locked[name]["digest"] == cur:
            out.append({"tool": name, "status": "ok", "locked": cur, "current": cur})
        else:
            out.append({"tool": name, "status": "drift", "locked": locked[name]["digest"], "current": cur})
    for name in sorted(set(locked) - seen):
        out.append({"tool": name, "status": "removed", "locked": locked[name]["digest"], "current": None})
    return out


def _pretty(d: dict | None) -> list[str]:
    if d is None:
        return []
    return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False).splitlines(keepends=True)


def diff(old: dict | None, new: dict | None, label: str = "") -> str:
    """A unified diff of two tool definitions, with invisible characters spelled out."""
    def show(lines: list[str]) -> list[str]:
        out = []
        for ln in lines:
            out.append("".join(f"<U+{ord(ch):04X}>" if (ord(ch) < 32 and ch != "\n") or 0x200B <= ord(ch) <= 0x200F or 0x2060 <= ord(ch) <= 0x206F or 0xE0000 <= ord(ch) <= 0xE007F or ord(ch) == 0xFEFF else ch for ch in ln))
        return out
    return "".join(difflib.unified_diff(show(_pretty(old)), show(_pretty(new)), fromfile=f"locked/{label}", tofile=f"current/{label}"))


RISK_RANK = {"low": 1, "medium": 2, "high": 3}
URL = re.compile(r"https?://[^\s\"'<>)\]]+", re.IGNORECASE)


SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
# words that move data somewhere, and words that turn a sentence into an order for the model
MOVE = re.compile(r"\b(?:send|sends|upload|uploads|copy|copies|forward|forwards|post|posts|share|shares|e-?mail|transmit|exfiltrate|attach|include the (?:contents?|file|output)|pass (?:its|the|their) (?:contents?|output)|report (?:it|them|the))\b", re.IGNORECASE)
ORDER = re.compile(r"\b(?:also|always|must|never|before (?:using|calling|you)|after (?:using|calling|you)|first|instead|make sure|remember to|ignore|do not tell|don'?t tell|every time|whenever)\b", re.IGNORECASE)


def added_sentences(old: str, new: str) -> list[str]:
    """Sentences in ``new`` that were not in ``old`` (whitespace and case ignored)."""
    norm = lambda t: " ".join(t.split()).lower()  # noqa: E731
    before = {norm(x) for x in SENTENCE.split(old) if x.strip()}
    return [x.strip() for x in SENTENCE.split(new) if x.strip() and norm(x) not in before]


def instruction_kind(sentence: str) -> str | None:
    """Whether an added sentence reads as an order to the model, and whether it moves data."""
    if MOVE.search(sentence) and ORDER.search(sentence):
        return "instruction to move data"
    if ORDER.search(sentence) and re.search(r"\b(?:you|the (?:model|assistant|agent))\b|^\s*(?:also|always|never|first|make sure|remember)\b", sentence, re.IGNORECASE):
        return "instruction for the model"
    return None


def _short(text: str, n: int = 90) -> str:
    t = " ".join(text.split())
    return t if len(t) <= n else t[: n - 1] + "…"


def _strings(d: dict | None) -> list[str]:
    if not d:
        return []
    out = [d.get("description") or ""]
    if d.get("inputSchema") is not None:
        # `$schema` / `$id` are JSON Schema metadata, not text the model is asked to follow
        out += [s for p, s in flatten_strings(d["inputSchema"]) if not p.split(".")[-1].startswith("$")]
    return [s for s in out if isinstance(s, str)]


def _params(d: dict | None) -> tuple[dict, set]:
    schema = (d or {}).get("inputSchema")
    if not isinstance(schema, dict):
        return {}, set()
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    req = schema.get("required") if isinstance(schema.get("required"), list) else []
    return props, {str(r) for r in req}


def explain(old: dict | None, new: dict | None) -> dict:
    """What changed between two tool definitions, in words, with a risk level. Deterministic, no model involved.

    Returns ``{"risk": "low"|"medium"|"high", "summary": str, "changes": [{"what", "risk"}]}``.
    """
    if old is None and new is None:
        return {"risk": "low", "summary": "no change", "changes": []}
    if old is None:
        found = scan_tool(new)["findings"]
        bad = [f for f in found if f["severity"] in ("critical", "high")]
        changes = [{"what": "new tool", "risk": "high" if bad else "medium"}]
        changes += [{"what": f"{f['rule']}: {f['message']}", "risk": "high"} for f in bad]
        return _summed(changes)
    if new is None:
        return _summed([{"what": "tool removed", "risk": "low"}])

    changes: list[dict] = []
    for k, label in (("annotations", "annotations changed: a client may act on these, for example read-only hints"), ("title", "title changed"), ("outputSchema", "output schema changed")):
        if old.get(k) != new.get(k):
            changes.append({"what": label, "risk": "medium"})
    if (old.get("description") or "") != (new.get("description") or ""):
        changes.append({"what": "description text changed", "risk": "low"})
        for sentence in added_sentences(old.get("description") or "", new.get("description") or ""):
            kind = instruction_kind(sentence)
            if kind:
                changes.append({"what": f"new {kind}: \"{_short(sentence)}\"", "risk": "high" if kind.startswith("instruction to move data") else "medium"})
    old_urls = {u for s in _strings(old) for u in URL.findall(s)}
    for u in sorted({u for s in _strings(new) for u in URL.findall(s)} - old_urls):
        changes.append({"what": f"new link: {u}", "risk": "medium"})
    old_rules = {(f["rule"]) for f in scan_tool(old)["findings"]}
    for f in scan_tool(new)["findings"]:
        if f["rule"] in old_rules or f["rule"] == "VFY-SCAN-008":
            continue
        risk = {"critical": "high", "high": "high", "medium": "medium"}.get(f["severity"], "low")
        changes.append({"what": f"{f['rule']}: {f['message']}", "risk": risk})
        old_rules.add(f["rule"])

    op, oreq = _params(old)
    np_, nreq = _params(new)
    for p in sorted(set(np_) - set(op)):
        changes.append({"what": f"new parameter `{p}`" + (" (required)" if p in nreq else ""), "risk": "medium"})
    for p in sorted(set(op) - set(np_)):
        changes.append({"what": f"parameter `{p}` removed", "risk": "low"})
    for p in sorted(set(op) & set(np_)):
        a, b = op[p] if isinstance(op[p], dict) else {}, np_[p] if isinstance(np_[p], dict) else {}
        if a.get("type") != b.get("type"):
            changes.append({"what": f"parameter `{p}` type {a.get('type')} -> {b.get('type')}", "risk": "medium"})
        if a.get("enum") != b.get("enum"):
            changes.append({"what": f"parameter `{p}` allowed values changed", "risk": "medium"})
        if (a.get("description") or "") != (b.get("description") or ""):
            changes.append({"what": f"parameter `{p}` description changed", "risk": "low"})
    for p in sorted((nreq - oreq) & set(op)):
        changes.append({"what": f"parameter `{p}` is now required", "risk": "medium"})
    if not changes:
        changes.append({"what": "schema details changed", "risk": "low"})
    return _summed(changes)


def _summed(changes: list[dict]) -> dict:
    risk = max((c["risk"] for c in changes), key=lambda r: RISK_RANK[r], default="low")
    if risk == "low" and all(c["what"].endswith("description changed") or c["what"] == "description text changed" for c in changes):
        summary = "only wording changed: no new link, parameter or instruction pattern"
    else:
        summary = "; ".join(c["what"] for c in changes if c["risk"] == risk)
    return {"risk": risk, "summary": summary, "changes": changes}


def seen_path(home: Path, server: str) -> Path:
    return home / "seen" / f"{safe_name(server)}.json"


def safe_name(server: str) -> str:
    """A file name for a server name, so `../x` cannot escape the folder."""
    keep = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in server).strip(".")
    return keep or "server"


def save_seen(home: Path, server: str, tools: list[dict]) -> None:
    """Remember the definitions a server last served, so `verfy lock approve` can diff them."""
    defs = {definition(t)["name"]: definition(t) for t in tools if isinstance(t, dict)}
    atomic_write(seen_path(home, server), json.dumps({"server": server, "seen_at": now_iso(), "tools": defs}, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def load_seen(home: Path, server: str) -> dict[str, dict]:
    p = seen_path(home, server)
    if not p.exists():
        return {}
    data = json.loads(p.read_text("utf-8"))
    return data.get("tools", {}) if isinstance(data, dict) else {}


def lock_digest(lock: dict) -> str:
    return digest(lock)
