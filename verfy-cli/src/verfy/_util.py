"""Small helpers shared by the scanner and the pre-check.

Every function here has a twin in ``web/verfy-engine.js``. Keep them in step:
the parity tests run the same fixtures through both.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Iterable

PATTERNS: dict = json.loads((Path(__file__).parent / "data" / "patterns.json").read_text("utf-8"))

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
VERDICT_RANK = {"deny": 2, "ask": 1, "allow": 0}


def real_file(p: Path) -> bool:
    """A file with something in it. On Linux the sandbox runtime holds a missing file closed: a device inside the sandbox,
    an empty file outside it while the sandbox runs. Neither is the user's file, so both count as missing."""
    try:
        return p.is_file() and p.stat().st_size > 0
    except OSError:
        return False


@lru_cache(maxsize=None)
def rx(pattern: str, flags: str = "") -> "re.Pattern[str]":
    f = 0
    if "i" in flags:
        f |= re.IGNORECASE
    return re.compile(pattern, f)


def words(name: str) -> list[str]:
    """Split ``readFile``, ``read_file`` and ``read-file`` into lowercase words."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return [w for w in re.split(r"[^A-Za-z0-9]+", s.lower()) if w]


def is_invisible(cp: int) -> bool:
    return any(a <= cp <= b for a, b in PATTERNS["invisible_ranges"])


def entropy(v: str) -> float:
    if not v:
        return 0.0
    counts: dict[str, int] = {}
    for ch in v:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(v)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def scan_secrets(text: str, every: bool = False) -> list[dict]:
    """Secrets in ``text``: the first hit per rule, or every hit with ``every=True``."""
    out: list[dict] = []
    if not text or not isinstance(text, str):
        return out
    seen = set()
    for rid, label, pat, flags, sev in PATTERNS["secrets"]:
        for m in rx(pat, flags).finditer(text):
            value = m.group(1) if m.groups() and m.group(1) is not None else m.group(0)
            low = value.lower()
            if any(h in low for h in PATTERNS["placeholders"]):
                continue
            if sev == "medium" and entropy(value) < 3.0:
                continue
            if rid in seen and not every:
                continue
            seen.add(rid)
            out.append({"id": rid, "label": label, "severity": sev, "start": m.start(), "end": m.end()})
    return out


def secret_spans(text: str) -> list[dict]:
    """Every secret in ``text``, in order, with overlapping hits merged into the first."""
    out: list[dict] = []
    for h in sorted(scan_secrets(text, every=True), key=lambda h: (h["start"], -h["end"])):
        if out and h["start"] < out[-1]["end"]:
            out[-1]["end"] = max(out[-1]["end"], h["end"])
        else:
            out.append(h)
    return out


def redact(text: str) -> str:
    for h in reversed(secret_spans(text)):
        text = text[: h["start"]] + "[REDACTED:" + h["id"] + "]" + text[h["end"]:]
    return text


def redact_value(v: Any) -> Any:
    if isinstance(v, str):
        return redact(v) if scan_secrets(v) else v
    if isinstance(v, list):
        return [redact_value(x) for x in v]
    if isinstance(v, dict):
        return {k: redact_value(x) for k, x in v.items()}
    return v


BINARY_KEYS = ("data", "blob")


def redact_output(v: Any, key: str = "") -> tuple[Any, int]:
    """Redact secrets in an MCP result. Returns the copy and how many secrets were hidden.

    Base64 payloads (``data`` of images and audio, ``blob`` of resources) are left alone.
    """
    if isinstance(v, str):
        if key in BINARY_KEYS:
            return v, 0
        n = len(secret_spans(v))
        return (redact(v), n) if n else (v, 0)
    if isinstance(v, list):
        out, total = [], 0
        for x in v:
            y, n = redact_output(x, key)
            out.append(y)
            total += n
        return out, total
    if isinstance(v, dict):
        out_d, total = {}, 0
        for k, x in v.items():
            y, n = redact_output(x, k)
            out_d[k] = y
            total += n
        return out_d, total
    return v, 0


def flatten_strings(v: Any, path: str = "") -> list[tuple[str, str]]:
    """Every string inside ``v`` with its dotted key path."""
    out: list[tuple[str, str]] = []
    if isinstance(v, str):
        out.append((path, v))
    elif isinstance(v, list):
        for i, x in enumerate(v):
            out.extend(flatten_strings(x, f"{path}[{i}]"))
    elif isinstance(v, dict):
        for k, x in v.items():
            out.extend(flatten_strings(x, f"{path}.{k}" if path else k))
    return out


# ---------------------------------------------------------------- paths

def normpath(p: str) -> str:
    """POSIX normpath that never touches the real filesystem."""
    absolute = p.startswith("/")
    parts: list[str] = []
    for part in p.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts and parts[-1] != "..":
                parts.pop()
            elif not absolute:
                parts.append("..")
            continue
        parts.append(part)
    s = "/".join(parts)
    return ("/" + s) if absolute else (s or ".")


_DRIVE = re.compile(r"^([A-Za-z]):(?=/|$)")


def to_posix(p: str) -> str:
    """Windows paths (``C:/Users/x``, also with backslashes) as Git Bash writes them: ``/c/Users/x``."""
    p = p.replace("\\", "/")
    m = _DRIVE.match(p)
    return "/" + m.group(1).lower() + p[2:] if m else p


def resolve(p: str, home: str, cwd: str) -> str:
    p = to_posix((p or "").strip())
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    elif p.startswith("$HOME") or p.startswith("${HOME}"):
        p = home + p[(5 if p.startswith("$HOME") else 7):]
    if not p.startswith("/"):
        p = cwd.rstrip("/") + "/" + p
    return normpath(p)


def is_within(path: str, root: str) -> bool:
    root = root.rstrip("/") or "/"
    return path == root or path.startswith(root + "/") or root == "/"


@lru_cache(maxsize=None)
def _glob_rx(pattern: str) -> "re.Pattern[str]":
    i, out = 0, ""
    if pattern.startswith("**/"):
        out = "(?:.*/)?"
        i = 3
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("/**/", i):
            out += "/(?:.*/)?"
            i += 4
            continue
        if pattern.startswith("/**", i) and i + 3 == len(pattern):
            out += "(?:/.*)?"
            i += 3
            continue
        if pattern.startswith("**", i):
            out += ".*"
            i += 2
            continue
        if c == "*":
            out += "[^/]*"
        elif c == "?":
            out += "[^/]"
        else:
            out += re.escape(c)
        i += 1
    return re.compile("^" + out + "$")


def glob_match(pattern: str, path: str, home: str) -> bool:
    if pattern == "~" or pattern.startswith("~/"):
        pattern = home + pattern[1:]
    if pattern.startswith("**/"):
        return bool(_glob_rx(pattern).match(path.lstrip("/"))) or bool(_glob_rx(pattern).match(path))
    return bool(_glob_rx(pattern).match(path))


def first_match(patterns: Iterable[str], path: str, home: str) -> str | None:
    for pat in patterns or []:
        if glob_match(pat, path, home):
            return pat
    return None


def name_match(pattern: str, name: str) -> bool:
    """Glob for tool names (``*`` matches anything, including ``/``)."""
    return bool(re.match("^" + re.escape(pattern).replace(r"\*", ".*") + "$", name or ""))


def host_match(pattern: str, host: str) -> bool:
    pattern, host = pattern.lower(), host.lower()
    if pattern.startswith("*."):
        return host == pattern[2:] or host.endswith(pattern[1:])
    return host == pattern
