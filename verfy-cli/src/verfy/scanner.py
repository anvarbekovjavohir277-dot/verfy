"""Scan MCP tool definitions before an agent is allowed to see them.

Input is whatever ``tools/list`` returned: a JSON-RPC response, a
``{"tools": [...]}`` object or a bare list. Output is a report with a 0-100
score and an A-F grade per tool and for the whole server (the weakest tool
sets the server grade), the findings behind every point lost, the tool's
capabilities and a ``sha256`` pin of its definition.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from ._util import PATTERNS, SEVERITY_RANK, flatten_strings, is_invisible, rx, scan_secrets, words
from .canonical import digest

WEIGHTS = {"critical": 45, "high": 20, "medium": 8, "low": 3, "info": 0}
VERSION = "verfy.scan/1"


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def extract_tools(data: Any) -> list[dict]:
    if isinstance(data, dict):
        if isinstance(data.get("result"), dict):
            data = data["result"]
        if "tools" in data:
            data = data["tools"]
        elif "name" in data:
            data = [data]
    if not isinstance(data, list):
        raise ValueError("expected a tools/list result, {\"tools\": [...]} or a list of tools")
    tools = [t for t in data if isinstance(t, dict)]
    if len(tools) != len(data):
        raise ValueError("every tool must be a JSON object")
    return tools


# pinned when a server sends them: clients act on annotations, and a title or output schema can reach the model
PINNED_EXTRAS = ("title", "annotations", "outputSchema")


def tool_pin(tool: dict) -> str:
    return digest({
        "name": tool.get("name", ""),
        "description": tool.get("description", "") or "",
        "inputSchema": tool.get("inputSchema", None),
        **{k: tool[k] for k in PINNED_EXTRAS if tool.get(k) is not None},
    })


def prompt_tool(prompt: dict) -> dict:
    """An MCP prompt as a lock entry, `prompt:<name>`. A client shows it to the model just as it shows a tool."""
    args = [a for a in prompt.get("arguments") or [] if isinstance(a, dict) and isinstance(a.get("name"), str)]
    return {
        "name": "prompt:" + str(prompt.get("name", "")),
        "description": prompt.get("description", "") or "",
        "inputSchema": {"type": "object", "properties": {a["name"]: {"type": "string", "description": a.get("description", "") or ""} for a in args},
                        "required": [a["name"] for a in args if a.get("required") is True]},
    }


def capabilities(tool: dict) -> list[str]:
    name_words = set(words(tool.get("name", "")))
    joined = "_".join(words(tool.get("name", "")))
    props = (tool.get("inputSchema") or {}).get("properties") or {}
    params = {str(k).lower() for k in props} if isinstance(props, dict) else set()
    caps = []
    for cap, spec in PATTERNS["capabilities"].items():
        hit = any(w in name_words or w == joined for w in spec["name"]) or any(p in params for p in spec["params"])
        if cap in ("fs_write", "fs_read") and hit and not spec["params"]:
            path_like = params & set(PATTERNS["path_keys"])
            hit = bool(path_like) or "file" in name_words or "files" in name_words or "directory" in name_words
        if hit:
            caps.append(cap)
    return caps


def _texts(tool: dict) -> list[tuple[str, str]]:
    out = []
    for key in ("title", "description"):
        if isinstance(tool.get(key), str):
            out.append((key, tool[key]))
    if tool.get("inputSchema") is not None:
        out.extend(("inputSchema." + p, s) for p, s in flatten_strings(tool["inputSchema"]) if not p.endswith(".type") and p != "type")
    for key in ("annotations", "outputSchema"):
        if tool.get(key) is not None:
            out.extend((key + "." + p, s) for p, s in flatten_strings(tool[key]) if not p.endswith(".type") and p != "type")
    return out


LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
PLAIN_ASCII = re.compile(r"^[\t\r\n\x20-\x7e]+$")


def _variants(text: str) -> list[str]:
    """The same text with common disguises taken off: invisible characters, Unicode tags, leet, spaced letters, base64."""
    out = []
    plain = "".join(chr(ord(c) - 0xE0000) if 0xE0020 <= ord(c) <= 0xE007E else c for c in text if not is_invisible(ord(c)) or 0xE0020 <= ord(c) <= 0xE007E)
    if plain != text:
        out.append(plain)
    out.append(plain.translate(LEET))
    spaced = re.sub(r"(?<![A-Za-z])[A-Za-z](?: {1,2}[A-Za-z]){4,}(?![A-Za-z])", lambda m: m.group(0).replace("  ", "\0").replace(" ", "").replace("\0", " "), plain)
    if spaced != plain:
        out.append(spaced)
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", plain):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True).decode("ascii")
        except (binascii.Error, ValueError):
            continue
        if PLAIN_ASCII.match(raw):
            out.append(raw)
    return [v for v in dict.fromkeys(out) if v != text]


# "Do not include API keys" is the opposite of asking for them: a match right after a negation is skipped
NEGATION = re.compile(r"\b(?:do\s+not|don'?t|never|must\s+not|should\s+not|shouldn'?t|avoid|no)\s+(?:[A-Za-z']+\s+){0,2}$", re.IGNORECASE)


def _affirmed(pattern: "re.Pattern[str]", text: str) -> bool:
    for m in pattern.finditer(text):
        before = re.split(r"[.!?\n]", text[max(0, m.start() - 40):m.start()])[-1]
        if not NEGATION.search(before):
            return True
    return False


def text_findings(text: str, where: str = "") -> list[dict]:
    """Findings for one piece of text a model reads: hidden instructions, invisible characters, blobs, secrets, links."""
    out: list[dict] = []
    for rule, sev, pat, flags, msg in PATTERNS["scan_text"]:
        if _affirmed(rx(pat, flags), text):
            out.append({"rule": rule, "severity": sev, "message": msg, "where": where})
    for variant in _variants(text):
        for rule, sev, pat, flags, msg in PATTERNS["scan_text"]:
            if sev in ("critical", "high") and _affirmed(rx(pat, flags), variant) and not _affirmed(rx(pat, flags), text):
                out.append({"rule": rule, "severity": sev, "message": msg + " It was disguised.", "where": where})
    bad = sorted({f"U+{ord(ch):04X}" for ch in text if is_invisible(ord(ch))})
    if bad:
        out.append({"rule": "VFY-SCAN-003", "severity": "high", "message": "Contains invisible characters (" + ", ".join(bad[:4]) + ") that can hide text from people.", "where": where})
    if rx(r"[A-Za-z0-9+/]{60,}={0,2}").search(text) or rx(r"(?:[0-9a-fA-F]{2}){40,}").search(text):
        out.append({"rule": "VFY-SCAN-005", "severity": "medium", "message": "Contains a long encoded blob that people cannot read.", "where": where})
    for s in scan_secrets(text):
        out.append({"rule": "VFY-SCAN-013", "severity": "high", "message": f"Contains a {s['label']}.", "where": where})
    if rx(r"https?://", "i").search(text):
        out.append({"rule": "VFY-SCAN-008", "severity": "low", "message": "Links to an outside URL, which can change after review.", "where": where})
    return out


def scan_tool(tool: dict, all_names: list[str] | None = None, pins: dict | None = None) -> dict:
    findings: list[dict] = []

    def add(rule: str, severity: str, message: str, where: str = "") -> None:
        for f in findings:
            if f["rule"] == rule and f["where"] == where and f["message"] == message:
                return
        findings.append({"rule": rule, "severity": severity, "message": message, "where": where})

    name = tool.get("name", "")
    texts = _texts(tool)
    if isinstance(name, str) and re.search(r"[A-Za-z]", name) and any(ord(c) > 127 for c in name):
        add("VFY-SCAN-016", "high", "The tool name mixes Latin with look-alike letters from another script.", "name")

    for where, text in texts:
        for f in text_findings(text, where):
            add(f["rule"], f["severity"], f["message"], f["where"])

    desc = tool.get("description") or ""
    if isinstance(desc, str):
        if len(desc) > 1500:
            add("VFY-SCAN-010", "low", f"Description is {len(desc)} characters long, a common place to hide instructions.", "description")
        if not desc.strip():
            add("VFY-SCAN-009", "low", "Has no description, so people cannot tell what it does.", "description")

    schema = tool.get("inputSchema")
    if not isinstance(schema, dict):
        add("VFY-SCAN-007", "low", "Has no input schema, so any arguments are accepted.", "inputSchema")
    else:
        if schema.get("type") != "object":
            add("VFY-SCAN-007", "low", "Input schema is not an object.", "inputSchema")
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        required = schema.get("required") if isinstance(schema.get("required"), list) else []
        for p in props:
            if re.search(r"ssh|private[_-]?key|seed[_-]?phrase|mnemonic|contents?[_-]of", str(p), re.I):
                add("VFY-SCAN-017", "high", f"The parameter name `{p}` asks for a key or the contents of a file.", f"inputSchema.properties.{p}")
            if str(p).lower() in PATTERNS["exfil_params"] and p in required:
                add("VFY-SCAN-006", "medium", f"Requires a free-form `{p}` parameter, a known side channel for leaking data.", f"inputSchema.properties.{p}")
        caps_now = capabilities(tool)
        if "exec" in caps_now:
            for p, spec in props.items():
                if str(p).lower() in PATTERNS["command_keys"] and isinstance(spec, dict) and spec.get("type") == "string" and not spec.get("enum") and not spec.get("pattern"):
                    add("VFY-SCAN-011", "low", f"Runs any command passed in `{p}`. Pair it with a pre-check policy.", f"inputSchema.properties.{p}")

    caps = capabilities(tool)
    ann = tool.get("annotations") if isinstance(tool.get("annotations"), dict) else {}
    if ann.get("readOnlyHint") is True and set(caps) & {"exec", "fs_write", "payment", "messaging"}:
        add("VFY-SCAN-012", "medium", "Says it is read-only, but its name and parameters say it changes things.", "annotations.readOnlyHint")
    if ann.get("destructiveHint") is False and set(words(name)) & set(PATTERNS["verbs"]["delete"]):
        add("VFY-SCAN-012", "medium", "Says it is not destructive, but its name says it deletes.", "annotations.destructiveHint")

    pin = tool_pin(tool)
    pin_status = None
    if pins is not None:
        known = pins.get(name)
        if known is None:
            pin_status = "new"
        elif known == pin:
            pin_status = "ok"
        else:
            pin_status = "changed"
            add("VFY-SCAN-014", "critical", "Its definition changed since you approved it (possible rug pull).", "")

    score = 100
    for f in findings:
        score -= WEIGHTS[f["severity"]]
    score = max(0, score)
    if any(f["severity"] == "critical" for f in findings):
        score = min(score, 39)
    findings.sort(key=lambda f: -SEVERITY_RANK[f["severity"]])
    return {
        "name": name,
        "sha256": pin,
        "pin": pin_status,
        "capabilities": caps,
        "score": score,
        "grade": grade(score),
        "findings": findings,
    }


def scan(data: Any, server: str = "server", pins: dict | None = None) -> dict:
    tools = extract_tools(data)
    names = [str(t.get("name", "")) for t in tools]
    results = [scan_tool(t, names, pins) for t in tools]
    seen: set[str] = set()
    for r in results:
        if r["name"] in seen:
            r["findings"].append({"rule": "VFY-SCAN-015", "severity": "medium", "message": "Another tool on this server has the same name.", "where": "name"})
            r["score"] = max(0, r["score"] - WEIGHTS["medium"])
            r["grade"] = grade(r["score"])
        seen.add(r["name"])
    summary = {s: 0 for s in ("critical", "high", "medium", "low")}
    for r in results:
        for f in r["findings"]:
            if f["severity"] in summary:
                summary[f["severity"]] += 1
    score = min((r["score"] for r in results), default=100)
    removed = sorted(set(pins) - set(names)) if pins is not None else []
    return {
        "v": VERSION,
        "server": server,
        "score": score,
        "grade": grade(score),
        "tool_count": len(results),
        "summary": summary,
        "tools": results,
        "removed_tools": removed,
    }


def unsafe_tools(report: dict) -> set[str]:
    """Tools a gateway should hide: any critical finding or a changed pin."""
    return {t["name"] for t in report["tools"] if t["pin"] == "changed" or any(f["severity"] == "critical" for f in t["findings"])}
