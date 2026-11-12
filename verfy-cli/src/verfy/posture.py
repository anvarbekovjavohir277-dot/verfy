"""``verfy posture``: settings in each coding agent's own config that weaken it or switch Verfy off.

Reads the files only and changes nothing, unless it is asked to fix them (``--fix --write``). Each check is a
documented setting of that agent:

* Claude Code (settings.json): ``permissions.defaultMode`` ``bypassPermissions``, ``disableAllHooks``, a blanket
  ``Bash`` allow rule, ``enableAllProjectMcpServers``.
* Codex CLI (config.toml, also in ``[profiles.*]``): ``approval_policy = "never"``,
  ``sandbox_mode = "danger-full-access"``, ``[features] hooks = false``.
* Gemini CLI (settings.json): ``hooksConfig.enabled = false``, Verfy's hook in ``hooksConfig.disabled``,
  ``general.defaultApprovalMode = "auto_edit"``. YOLO mode can only be turned on from the command line, so it
  cannot be seen here.
* Cursor (hooks.json): a Verfy hook that does not fail closed. Cursor keeps its auto-run setting in its own database,
  which Verfy does not read.
* GitHub Copilot in VS Code (settings.json): ``chat.tools.global.autoApprove``, ``chat.permissions.default``
  ``autoApprove`` or ``autopilot``. https://code.visualstudio.com/docs/copilot/reference/copilot-settings
* GitHub Copilot CLI (~/.copilot/settings.json): ``disableAllHooks``. Its allow-all modes are command-line flags.
* Devin CLI (config.json): ``permission_mode`` ``dangerous``, a blanket ``exec`` allow rule. Devin Desktop keeps its
  own mode in the app. https://docs.devin.ai/cli/reference/configuration/config-file

Severities: high (the agent acts without any check, or Verfy is off), medium (fewer checks than it looks), low.

A fix is the smallest edit that takes the finding away: one key set or removed, or one entry taken out of a list.
A JSON file is written again whole. One with comments (VS Code's, Copilot CLI's, Devin's) is edited in place instead,
for a key at its top level, so the comments stay; any other change to it is left for the person. Codex's config.toml
is edited line by line. Every edited file is parsed again and only written when it then says exactly what was meant.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
from pathlib import Path
from typing import Any

from . import hook as hooks
from . import wrapcfg

RANK = {"low": 1, "medium": 2, "high": 3}
BACKUP = ".verfy-posture-backup"
VSCODE_USER = (("AppData", "Roaming", "Code", "User"), ("Library", "Application Support", "Code", "User"), (".config", "Code", "User"))


def _f(agent: str, path: Path, severity: str, setting: str, why: str, fix: str, edit: tuple, change: str) -> dict:
    return {"agent": agent, "path": str(path), "severity": severity, "setting": setting, "why": why, "fix": fix,
            "edit": edit, "change": change}


def _scan(text: str, on_plain) -> str:
    """Walk JSON text; `on_plain(text, i)` returns how many characters to skip at i outside a string (0: keep one)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            in_str = ch != '"'
            i += 1
            continue
        if ch == '"':
            in_str = True
            out.append(ch)
            i += 1
            continue
        skip = on_plain(text, i)
        if skip:
            i += skip
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def strip_jsonc(text: str) -> str:
    """JSON with // and /* */ comments and trailing commas (VS Code's and Copilot's settings) as plain JSON."""
    def comment(t: str, i: int) -> int:
        if t.startswith("//", i):
            j = t.find("\n", i)
            return (len(t) if j < 0 else j) - i
        if t.startswith("/*", i):
            j = t.find("*/", i + 2)
            return (len(t) if j < 0 else j + 2) - i
        return 0

    def comma(t: str, i: int) -> int:
        return 1 if t[i] == "," and re.match(r"\s*[}\]]", t[i + 1:]) else 0

    return _scan(_scan(text, comment), comma)


def _json(path: Path) -> dict | None:
    try:
        text = path.read_text("utf-8-sig")
    except OSError:
        return None
    for candidate in (text, strip_jsonc(text)):
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        return data if isinstance(data, dict) else None
    return None


def claude(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        out.append(_f("Claude Code", path, "high", "permissions.defaultMode = bypassPermissions",
                      "Claude Code runs every tool without asking you. Verfy's hook still checks each call, but nothing else does.",
                      "Use \"default\" or \"acceptEdits\".",
                      ("set", ("permissions", "defaultMode"), "default"), 'set permissions.defaultMode to "default"'))
    if cfg.get("disableAllHooks") is True:
        out.append(_f("Claude Code", path, "high", "disableAllHooks = true", "No hook runs, so Verfy checks nothing in Claude Code.",
                      "Remove disableAllHooks.", ("del", ("disableAllHooks",)), "remove disableAllHooks"))
    allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
    blanket = [a for a in allow if a.replace(" ", "") in ("Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)", "*")]
    if blanket:
        out.append(_f("Claude Code", path, "medium", f"permissions.allow contains {', '.join(blanket)}",
                      "Every shell command is allowed without a prompt. Verfy still asks about the risky ones it recognises.",
                      "Allow specific commands, such as Bash(npm test).",
                      ("drop", ("permissions", "allow"), tuple(blanket)), f"take {', '.join(blanket)} out of permissions.allow"))
    if cfg.get("enableAllProjectMcpServers") is True:
        out.append(_f("Claude Code", path, "medium", "enableAllProjectMcpServers = true",
                      "A cloned repository's .mcp.json starts its MCP servers without asking you.",
                      "Remove it and approve project servers one by one.",
                      ("del", ("enableAllProjectMcpServers",)), "remove enableAllProjectMcpServers"))
    return out


def codex(path: Path) -> list[dict]:
    try:
        import tomllib
        cfg = tomllib.loads(path.read_text("utf-8-sig"))
    except (ModuleNotFoundError, OSError, ValueError):
        return []
    out = []
    tables = [("", (), cfg)] + [(f"profiles.{k}.", ("profiles", k), v) for k, v in (cfg.get("profiles") or {}).items() if isinstance(v, dict)]
    for prefix, table, t in tables:
        if t.get("approval_policy") == "never":
            out.append(_f("Codex CLI", path, "high", f'{prefix}approval_policy = "never"',
                          "Codex never asks you before it runs a command. Verfy's hook still checks each call, but nothing else does.",
                          'Use "on-request" or "untrusted".',
                          ("toml", table, "approval_policy", "on-request"), f'set {prefix}approval_policy to "on-request"'))
        if t.get("sandbox_mode") == "danger-full-access":
            out.append(_f("Codex CLI", path, "high", f'{prefix}sandbox_mode = "danger-full-access"',
                          "Codex's own sandbox is off: commands can write anywhere and reach any host.",
                          'Use "workspace-write".',
                          ("toml", table, "sandbox_mode", "workspace-write"), f'set {prefix}sandbox_mode to "workspace-write"'))
    features = cfg.get("features") if isinstance(cfg.get("features"), dict) else {}
    if features.get("hooks") is False:
        out.append(_f("Codex CLI", path, "high", "[features] hooks = false", "Codex runs no hooks, so Verfy checks nothing in Codex.",
                      "Remove hooks = false.", ("toml", ("features",), "hooks", None), "remove hooks = false from [features]"))
    return out


def gemini(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    hc = cfg.get("hooksConfig") if isinstance(cfg.get("hooksConfig"), dict) else {}
    if hc.get("enabled") is False:
        out.append(_f("Gemini CLI", path, "high", "hooksConfig.enabled = false", "Gemini CLI runs no hooks, so Verfy checks nothing there.",
                      "Remove it or set it to true.", ("del", ("hooksConfig", "enabled")), "remove hooksConfig.enabled"))
    mine = [d for d in hc.get("disabled") or [] if isinstance(d, str) and (d == "verfy" or "verfy hook" in d)]
    if mine:
        out.append(_f("Gemini CLI", path, "high", "hooksConfig.disabled lists Verfy", "Gemini CLI skips Verfy's hook.",
                      "Take Verfy out of hooksConfig.disabled.",
                      ("drop", ("hooksConfig", "disabled"), tuple(mine)), "take Verfy out of hooksConfig.disabled"))
    general = cfg.get("general") if isinstance(cfg.get("general"), dict) else {}
    if general.get("defaultApprovalMode") == "auto_edit":
        out.append(_f("Gemini CLI", path, "low", 'general.defaultApprovalMode = "auto_edit"',
                      "File edits are approved without asking. Verfy still checks each one.", 'Use "default".',
                      ("set", ("general", "defaultApprovalMode"), "default"), 'set general.defaultApprovalMode to "default"'))
    return out


def cursor(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    for event, entries in (cfg.get("hooks") or {}).items() if isinstance(cfg.get("hooks"), dict) else ():
        for e in entries if isinstance(entries, list) else []:
            if not isinstance(e, dict) or e.get("command") != hooks.CURSOR_COMMAND:
                continue
            wanted = hooks.CURSOR_ENTRY.get(event, {"failClosed": True}).get("failClosed", True)
            if wanted and e.get("failClosed") is not True:
                out.append(_f("Cursor", path, "medium", f"{event}: failClosed is not true",
                              "If Verfy's hook crashes or times out, Cursor lets the action through.", "verfy setup --write sets it.",
                              ("failclosed", event), f"set failClosed to true on Verfy's {event} hook"))
    return out


def vscode(path: Path) -> list[dict]:
    """GitHub Copilot's agent in VS Code: the two settings that approve every tool call."""
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    if cfg.get("chat.tools.global.autoApprove") is True:
        out.append(_f("GitHub Copilot (VS Code)", path, "high", "chat.tools.global.autoApprove = true",
                      "VS Code approves every tool call of its AI agent without asking you. Verfy's hook still checks each call, but nothing else does.",
                      "Remove chat.tools.global.autoApprove.",
                      ("del", ("chat.tools.global.autoApprove",)), "remove chat.tools.global.autoApprove"))
    mode = cfg.get("chat.permissions.default")
    if mode in ("autoApprove", "autopilot"):
        out.append(_f("GitHub Copilot (VS Code)", path, "high", f'chat.permissions.default = "{mode}"',
                      "New agent sessions start with every tool call allowed without asking. Verfy's hook still checks each call, but nothing else does.",
                      'Use "default".', ("set", ("chat.permissions.default",), "default"), 'set chat.permissions.default to "default"'))
    return out


def copilot_cli(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    if cfg.get("disableAllHooks") is True:
        return [_f("GitHub Copilot CLI", path, "high", "disableAllHooks = true",
                   "Copilot CLI runs no hook from your settings or the repository, so Verfy checks nothing there.",
                   "Remove disableAllHooks.", ("del", ("disableAllHooks",)), "remove disableAllHooks")]
    return []


def devin(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    if cfg.get("permission_mode") == "dangerous":
        out.append(_f("Devin", path, "high", 'permission_mode = "dangerous"',
                      "New Devin sessions start in the mode Devin's own config calls dangerous. Verfy's hook still checks each call.",
                      'Use "normal".', ("set", ("permission_mode",), "normal"), 'set permission_mode to "normal"'))
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    blanket = [a for a in perms.get("allow") or [] if isinstance(a, str) and a.replace(" ", "").lower() in ("exec", "exec(*)", "exec(**)")]
    if blanket:
        out.append(_f("Devin", path, "medium", f"permissions.allow contains {', '.join(blanket)}",
                      "Every shell command is allowed without a prompt. Verfy still stops the risky ones it recognises.",
                      "Allow specific commands, such as Exec(npm test).",
                      ("drop", ("permissions", "allow"), tuple(blanket)), f"take {', '.join(blanket)} out of permissions.allow"))
    return out


def _places(home: Path, cwd: Path) -> list:
    return [
        (claude, home / ".claude" / "settings.json"), (claude, cwd / ".claude" / "settings.json"), (claude, cwd / ".claude" / "settings.local.json"),
        (codex, home / ".codex" / "config.toml"), (codex, cwd / ".codex" / "config.toml"),
        (gemini, home / ".gemini" / "settings.json"), (gemini, cwd / ".gemini" / "settings.json"),
        (cursor, home / ".cursor" / "hooks.json"), (cursor, cwd / ".cursor" / "hooks.json"),
        *((vscode, home.joinpath(*d, "settings.json")) for d in VSCODE_USER), (vscode, cwd / ".vscode" / "settings.json"),
        (copilot_cli, home / ".copilot" / "settings.json"),
        (devin, hooks.devin_config_path(False, home=home)), (devin, cwd / ".devin" / "config.json"), (devin, cwd / ".devin" / "config.local.json"),
    ]


def _each(home: Path, cwd: Path):
    """Every (check, file) to read, each file once."""
    seen: set[Path] = set()
    for fn, path in _places(home, cwd):
        try:
            key = path.resolve()
        except OSError:
            continue
        if key not in seen and path.is_file():
            seen.add(key)
            yield fn, path


def files(home: Path, cwd: Path) -> list[Path]:
    """The config files posture reads on this machine, each once."""
    return [path for _fn, path in _each(home, cwd)]


def check(home: Path, cwd: Path) -> list[dict]:
    """Every finding for the agents' user settings and this folder's settings."""
    out: list[dict] = []
    for fn, path in _each(home, cwd):
        out += fn(path)
    return sorted(out, key=lambda f: -RANK[f["severity"]])


def worst(findings: list[dict]) -> int:
    """Exit code: 0 nothing, 1 medium or low, 2 high."""
    top = max((RANK[f["severity"]] for f in findings), default=0)
    return 2 if top >= RANK["high"] else (1 if top else 0)


def summary(findings: list[dict]) -> str:
    if not findings:
        return "no risky setting found"
    n = {s: sum(1 for f in findings if f["severity"] == s) for s in RANK}
    return ", ".join(f"{n[s]} {s}" for s in ("high", "medium", "low") if n[s]) + " (verfy posture)"


def as_json(findings: list[dict]) -> Any:
    return {"v": 1, "findings": [{k: v for k, v in f.items() if k != "edit"} for f in findings]}


# ---------------------------------------------------------------- verfy posture --fix

def _apply_json(cfg: dict, edit: tuple) -> None:
    if edit[0] == "failclosed":
        for e in cfg["hooks"][edit[1]]:
            if isinstance(e, dict) and e.get("command") == hooks.CURSOR_COMMAND:
                e["failClosed"] = True
        return
    node = cfg
    for key in edit[1][:-1]:
        node = node[key]
    last = edit[1][-1]
    if edit[0] == "set":
        node[last] = edit[2]
    elif edit[0] == "del":
        node.pop(last, None)
    else:  # drop
        node[last] = [x for x in node[last] if x not in edit[2]]


def _toml_table(line: str) -> tuple[str, ...] | None:
    """The name of a `[a.b]` table header as its parts; None for any other line, also `[[array]]` headers."""
    m = re.match(r"^\s*\[(?!\[)(.+?)\]\s*(?:#.*)?$", line.rstrip("\r\n"))
    if not m:
        return None
    parts, rest = [], m.group(1).strip()
    while rest:
        p = re.match(r"""\s*(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|([A-Za-z0-9_-]+))\s*(\.|$)""", rest)
        if not p:
            return None
        parts.append(json.loads('"' + p.group(1) + '"') if p.group(1) is not None else (p.group(2) if p.group(2) is not None else p.group(3)))
        rest = rest[p.end():]
    return tuple(parts)


def _toml_edit(text: str, table: tuple[str, ...], key: str, value: str | None) -> str:
    """Set (or with None, remove) one `key = value` line of a table; () is the top of the file."""
    lines = text.splitlines(keepends=True)
    newline = "\r\n" if "\r\n" in text else "\n"
    headers = [i for i, l in enumerate(lines) if re.match(r"^\s*\[", l)]
    if table:
        start = next((i + 1 for i in headers if _toml_table(lines[i]) == table), None)
        if start is None:
            raise ValueError(f"[{'.'.join(table)}] is not written as a table of its own; change it by hand")
    else:
        start = 0
    end = next((i for i in headers if i >= start), len(lines))
    at = next((i for i in range(start, end) if re.match(rf"^\s*{re.escape(key)}\s*=", lines[i])), None)
    if at is None:
        raise ValueError(f"{key} is not written as a line of its own; change it by hand")
    indent = re.match(r"^\s*", lines[at]).group(0)
    lines[at:wrapcfg._value_end(lines, at)] = [] if value is None else [f"{indent}{key} = {wrapcfg.toml_string(value)}{newline}"]
    return "".join(lines)


def _tokens(text: str) -> list[tuple[str, int, int]]:
    """JSON with comments as (kind, start, end) tokens: one of `{}[]:,`, "str" or "lit". Comments and space are left out."""
    out, i, n = [], 0, len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n\ufeff":
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j < 0:
                raise ValueError("a comment that does not end")
            i = j + 2
        elif ch in "{}[]:,":
            out.append((ch, i, i + 1))
            i += 1
        elif ch == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            if j >= n:
                raise ValueError("a string that does not end")
            out.append(("str", i, j + 1))
            i = j + 1
        else:
            m = re.match(r"[-+0-9.eE]+|true|false|null", text[i:])
            if not m:
                raise ValueError(f"unexpected {ch!r}")
            out.append(("lit", i, i + m.end()))
            i += m.end()
    return out


def _jsonc_member(text: str, key: str) -> tuple[int, int, int, int, int] | None:
    """Where a top-level member is: (key start, value start, value end, index of its key token, index after its value),
    or None. Its value can be anything."""
    toks = _tokens(text)
    depth, k = 0, 0
    while k < len(toks):
        kind = toks[k][0]
        if kind in "{[":
            depth += 1
        elif kind in "}]":
            depth -= 1
        elif kind == "str" and depth == 1 and k + 1 < len(toks) and toks[k + 1][0] == ":" and json.loads(text[toks[k][1]:toks[k][2]]) == key:
            v = k + 2
            end, d = v, 0
            while end < len(toks):
                d += 1 if toks[end][0] in "{[" else (-1 if toks[end][0] in "}]" else 0)
                end += 1
                if d == 0:
                    break
            return toks[k][1], toks[v][1], toks[end - 1][2], k, end
        k += 1
    return None


def _jsonc_edit(text: str, edit: tuple) -> str:
    """Set or remove one top-level key in JSON with comments, leaving every other character as it was."""
    op, path = edit[0], edit[1]
    if op not in ("set", "del") or len(path) != 1:
        raise ValueError("it has comments, and only a top-level key is changed in such a file; change it by hand")
    where = _jsonc_member(text, path[0])
    if where is None:
        raise ValueError(f"{path[0]} is not at the top level; change it by hand")
    key_start, value_start, value_end, k, after = where
    if op == "set":
        return text[:value_start] + json.dumps(edit[2], ensure_ascii=False) + text[value_end:]
    toks = _tokens(text)
    start, end = key_start, value_end
    if after < len(toks) and toks[after][0] == ",":
        end = toks[after][2]  # the comma after it, and the spaces after that on the same line
        while end < len(text) and text[end] in " \t":
            end += 1
    elif toks[k - 1][0] == ",":
        start = toks[k - 1][1]  # the last member: the comma before it
    # a member alone on its lines takes its lines with it
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = len(text) if line_end < 0 else line_end + 1
    if not text[line_start:start].strip() and not text[end:line_end].strip():
        start, end = line_start, line_end
    return text[:start] + text[end:]


def _indent(text: str) -> int | str:
    m = re.search(r'\n([ \t]+)"', text)
    return m.group(1) if m else 2


def fix_plan(findings: list[dict]) -> list[dict]:
    """One item per file: {"path", "findings", "state": "fix"|"error", "text" or "error"}. Nothing is written."""
    by_path: dict[str, list[dict]] = {}
    for f in findings:
        by_path.setdefault(f["path"], []).append(f)
    out = []
    for name, fs in by_path.items():
        path = Path(name)
        item: dict = {"path": path, "findings": fs}
        try:
            text = path.read_bytes().decode("utf-8-sig")  # as it is, line endings included
            if path.suffix.lower() == ".toml":
                import tomllib
                expected, new = copy.deepcopy(tomllib.loads(text)), text
                for f in fs:
                    _op, table, key, value = f["edit"]
                    new = _toml_edit(new, table, key, value)
                    node = expected
                    for part in table:
                        node = node[part]
                    if value is None:
                        node.pop(key, None)
                    else:
                        node[key] = value
                if tomllib.loads(new) != expected:
                    raise ValueError("the edited file would not say what was meant; change it by hand")
            else:
                try:
                    cfg = json.loads(text)
                    plain = True
                except ValueError:
                    cfg = json.loads(strip_jsonc(text))  # comments: edited in place below
                    plain = False
                expected = copy.deepcopy(cfg)
                for f in fs:
                    _apply_json(expected, f["edit"])
                if plain:
                    new = json.dumps(expected, indent=_indent(text), ensure_ascii=False) + "\n"
                    if "\r\n" in text:
                        new = new.replace("\n", "\r\n")
                else:
                    new = text
                    for f in fs:
                        new = _jsonc_edit(new, f["edit"])
                    if json.loads(strip_jsonc(new)) != expected:
                        raise ValueError("the edited file would not say what was meant; change it by hand")
            item.update(state="fix", text=new)
        except (OSError, ValueError, KeyError, TypeError) as e:
            item.update(state="error", error=str(e))
        out.append(item)
    return out


def apply_fixes(items: list[dict]) -> list[dict]:
    """Write every planned fix, keeping the old file next to it. One file that fails does not stop the others."""
    for item in items:
        if item["state"] != "fix":
            continue
        path: Path = item["path"]
        try:
            shutil.copyfile(path, path.with_suffix(path.suffix + BACKUP))
            path.write_text(item["text"], "utf-8", newline="")
            item["done"] = True
        except OSError as e:
            item.update(state="error", error=f"cannot write it: {e}")
    return items
