"""``verfy posture``: settings in each coding agent's own config that weaken it or switch Verfy off.

Reads the files only and changes nothing. Each check is a documented setting of that agent:

* Claude Code (settings.json): ``permissions.defaultMode`` ``bypassPermissions``, ``disableAllHooks``, a blanket
  ``Bash`` allow rule, ``enableAllProjectMcpServers``.
* Codex CLI (config.toml, also in ``[profiles.*]``): ``approval_policy = "never"``,
  ``sandbox_mode = "danger-full-access"``, ``[features] hooks = false``.
* Gemini CLI (settings.json): ``hooksConfig.enabled = false``, Verfy's hook in ``hooksConfig.disabled``,
  ``general.defaultApprovalMode = "auto_edit"``. YOLO mode can only be turned on from the command line, so it
  cannot be seen here.
* Cursor (hooks.json): a Verfy hook that does not fail closed. Cursor keeps its auto-run setting in its own database,
  which Verfy does not read.

Severities: high (the agent acts without any check, or Verfy is off), medium (fewer checks than it looks), low.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from . import hook as hooks

RANK = {"low": 1, "medium": 2, "high": 3}


def _f(agent: str, path: Path, severity: str, setting: str, why: str, fix: str) -> dict:
    return {"agent": agent, "path": str(path), "severity": severity, "setting": setting, "why": why, "fix": fix}


def _json(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text("utf-8-sig"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def claude(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        out.append(_f("Claude Code", path, "high", "permissions.defaultMode = bypassPermissions",
                      "Claude Code runs every tool without asking you. Verfy's hook still checks each call, but nothing else does.",
                      "Use \"default\" or \"acceptEdits\"."))
    if cfg.get("disableAllHooks") is True:
        out.append(_f("Claude Code", path, "high", "disableAllHooks = true", "No hook runs, so Verfy checks nothing in Claude Code.",
                      "Remove disableAllHooks."))
    allow = [a for a in perms.get("allow") or [] if isinstance(a, str)]
    blanket = [a for a in allow if a.replace(" ", "") in ("Bash", "Bash(*)", "Bash(*:*)", "Bash(:*)", "*")]
    if blanket:
        out.append(_f("Claude Code", path, "medium", f"permissions.allow contains {', '.join(blanket)}",
                      "Every shell command is allowed without a prompt. Verfy still asks about the risky ones it recognises.",
                      "Allow specific commands, such as Bash(npm test)."))
    if cfg.get("enableAllProjectMcpServers") is True:
        out.append(_f("Claude Code", path, "medium", "enableAllProjectMcpServers = true",
                      "A cloned repository's .mcp.json starts its MCP servers without asking you.",
                      "Remove it and approve project servers one by one."))
    return out


def codex(path: Path) -> list[dict]:
    try:
        import tomllib
        cfg = tomllib.loads(path.read_text("utf-8-sig"))
    except (ModuleNotFoundError, OSError, ValueError):
        return []
    out = []
    tables = [("", cfg)] + [(f"profiles.{k}.", v) for k, v in (cfg.get("profiles") or {}).items() if isinstance(v, dict)]
    for prefix, t in tables:
        if t.get("approval_policy") == "never":
            out.append(_f("Codex CLI", path, "high", f'{prefix}approval_policy = "never"',
                          "Codex never asks you before it runs a command. Verfy's hook still checks each call, but nothing else does.",
                          'Use "on-request" or "untrusted".'))
        if t.get("sandbox_mode") == "danger-full-access":
            out.append(_f("Codex CLI", path, "high", f'{prefix}sandbox_mode = "danger-full-access"',
                          "Codex's own sandbox is off: commands can write anywhere and reach any host.",
                          'Use "workspace-write".'))
    features = cfg.get("features") if isinstance(cfg.get("features"), dict) else {}
    if features.get("hooks") is False:
        out.append(_f("Codex CLI", path, "high", "[features] hooks = false", "Codex runs no hooks, so Verfy checks nothing in Codex.",
                      "Remove hooks = false."))
    return out


def gemini(path: Path) -> list[dict]:
    cfg = _json(path)
    if cfg is None:
        return []
    out = []
    hc = cfg.get("hooksConfig") if isinstance(cfg.get("hooksConfig"), dict) else {}
    if hc.get("enabled") is False:
        out.append(_f("Gemini CLI", path, "high", "hooksConfig.enabled = false", "Gemini CLI runs no hooks, so Verfy checks nothing there.",
                      "Remove it or set it to true."))
    disabled = [d for d in hc.get("disabled") or [] if isinstance(d, str)]
    if any(d == "verfy" or "verfy hook" in d for d in disabled):
        out.append(_f("Gemini CLI", path, "high", "hooksConfig.disabled lists Verfy", "Gemini CLI skips Verfy's hook.",
                      "Take Verfy out of hooksConfig.disabled."))
    general = cfg.get("general") if isinstance(cfg.get("general"), dict) else {}
    if general.get("defaultApprovalMode") == "auto_edit":
        out.append(_f("Gemini CLI", path, "low", 'general.defaultApprovalMode = "auto_edit"',
                      "File edits are approved without asking. Verfy still checks each one.", 'Use "default".'))
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
                              "If Verfy's hook crashes or times out, Cursor lets the action through.", "verfy setup --write sets it."))
    return out


def _places(home: Path, cwd: Path) -> list:
    return [
        (claude, home / ".claude" / "settings.json"), (claude, cwd / ".claude" / "settings.json"), (claude, cwd / ".claude" / "settings.local.json"),
        (codex, home / ".codex" / "config.toml"), (codex, cwd / ".codex" / "config.toml"),
        (gemini, home / ".gemini" / "settings.json"), (gemini, cwd / ".gemini" / "settings.json"),
        (cursor, home / ".cursor" / "hooks.json"), (cursor, cwd / ".cursor" / "hooks.json"),
    ]


def files(home: Path, cwd: Path) -> list[Path]:
    """The config files posture reads on this machine, each once."""
    out, seen = [], set()
    for _fn, path in _places(home, cwd):
        try:
            key = path.resolve()
        except OSError:
            continue
        if key not in seen and path.is_file():
            seen.add(key)
            out.append(path)
    return out


def check(home: Path, cwd: Path) -> list[dict]:
    """Every finding for the agents' user settings and this folder's settings."""
    places = _places(home, cwd)
    seen: set[Path] = set()
    out: list[dict] = []
    for fn, path in places:
        try:
            key = path.resolve()
        except OSError:
            continue
        if key in seen or not path.is_file():
            continue
        seen.add(key)
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
    return {"v": 1, "findings": findings}
