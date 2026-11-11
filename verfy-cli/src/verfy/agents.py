"""Every coding agent on this machine, and what ``verfy setup`` does for each in one go.

For each agent it finds, setup adds Verfy's hook (every tool call is checked and gets a signed receipt) and puts the
MCP servers in that agent's own config behind the gateway (scan, lock, pre-check, receipts, secrets taken out of
answers). It reads first and prints what it would change; with ``write`` it changes it, keeping a backup of every
file. A remote server that signs in with OAuth is left alone, because the gateway cannot sign in yet.

An agent is "found" when its folder is in the home folder or its command is on PATH. Paths come from the home folder
only, never from environment variables, so a test with another home folder cannot touch the real configs.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from . import hook as hooks
from . import wrapcfg

VSCODE_USER = (("AppData", "Roaming", "Code", "User"), ("Library", "Application Support", "Code", "User"), (".config", "Code", "User"))
DESKTOP = (("AppData", "Roaming", "Claude"), ("Library", "Application Support", "Claude"), (".config", "Claude"))


@dataclass(frozen=True)
class Agent:
    key: str
    label: str
    hook: str | None  # key in hook.INSTALL; None when the agent has no hooks
    marks: tuple[tuple[str, ...], ...]  # paths under home that show it is installed
    commands: tuple[str, ...]  # or one of these on PATH
    user_mcp: tuple[tuple[str, ...], ...]
    project_mcp: tuple[tuple[str, ...], ...]


AGENTS = (
    Agent("claude-code", "Claude Code", "claude-code", ((".claude",), (".claude.json",)), ("claude",), ((".claude.json",),), ((".mcp.json",),)),
    Agent("cursor", "Cursor", "cursor", ((".cursor",),), ("cursor", "cursor-agent"), ((".cursor", "mcp.json"),), ((".cursor", "mcp.json"),)),
    Agent("codex", "Codex CLI", "codex", ((".codex",),), ("codex",), ((".codex", "config.toml"),), ((".codex", "config.toml"),)),
    Agent("gemini", "Gemini CLI", "gemini", ((".gemini",),), ("gemini",), ((".gemini", "settings.json"),), ((".gemini", "settings.json"),)),
    Agent("copilot", "GitHub Copilot", "copilot", ((".copilot",), *VSCODE_USER), ("copilot", "code"),
          ((".copilot", "mcp-config.json"), *(d + ("mcp.json",) for d in VSCODE_USER)), ((".vscode", "mcp.json"),)),
    Agent("windsurf", "Windsurf", "windsurf", ((".codeium", "windsurf"),), ("windsurf",), ((".codeium", "windsurf", "mcp_config.json"),), ()),
    Agent("claude-desktop", "Claude Desktop", None, DESKTOP, (), tuple(d + ("claude_desktop_config.json",) for d in DESKTOP), ()),
)
BY_KEY = {a.key: a for a in AGENTS}


def found(home: Path, which: Callable[[str], str | None] | None = None) -> list[Agent]:
    which = which or shutil.which
    return [a for a in AGENTS if any(home.joinpath(*m).exists() for m in a.marks) or any(which(c) for c in a.commands)]


def plan(agents: list[Agent], home: Path, cwd: Path, project: bool, exe: str) -> list[dict]:
    """What setup would change, one entry per file: {"agent", "kind": "hook"|"mcp", "path", "state", "text", ...}."""
    out = []
    pending: dict[Path, str] = {}  # Gemini keeps its hook and its MCP servers in one file: the second change builds on the first

    def read(path: Path) -> str:
        return pending[path] if path in pending else path.read_text("utf-8-sig")

    for a in agents:
        if a.hook:
            _label, where, add, _dirs = hooks.INSTALL[a.hook]
            path = where(project, cwd) if project else _home_path(where, home)
            item = {"agent": a, "kind": "hook", "path": path}
            try:
                current = json.loads(read(path)) if path in pending or path.exists() else {}
                if not isinstance(current, dict):
                    raise ValueError("not a JSON object")
                updated, changed = add(current)
                item.update(state="add" if changed else "on", text=json.dumps(updated, indent=2, ensure_ascii=False) + "\n")
                if changed:
                    pending[path] = item["text"]
            except (OSError, ValueError) as e:
                item.update(state="error", error=f"cannot read it: {e}")
            out.append(item)
        for parts in (a.project_mcp if project else a.user_mcp):
            path = (cwd if project else home).joinpath(*parts)
            if path not in pending and not path.is_file():
                continue
            item = {"agent": a, "kind": "mcp", "path": path}
            try:
                text, cfg, wrapped, left = wrapcfg.wrap_text(path, read(path), "verfy" if project else exe, skip_signin=True)
                item.update(state="wrap" if wrapped else "on", text=text, wrapped=wrapped, left=left)
                if wrapped:
                    pending[path] = text
            except (OSError, ValueError) as e:
                item.update(state="error", error=f"cannot read it: {e}")
            out.append(item)
    return out


def _home_path(where: Callable[..., Path], home: Path) -> Path:
    """The user-level file under this home folder (hook.INSTALL works from Path.home())."""
    real = where(False)
    try:
        return home / real.relative_to(Path.home())
    except ValueError:
        return real


def apply(items: list[dict]) -> list[dict]:
    """Write every change in the plan, keeping a backup. One file that fails does not stop the others."""
    backed_up: set[Path] = set()
    for item in items:
        if item["state"] not in ("add", "wrap"):
            continue
        path: Path = item["path"]
        try:
            if path.exists() and path not in backed_up:  # the backup is the file as it was before setup
                backed_up.add(path)
                shutil.copyfile(path, path.with_suffix(path.suffix + ".verfy-backup"))
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(item["text"], "utf-8")
            item["done"] = True
        except OSError as e:
            item.update(state="error", error=f"cannot write it: {e}")
    return items
