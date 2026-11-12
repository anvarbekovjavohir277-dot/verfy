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
import sys
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
    Agent("devin", "Devin Desktop", "devin", ((".devin",), (".config", "devin"), ("AppData", "Roaming", "devin"), (".codeium", "windsurf")),
          ("devin",), (), ()),
    Agent("windsurf", "Windsurf", "windsurf", ((".codeium", "windsurf"),), ("windsurf",), ((".codeium", "windsurf", "mcp_config.json"),), ()),
    Agent("claude-desktop", "Claude Desktop", None, DESKTOP, (), tuple(d + ("claude_desktop_config.json",) for d in DESKTOP), ()),
)
BY_KEY = {a.key: a for a in AGENTS}


def found(home: Path, which: Callable[[str], str | None] | None = None) -> list[Agent]:
    which = which or shutil.which
    return [a for a in AGENTS if any(home.joinpath(*m).exists() for m in a.marks) or any(which(c) for c in a.commands)]


def system_hooked(agent: str, platform: str | None = None) -> Path | None:
    """The machine-wide file that already runs Verfy's hook for this agent, if there is one."""
    paths = SYSTEM_FILES.get(agent)
    if not paths:
        return None
    path = Path(paths[_platform(platform or sys.platform)])
    try:
        return path if path.is_file() and "verfy" in path.read_text("utf-8-sig") and " hook " in path.read_text("utf-8-sig") else None
    except OSError:
        return None


def system_current(agent: str) -> bool:
    """True when the machine-wide file for this agent already holds every hook this Verfy adds."""
    item = next((i for i in system_plan(sys.platform, shutil.which("verfy")) if i["agent"].key == agent), None)
    return item is not None and item["state"] == "on"


def plan(agents: list[Agent], home: Path, cwd: Path, project: bool, exe: str) -> list[dict]:
    """What setup would change, one entry per file: {"agent", "kind": "hook"|"mcp", "path", "state", "text", ...}."""
    out = []
    pending: dict[Path, str] = {}  # Gemini keeps its hook and its MCP servers in one file: the second change builds on the first

    def read(path: Path) -> str:
        return pending[path] if path in pending else path.read_text("utf-8-sig")

    for a in agents:
        machine = None if project else system_hooked(a.key)
        if a.hook and machine:
            # no second, user-level copy; an older machine-wide file is reported, since only an administrator can update it
            current = system_current(a.key)
            out.append({"agent": a, "kind": "system", "path": machine, "state": "on"} if current else
                       {"agent": a, "kind": "system", "path": machine, "state": "error",
                        "error": "the machine-wide hook is from an older Verfy: run `verfy setup --system --write` as administrator"})
        elif a.hook:
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


# ---------------------------------------------------------------- IDE terminal inside the sandbox

# The IDE itself is a desktop app and cannot run inside the sandbox runtime, but its AI agent runs commands in the
# IDE's terminal. Making that terminal start inside `verfy run --sandbox` closes what those commands can write and
# reach. Opt in with `verfy setup --sandbox-terminal on`: a sandboxed terminal also stops installs that need a host
# your policy does not allow.
IDES = (("Code", "VS Code"), ("Cursor", "Cursor"), ("Windsurf", "Windsurf"))
APP_DIRS = (("AppData", "Roaming"), ("Library", "Application Support"), (".config",))
PROFILE = "Verfy sandbox"


class IDE:
    def __init__(self, label: str):
        self.key, self.label = "ide-" + label.lower().replace(" ", ""), label


def ide_settings(home: Path) -> list[tuple[IDE, Path]]:
    """Each installed IDE's user settings file (VS Code, Cursor, Windsurf), found by its settings folder."""
    out = []
    for folder, label in IDES:
        for base in APP_DIRS:
            user = home.joinpath(*base, folder, "User")
            if user.is_dir():
                out.append((IDE(label), user / "settings.json"))
                break
    return out


def platform_key(platform: str) -> str:
    return "windows" if platform.startswith("win") else ("osx" if platform == "darwin" else "linux")


def terminal_profile(platform: str, exe: str, wsl: str | None) -> dict | None:
    """The terminal profile that opens a shell inside the sandbox. On Windows the sandbox runs inside WSL2."""
    key = platform_key(platform)
    if key == "windows":
        if not wsl:
            return None
        return {"path": wsl, "args": ["--exec", "bash", "-lc", "exec verfy run --sandbox -- bash -l"]}
    shell = "zsh" if key == "osx" else "bash"
    return {"path": exe, "args": ["run", "--sandbox", "--", shell, "-l"]}


def with_sandbox_terminal(settings: dict, on: bool, platform: str, profile: dict | None) -> tuple[dict, bool]:
    key = platform_key(platform)
    out = json.loads(json.dumps(settings))
    profiles_key, default_key = f"terminal.integrated.profiles.{key}", f"terminal.integrated.defaultProfile.{key}"
    profiles = out.get(profiles_key) if isinstance(out.get(profiles_key), dict) else {}
    if on:
        if profile is None:
            raise ValueError("no sandbox here: on Windows it needs WSL2 with verfy and srt inside it")
        if profiles.get(PROFILE) == profile and out.get(default_key) == PROFILE:
            return out, False
        out[profiles_key] = {**profiles, PROFILE: profile}
        out[default_key] = PROFILE
        return out, True
    changed = False
    if PROFILE in profiles:
        profiles = {k: v for k, v in profiles.items() if k != PROFILE}
        if profiles:
            out[profiles_key] = profiles
        else:
            out.pop(profiles_key, None)
        changed = True
    if out.get(default_key) == PROFILE:
        out.pop(default_key)
        changed = True
    return out, changed


def terminal_plan(home: Path, on: bool, platform: str, exe: str, wsl: str | None) -> list[dict]:
    """One item per IDE settings file. A settings file with comments is not rewritten: the comments would be lost."""
    profile = terminal_profile(platform, exe, wsl)
    out = []
    for ide, path in ide_settings(home):
        item = {"agent": ide, "kind": "terminal", "path": path}
        try:
            text = path.read_text("utf-8-sig") if path.exists() else "{}"
            try:
                current = json.loads(text) if text.strip() else {}
            except ValueError:
                raise ValueError("it has comments or trailing commas; add the profile by hand from `verfy setup --sandbox-terminal on`") from None
            if not isinstance(current, dict):
                raise ValueError("not a JSON object")
            updated, changed = with_sandbox_terminal(current, on, platform, profile)
            item.update(state="add" if changed else "on", text=json.dumps(updated, indent=4, ensure_ascii=False) + "\n", on=on)
        except (OSError, ValueError) as e:
            item.update(state="error", error=f"cannot change it: {e}")
        out.append(item)
    return out


# ---------------------------------------------------------------- machine-wide hooks (verfy setup --system)

# Where Claude Code and Cursor read settings an administrator deploys. A user, and so an agent running as that user,
# cannot change these files, and Claude Code does not let user or project settings override a managed value. Verfy
# writes a drop-in file of its own for Claude Code, so an organisation's managed-settings.json is left as it is.
# https://code.claude.com/docs/en/managed-settings, https://cursor.com/docs/agent/hooks
SYSTEM_FILES = {
    "claude-code": {
        "darwin": "/Library/Application Support/ClaudeCode/managed-settings.d/50-verfy.json",
        "linux": "/etc/claude-code/managed-settings.d/50-verfy.json",
        "win32": r"C:\Program Files\ClaudeCode\managed-settings.d\50-verfy.json",
    },
    "cursor": {
        "darwin": "/Library/Application Support/Cursor/hooks.json",
        "linux": "/etc/cursor/hooks.json",
        "win32": r"C:\ProgramData\Cursor\hooks.json",
    },
}
ADMIN_NOTE = ("it needs administrator rights: run it again in an administrator terminal (Windows) "
              "or with sudo (macOS, Linux)")


def _platform(platform: str) -> str:
    return "win32" if platform.startswith("win") else ("darwin" if platform == "darwin" else "linux")


def system_command(exe: str | None) -> str:
    """The verfy a machine-wide hook runs: the full path when it has no space (a hook command is run by a shell), else
    `verfy` from PATH."""
    return exe if exe and " " not in exe else "verfy"


def claude_system_settings(verfy: str) -> dict:
    return {"hooks": {
        "PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": f"{verfy} hook pre-tool-use", "timeout": 10}]}],
        "UserPromptSubmit": [{"hooks": [{"type": "command", "command": f"{verfy} hook prompt", "timeout": 10}]}],
    }}


def system_plan(platform: str, exe: str | None, root: Path | None = None) -> list[dict]:
    """The machine-wide hook files for Claude Code and Cursor. `root` moves them under a test folder."""
    plat, verfy = _platform(platform), system_command(exe)
    out = []

    def place(agent: str) -> Path:
        p = Path(SYSTEM_FILES[agent][plat])
        return root / p.relative_to(p.anchor) if root else p

    path = place("claude-code")
    item = {"agent": BY_KEY["claude-code"], "kind": "system", "path": path}
    want = json.dumps(claude_system_settings(verfy), indent=2) + "\n"
    try:
        same = path.exists() and json.loads(path.read_text("utf-8-sig")) == claude_system_settings(verfy)
        item.update(state="on" if same else "add", text=want)
    except (OSError, ValueError) as e:
        item.update(state="error", error=f"cannot read it: {e}")
    out.append(item)

    path = place("cursor")
    item = {"agent": BY_KEY["cursor"], "kind": "system", "path": path}
    try:
        current = json.loads(path.read_text("utf-8-sig")) if path.exists() else {}
        if not isinstance(current, dict):
            raise ValueError("not a JSON object")
        updated, changed = hooks.with_cursor_hook(current, command=f"{verfy} hook cursor")
        item.update(state="add" if changed else "on", text=json.dumps(updated, indent=2) + "\n")
    except (OSError, ValueError) as e:
        item.update(state="error", error=f"cannot read it: {e}")
    out.append(item)
    return out


def without_user_hooks(config: dict) -> tuple[dict, bool]:
    """A settings or hooks file with Verfy's own hook entries taken out, everything else kept. Used once the same hooks
    are machine-wide, so each call is not checked and recorded twice."""
    out = json.loads(json.dumps(config))
    hooks_ = out.get("hooks")
    if not isinstance(hooks_, dict):
        return out, False
    changed = False
    for event, entries in list(hooks_.items()):
        if not isinstance(entries, list):
            continue
        kept = []
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("command"), str) and "verfy hook" in e["command"]:
                changed = True  # Cursor: {"command": ...}
                continue
            if isinstance(e, dict) and isinstance(e.get("hooks"), list):
                inner = [h for h in e["hooks"] if not (isinstance(h, dict) and "verfy hook" in str(h.get("command", "")))]
                if len(inner) != len(e["hooks"]):
                    changed = True
                    if not inner:
                        continue  # Claude Code: a group with only Verfy's hook
                    e = {**e, "hooks": inner}
            kept.append(e)
        hooks_[event] = kept
    return out, changed


def user_hook_cleanup(home: Path) -> list[dict]:
    """Verfy's entries in the user's own Claude Code and Cursor files, to remove after the machine-wide ones are in."""
    out = []
    for key, path in (("claude-code", home / ".claude" / "settings.json"), ("cursor", home / ".cursor" / "hooks.json")):
        if not path.is_file():
            continue
        item = {"agent": BY_KEY[key], "kind": "unhook", "path": path}
        try:
            current = json.loads(path.read_text("utf-8-sig"))
            if not isinstance(current, dict):
                raise ValueError("not a JSON object")
            updated, changed = without_user_hooks(current)
            item.update(state="add" if changed else "on", text=json.dumps(updated, indent=2, ensure_ascii=False) + "\n")
        except (OSError, ValueError) as e:
            item.update(state="error", error=f"cannot read it: {e}")
        out.append(item)
    return out


def apply_system(items: list[dict], cleanup: list[dict]) -> list[dict]:
    """Write the machine-wide files; only when every one is in place, take Verfy's hooks out of the user's files."""
    for item in items:
        if item["state"] != "add":
            continue
        path: Path = item["path"]
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.exists():
                shutil.copyfile(path, path.with_suffix(path.suffix + ".verfy-backup"))
            path.write_text(item["text"], "utf-8")
            item["done"] = True
        except OSError as e:
            item.update(state="error", error=ADMIN_NOTE if isinstance(e, PermissionError) else f"cannot write it: {e}")
    if all(i["state"] in ("on", "add") for i in items):
        return items + apply(cleanup)
    for c in cleanup:
        if c["state"] == "add":
            c.update(state="skipped", error="kept, because a machine-wide file was not written")
    return items + cleanup
