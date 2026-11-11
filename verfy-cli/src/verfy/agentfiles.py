"""Lock the files a coding agent loads as instructions, not only MCP tools.

Claude Code, Codex, Gemini CLI, Cursor and others read instruction files (CLAUDE.md, AGENTS.md,
GEMINI.md, rules), skills, sub-agents, slash commands, hook settings and installed plugins. Any of
them can change without anyone reviewing it, for example when a plugin updates itself. This module
pins the SHA-256 of each such file and reports what changed.

Two scopes:

* project: files in the repository, pinned in the ``files`` section of ``verfy.lock`` (committed,
  so CI fails when they change without a reviewed lock update).
* user: files in your home folder (user-level instructions, skills and installed plugins), pinned in
  ``~/.verfy/agent-files.lock`` on this machine.

Small text files keep a copy of the approved text (16 KB in a project, 64 KB in the home folder), so
a change can be shown as a diff and the sentences it added can be checked.

Everything here is local and deterministic: files are hashed, never sent anywhere.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
from pathlib import Path

from .fileio import atomic_write
from .lock import APPROVERS, added_sentences, instruction_kind, _short
from .receipts import now_iso
from .scanner import text_findings

USER_LOCK_VERSION = 1
MAX_FILES = 5000
SNAPSHOT_BYTES = {"project": 16 * 1024, "user": 64 * 1024}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".next", "target", ".tox", ".mypy_cache", ".pytest_cache", "site-packages"}

# instruction files an agent reads wherever they appear in the repository
INSTRUCTION_NAMES = {"CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules"}
PROJECT_FILES = [".claude/settings.json", ".github/copilot-instructions.md", ".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".gemini/settings.json", ".cursor/hooks.json", ".codex/hooks.json", ".codex/config.toml", ".windsurf/hooks.json"]
PROJECT_DIRS = [".claude/agents", ".claude/commands", ".claude/skills", ".claude/hooks", ".cursor/rules", ".windsurf/rules", ".github/instructions", ".github/hooks", ".gemini/commands"]

USER_FILES = ["~/.claude/CLAUDE.md", "~/.claude/settings.json", "~/.codex/AGENTS.md", "~/.codex/config.toml", "~/.gemini/GEMINI.md", "~/.gemini/settings.json", "~/.cursor/mcp.json", "~/.cursor/hooks.json", "~/.codex/hooks.json", "~/.copilot/mcp-config.json", "~/.codeium/windsurf/mcp_config.json", "~/.codeium/windsurf/hooks.json", "~/.codeium/windsurf/memories/global_rules.md"]
USER_DIRS = ["~/.claude/agents", "~/.claude/commands", "~/.claude/skills", "~/.claude/plugins/cache", "~/.codex/prompts", "~/.gemini/commands", "~/.copilot/hooks"]


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    n = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
            n += len(chunk)
    return "sha256:" + h.hexdigest(), n


def _walk(top: Path, notes: list[str], limit: int) -> list[Path]:
    out: list[Path] = []
    for root, dirs, files in os.walk(top):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(files):
            out.append(Path(root) / name)
            if len(out) >= limit:
                notes.append(f"stopped after {limit} files under {top}")
                return out
    return out


def project_files(root: Path, notes: list[str] | None = None) -> list[Path]:
    """Agent files in a repository, as paths below ``root``."""
    notes = notes if notes is not None else []
    found: set[Path] = set()
    for rel in PROJECT_FILES:
        if (root / rel).is_file():
            found.add(root / rel)
    for rel in PROJECT_DIRS:
        if (root / rel).is_dir():
            found.update(_walk(root / rel, notes, MAX_FILES))
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        found.update(Path(dirpath) / f for f in files if f in INSTRUCTION_NAMES)
        if len(found) > MAX_FILES:
            notes.append(f"more than {MAX_FILES} agent files; only the first ones are locked")
            break
    return sorted(found)[:MAX_FILES]


def user_files(home: Path, notes: list[str] | None = None) -> list[Path]:
    """Agent files in the home folder: user-level instructions, skills, commands and installed plugins."""
    notes = notes if notes is not None else []
    found: set[Path] = set()
    expand = lambda p: home / p[2:]  # noqa: E731
    for p in USER_FILES:
        if expand(p).is_file():
            found.add(expand(p))
    for p in USER_DIRS:
        if expand(p).is_dir():
            found.update(_walk(expand(p), notes, MAX_FILES))
    return sorted(found)[:MAX_FILES]


def key_for(path: Path, root: Path, user: bool) -> str:
    rel = path.relative_to(root).as_posix()
    return f"~/{rel}" if user else rel


def snapshot(paths: list[Path], root: Path, user: bool) -> dict[str, dict]:
    """``{key: {sha256, bytes[, text]}}`` for each readable file."""
    out: dict[str, dict] = {}
    for p in paths:
        try:
            digest, size = sha256_file(p)
        except OSError:
            continue
        entry = {"sha256": digest, "bytes": size}
        if size <= SNAPSHOT_BYTES["user" if user else "project"]:
            try:
                entry["text"] = p.read_text("utf-8")
            except (OSError, UnicodeDecodeError):
                pass
        out[key_for(p, root, user)] = entry
    return out


def compare(locked: dict[str, dict], current: dict[str, dict]) -> list[dict]:
    """ok / changed / new / removed for every locked and current file."""
    rows = []
    for key in sorted(set(locked) | set(current)):
        a, b = locked.get(key), current.get(key)
        if a is None:
            rows.append({"path": key, "status": "new", "locked": None, "current": b["sha256"]})
        elif b is None:
            rows.append({"path": key, "status": "removed", "locked": a["sha256"], "current": None})
        elif a["sha256"] == b["sha256"]:
            rows.append({"path": key, "status": "ok", "locked": a["sha256"], "current": b["sha256"]})
        else:
            rows.append({"path": key, "status": "changed", "locked": a["sha256"], "current": b["sha256"]})
    return rows


def explain_text(old: str | None, new: str | None, changed: bool = True) -> dict:
    """Risk of a change to an instruction file: new orders for the model, new links, hidden text.

    ``old`` is the locked text when a copy was kept; without it the whole current file is checked.
    """
    if new is None:
        return {"risk": "low", "summary": "file removed" if changed else "not readable as text", "changes": [{"what": "file removed" if changed else "not readable as text", "risk": "low"}]}
    # a byte-order mark at the very start is an editor artifact, not hidden text
    old = old[1:] if old and old.startswith("\ufeff") else old
    new = new[1:] if new.startswith("\ufeff") else new
    changes: list[dict] = []
    before_rules = {f["rule"] for f in text_findings(old)} if old is not None else set()
    for f in text_findings(new):
        if f["rule"] in before_rules:
            continue
        before_rules.add(f["rule"])
        risk = {"critical": "high", "high": "high", "medium": "medium"}.get(f["severity"], "low")
        changes.append({"what": f"{f['rule']}: {f['message']}", "risk": risk})
    if old is not None:
        for s in added_sentences(old, new):
            kind = instruction_kind(s)
            if kind:
                changes.append({"what": f"new {kind}: \"{_short(s)}\"", "risk": "high" if kind.startswith("instruction to move data") else "medium"})
    if not changes:
        changes.append({"what": "content changed" if changed else "new file", "risk": "low"})
    rank = {"low": 1, "medium": 2, "high": 3}
    risk = max((c["risk"] for c in changes), key=lambda r: rank[r])
    return {"risk": risk, "summary": "; ".join(c["what"] for c in changes if c["risk"] == risk), "changes": changes}


def text_of(path: Path) -> str | None:
    try:
        if path.stat().st_size > 1024 * 1024:
            return None
        return path.read_text("utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def diff_text(old: str, new: str, label: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), fromfile=f"locked/{label}", tofile=f"current/{label}"))


def entries(current: dict[str, dict], by: str, keep_text: bool) -> dict[str, dict]:
    if by not in APPROVERS:
        raise ValueError(f"approved_by must be one of {APPROVERS}")
    at = now_iso()
    out = {}
    for key, e in current.items():
        out[key] = {"sha256": e["sha256"], "bytes": e["bytes"], "approved_at": at, "approved_by": by}
        if keep_text and "text" in e:
            out[key]["text"] = e["text"]
    return out


# ---------------------------------------------------------------- user lock file

def user_lock_path(home: Path) -> Path:
    return home / "agent-files.lock"


def load_user_lock(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    data = json.loads(path.read_text("utf-8"))
    if not isinstance(data, dict) or data.get("version") != USER_LOCK_VERSION or not isinstance(data.get("files"), dict):
        raise ValueError(f"{path} is not a Verfy agent-files lock (version {USER_LOCK_VERSION})")
    return data["files"]


def save_user_lock(path: Path, files: dict[str, dict]) -> None:
    atomic_write(path, json.dumps({"version": USER_LOCK_VERSION, "files": files}, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
