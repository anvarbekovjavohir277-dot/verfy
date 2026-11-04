"""Claude Code hook adapter: ``verfy hook pre-tool-use``.

Claude Code runs the hook before every tool call and sends the call as JSON on
stdin. Verfy maps it to an action, runs the same deterministic pre-check the
gateway uses, writes a signed receipt and answers:

* deny  -> ``permissionDecision: deny`` with the rule and the reason
* ask   -> ``permissionDecision: ask`` so the person decides
* allow -> no output, so Claude Code's own permission rules still apply

Verfy never answers "allow" itself and never fails open: a broken policy, a
locked ledger or any internal error becomes ``fail_mode`` (``ask`` by default,
``deny`` if the policy says so). The hook makes no network calls; team sync
runs as a separate command.

Reference: https://code.claude.com/docs/en/hooks
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, IO

from . import sessions
from .policy import load_policy
from .precheck import check

PRE_TOOL_COMMAND = "verfy hook pre-tool-use"
MAX_STDIN = 4 * 1024 * 1024


def action_from_payload(payload: dict[str, Any]) -> dict:
    """Turn a Claude Code PreToolUse payload into a Verfy action."""
    tool = str(payload.get("tool_name") or "")
    data = payload.get("tool_input")
    if not isinstance(data, dict):
        data = {"input": data}
    if tool.startswith("mcp__"):
        # mcp__<server>__<tool>; server names may themselves contain "__"
        rest = tool[len("mcp__"):]
        server, _, name = rest.rpartition("__")
        return {"server": server or rest, "tool": name or rest, "arguments": data}
    if tool in ("Bash", "PowerShell"):
        return {"server": "claude-code", "tool": tool, "arguments": {"command": str(data.get("command") or "")}}
    if tool in ("Write", "Edit", "MultiEdit"):
        content = data.get("content")
        if tool == "Edit":
            content = data.get("new_string")
        if tool == "MultiEdit":
            content = "\n".join(str(e.get("new_string") or "") for e in data.get("edits") or [] if isinstance(e, dict))
        return {"server": "claude-code", "tool": "write_file", "arguments": {"file_path": str(data.get("file_path") or ""), "content": str(content or "")}}
    if tool == "NotebookEdit":
        return {"server": "claude-code", "tool": "write_file", "arguments": {"file_path": str(data.get("notebook_path") or ""), "content": str(data.get("new_source") or "")}}
    if tool == "Read":
        return {"server": "claude-code", "tool": "read_file", "arguments": {"file_path": str(data.get("file_path") or "")}}
    if tool == "WebFetch":
        return {"server": "claude-code", "tool": "fetch_url", "arguments": {"url": str(data.get("url") or "")}}
    return {"server": "claude-code", "tool": tool or "unknown", "arguments": data}


def _output(verdict: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict, "permissionDecisionReason": reason}}


def _reason(decision: dict, receipt: dict | None) -> str:
    rules = "; ".join(f"[{f['rule']}] {f['message']}" for f in decision["findings"]) or "no rule matched"
    tail = f" Receipt {receipt['id']} (#{receipt['seq']})." if receipt else ""
    if decision["verdict"] == "deny":
        return f"Verfy blocked this action: {rules}.{tail} Do not retry it in another form; explain to the user why it is needed."
    return f"Verfy: this action needs your approval: {rules}.{tail}"


def evaluate(payload: dict, policy: dict, context: dict | None = None) -> tuple[dict, dict]:
    action = action_from_payload(payload)
    return action, check(action, policy, context)


def run_pre_tool_use(payload: Any, *, get_policy: Callable[[str | None], dict], record: Callable[..., dict | None] | None,
                     home: Path | None = None) -> dict | None:
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    policy = get_policy(cwd)
    tracked = str(payload.get("session_id") or "") if home and (policy.get("session") or {}).get("after_outside_text", "off") != "off" else ""
    source = sessions.source_of(home, tracked) if tracked else None
    action, decision = evaluate(payload, policy, {"untrusted": source} if source else None)
    if tracked and decision["verdict"] != "deny":
        read = sessions.outside_text(action, decision, policy)
        if read:
            sessions.mark(home, tracked, read)
    receipt = None
    if record is not None:
        receipt = record(action=action, decision=decision, session=str(payload.get("session_id") or "ses_" + uuid.uuid4().hex[:12]),
                         policy=policy, outcome={"status": "pending" if decision["verdict"] == "allow" else ("blocked" if decision["verdict"] == "deny" else "asked"), "result_sha256": None})
    if decision["verdict"] == "allow":
        return None
    return _output(decision["verdict"], _reason(decision, receipt))


def fail_safe(message: str, mode: str = "ask") -> dict:
    mode = mode if mode in ("ask", "deny") else "ask"
    return _output(mode, f"Verfy could not check this action ({message}), so it was not allowed automatically. Review it yourself.")


def run_hook(event: str, *, stdin: IO[str] | None = None, stdout: IO[str] | None = None,
             get_policy: Callable[[str | None], dict] | None = None, record: Callable[..., dict | None] | None = None,
             fail_mode: Callable[[], str] | None = None, home: Path | None = None) -> int:
    """Entry point for ``verfy hook <event>``. Always exits 0 with JSON on stdout."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    get_policy = get_policy or (lambda cwd: load_policy(None, workspace=cwd))
    if event != "pre-tool-use":
        print(f"verfy hook: unknown event `{event}` (supported: pre-tool-use)", file=sys.stderr)
        return 2
    try:
        raw = stdin.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            raise ValueError("hook input is larger than 4 MB")
        out = run_pre_tool_use(json.loads(raw), get_policy=get_policy, record=record, home=home)
    except Exception as e:  # noqa: BLE001 - every failure must become ask/deny, never allow
        mode = "ask"
        try:
            mode = fail_mode() if fail_mode else "ask"
        except Exception:  # noqa: BLE001
            mode = "ask"
        out = fail_safe(f"{type(e).__name__}: {str(e)[:200]}", mode)
    if out is not None:
        stdout.write(json.dumps(out) + "\n")
        stdout.flush()
    return 0


# ---------------------------------------------------------------- install

def settings_path(project: bool, cwd: Path | None = None) -> Path:
    if project:
        return (cwd or Path.cwd()) / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def with_hook(settings: dict, command: str = PRE_TOOL_COMMAND) -> tuple[dict, bool]:
    """Add the Verfy PreToolUse hook to a Claude Code settings object. Returns (settings, changed)."""
    out = json.loads(json.dumps(settings))
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in settings.json is not an object")
    pre = hooks.setdefault("PreToolUse", [])
    if not isinstance(pre, list):
        raise ValueError("`hooks.PreToolUse` in settings.json is not a list")
    for group in pre:
        for h in (group or {}).get("hooks", []) if isinstance(group, dict) else []:
            if isinstance(h, dict) and str(h.get("command", "")).startswith("verfy hook"):
                return out, False
    pre.append({"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]})
    return out, True
