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

``verfy hook cursor`` does the same for Cursor's terminal, MCP and file read
hooks. Cursor counts no output as a failure, so there Verfy does answer "allow",
and a file read cannot wait for a person, so "ask" becomes "deny". Cursor's file
edits and web search are not covered: no hook documents their input.

``verfy hook codex``, ``verfy hook gemini``, ``verfy hook copilot`` and
``verfy hook windsurf`` (beta) do the same for Codex CLI, Gemini CLI, GitHub
Copilot (the CLI and VS Code) and Windsurf. Codex, Gemini, Windsurf and the
Copilot CLI cannot wait for a person from a hook, so there "ask" becomes a block
that tells the agent to ask the user. What an adapter cannot read is blocked.

Reference: https://code.claude.com/docs/en/hooks, https://cursor.com/docs/agent/hooks,
https://developers.openai.com/codex/hooks, https://geminicli.com/docs/hooks/,
https://docs.github.com/en/copilot/reference/hooks-configuration, https://docs.windsurf.com/windsurf/cascade/hooks
"""

from __future__ import annotations

import functools
import json
import re
import shlex
import sys
import uuid
from pathlib import Path
from typing import Any, Callable, IO

from . import sessions
from .policy import load_policy
from ._util import redact_output, scan_secrets
from .precheck import check

PRE_TOOL_COMMAND = "verfy hook pre-tool-use"
CURSOR_COMMAND = "verfy hook cursor"
CURSOR_EVENTS = ("beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "preToolUse", "beforeSubmitPrompt", "postToolUse")
# hooks.json entry per event: the hooks that decide fail closed; the prompt guard and the output filter must not stop
# Cursor when they cannot run. preToolUse leaves Shell, Read and MCP calls to their own hooks, which already check them.
CURSOR_ENTRY = {
    "preToolUse": {"failClosed": True},  # no matcher: side_answer skips Shell, Read and MCP, which other hooks check
    "beforeSubmitPrompt": {"failClosed": False},
    "postToolUse": {"failClosed": False, "matcher": "^MCP"},
}
PROMPT_COMMAND = "verfy hook prompt"
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
    if tool == "NotebookRead":
        return {"server": "claude-code", "tool": "read_file", "arguments": {"file_path": str(data.get("notebook_path") or "")}}
    if tool == "WebFetch":
        return {"server": "claude-code", "tool": "fetch_url", "arguments": {"url": str(data.get("url") or "")}}
    if tool == "Glob" and not data.get("path"):
        data = {**data, "path": data.get("pattern")}  # an absolute pattern lists that folder
    return {"server": "claude-code", "tool": tool or "unknown", "arguments": data}


def cursor_action(payload: dict[str, Any]) -> dict:
    """Turn a Cursor hook payload into a Verfy action. What it cannot read raises, so it is never allowed by default."""
    event = payload.get("hook_event_name")
    if event == "beforeShellExecution":
        command = payload.get("command")
        if not isinstance(command, str) or not command:
            raise ValueError("no command in the hook input")
        return {"server": "cursor", "tool": "Shell", "arguments": {"command": command}}
    if event == "beforeMCPExecution":
        server, tool = payload.get("mcp_server_name"), payload.get("tool_name")
        if not (isinstance(server, str) and server and isinstance(tool, str) and tool):
            raise ValueError("no server or tool name in the hook input")
        data = payload.get("tool_input")
        if isinstance(data, str):
            data = json.loads(data or "{}")
        return {"server": server, "tool": tool, "arguments": data if isinstance(data, dict) else {"input": data}}
    if event == "beforeReadFile":
        path = payload.get("file_path")
        if not isinstance(path, str) or not path:
            raise ValueError("no file path in the hook input")
        return {"server": "cursor", "tool": "read_file", "arguments": {"file_path": path}}
    if event == "preToolUse":
        data = payload.get("tool_input")
        if isinstance(data, str):
            data = json.loads(data or "{}")
        return tool_action("cursor", str(payload.get("tool_name") or ""), data)  # type: ignore[return-value]
    raise ValueError(f"Verfy does not handle the Cursor event {event!r}")


def cursor_payload(payload: Any) -> dict:
    """The fields `run_pre_tool_use` reads, from what Cursor sends."""
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    roots = payload.get("workspace_roots")
    return {**payload, "cwd": payload.get("cwd") or (roots[0] if isinstance(roots, list) and roots else None), "session_id": payload.get("conversation_id")}


def cursor_answer(out: dict | None, event: Any) -> dict:
    """Cursor's answer from Verfy's. Only the terminal and MCP hooks can ask a person, and the read hook takes one message."""
    if out is None:
        return {"permission": "allow"}
    verdict = out["hookSpecificOutput"]["permissionDecision"]
    reason = out["hookSpecificOutput"]["permissionDecisionReason"]
    if event in ("beforeShellExecution", "beforeMCPExecution"):
        return {"permission": verdict, "user_message": reason, "agent_message": reason}
    if verdict == "ask":
        reason = "Cursor cannot wait for a person here, so this was blocked. " + reason
    if event == "preToolUse":
        return {"permission": "deny", "user_message": reason, "agent_message": reason}
    return {"permission": "deny", "user_message": reason}


# ------------------------------------------------- Codex, Gemini, Copilot, Windsurf

# tool names after lower-casing and dropping "_", "-" and spaces
SHELL_TOOLS = {"bash", "exec", "powershell", "shell", "shellcommand", "execcommand", "localshell", "unifiedexec", "runshellcommand",
               "runinterminal", "runcommand", "terminal", "containerexec"}
READ_TOOLS = {"view", "read", "readfile", "notebookread"}
WRITE_TOOLS = {"create", "createfile", "write", "writefile", "edit", "editfile", "multiedit", "replace", "strreplace",
               "replacestringinfile", "multireplacestringinfile", "inserteditintofile", "notebookedit"}
FETCH_TOOLS = {"webfetch", "fetch", "fetchurl", "fetchwebpage"}
# text typed into a shell session that is already running: checked as a command of its own
SHELL_INPUT_TOOLS = {"writestdin", "writetoprocess", "writebash", "sendinput", "writeinput", "sendkeys"}
INPUT_KEYS = ("chars", "input", "text", "data", "keys", "command")
DELETE_TOOLS = {"delete", "deletefile", "remove", "removefile", "rm", "deletefiles"}
PATH_KEYS = ("file_path", "filePath", "path", "absolute_path", "notebook_path", "target_file", "file")
CONTENT_KEYS = ("content", "file_text", "fileText", "new_string", "newString", "new_str", "newStr", "new_source", "code", "text")
NO_ASK = ("{agent} cannot wait for a person from a hook, so Verfy blocked this. Ask the user first; "
          "if they agree, they can run it themselves or allow it in the Verfy policy. ")


def _key(name: str) -> str:
    return re.sub(r"[\W_]", "", name.lower())


def _first(data: dict, keys: tuple[str, ...]) -> str:
    for k in keys:
        if isinstance(data.get(k), str) and data[k]:
            return data[k]
    return ""


def _command(data: dict) -> str:
    cmd = data.get("command", data.get("cmd"))
    if isinstance(cmd, list) and all(isinstance(c, str) for c in cmd):
        if len(cmd) >= 3:
            shell = Path(cmd[0].replace("\\", "/")).name.lower().removesuffix(".exe")
            flag = cmd[1].lower()
            # PowerShell and cmd.exe join every argument after -Command or /c into the command they run
            if shell in ("powershell", "pwsh", "cmd") and flag in ("-command", "-c", "/c", "/k", "-commandwithargs"):
                return " ".join(cmd[2:])
            # ["bash", "-lc", "rm -rf ~"]: the script; any later arguments are only $0, $1, ...
            if flag in ("-c", "-lc"):
                return cmd[2]
        return shlex.join(cmd)
    return cmd if isinstance(cmd, str) else ""


def _write(server: str, path: str, content: str) -> dict:
    return {"server": server, "tool": "write_file", "arguments": {"file_path": path, "content": content}}


def _writes(server: str, data: dict) -> list[dict]:
    """One write per file an edit tool changes. Raises when no file is named, so it is not allowed by default."""
    items = data.get("replacements") if isinstance(data.get("replacements"), list) else [data]
    out = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("an edit without a file")
        path = _first(item, PATH_KEYS) or _first(data, PATH_KEYS)
        if not path:
            raise ValueError("no file path in the edit")
        edits = item.get("edits")
        if isinstance(edits, list):
            content = "\n".join(_first(e, CONTENT_KEYS) for e in edits if isinstance(e, dict))
        else:
            content = _first(item, CONTENT_KEYS)
        out.append(_write(server, path, content))
    return out


def _patch_text(data: Any) -> str:
    if isinstance(data, str):
        return data
    for k in ("patch", "input", "command"):
        v = data.get(k)
        if isinstance(v, list):
            v = next((x for x in v if isinstance(x, str) and "*** " in x), None)
        if isinstance(v, str) and "*** " in v:
            return v
    return ""


def patch_actions(server: str, text: str) -> list[dict]:
    """The files an apply_patch body adds, changes, moves or deletes, each as a write with the lines it adds."""
    out: list[dict] = []
    path, added = None, []

    def flush():
        if path is not None:
            out.append(_write(server, path, "\n".join(added)))

    for line in text.splitlines():
        m = re.match(r"^\*\*\* (Add|Update|Delete) File: (.+?)\s*$", line)
        if m:
            flush()
            path, added = m.group(2), []
            continue
        m = re.match(r"^\*\*\* Move to: (.+?)\s*$", line)
        if m and path is not None:
            flush()
            path, added = m.group(1), []
            continue
        if path is not None and line.startswith("+"):
            added.append(line[1:])
    flush()
    if not out:
        raise ValueError("no file in the patch")
    return out


def _urls(data: dict) -> list[str]:
    found = [u for k in ("url", "urls") for u in ([data.get(k)] if isinstance(data.get(k), str) else data.get(k) or []) if isinstance(u, str)]
    if not found and isinstance(data.get("prompt"), str):
        found = re.findall(r"https?://[^\s\"'<>)\]]+", data["prompt"])
    return found


def tool_action(server: str, name: str, data: Any) -> dict | list[dict]:
    """A tool call from Codex, Gemini or Copilot as one or more Verfy actions. Known tools whose input it cannot read raise."""
    if not name:
        raise ValueError("no tool name in the hook input")
    if not isinstance(data, dict):
        data = {"input": data}
    if name.startswith("mcp__"):
        server_, _, tool = name[len("mcp__"):].rpartition("__")
        return {"server": server_ or name, "tool": tool or name, "arguments": data}
    key = _key(name)
    if key == "strreplaceeditor":
        key = "view" if data.get("command") == "view" else "edit"
    if key in SHELL_TOOLS:
        cmd = _command(data)
        if not cmd:
            raise ValueError(f"no command in the {name} call")
        return {"server": server, "tool": "Shell", "arguments": {"command": cmd}}
    if key in SHELL_INPUT_TOOLS:
        typed = _first(data, INPUT_KEYS)
        if not typed and not any(k in data for k in INPUT_KEYS):
            raise ValueError(f"no input in the {name} call")
        if not typed.strip():
            return {"server": server, "tool": name, "arguments": {"input": typed}}  # Enter, an empty line
        return {"server": server, "tool": "Shell", "arguments": {"command": typed}}
    if key in DELETE_TOOLS:
        path = _first(data, PATH_KEYS)
        if not path:
            raise ValueError(f"no file path in the {name} call")
        return {"server": server, "tool": "delete_file", "arguments": {"path": path}}
    if key in READ_TOOLS:
        path = _first(data, PATH_KEYS)
        if not path:
            raise ValueError(f"no file path in the {name} call")
        return {"server": server, "tool": "read_file", "arguments": {"file_path": path}}
    if key in WRITE_TOOLS:
        return _writes(server, data)
    if key == "applypatch":
        return patch_actions(server, _patch_text(data))
    if key == "readmanyfiles":
        paths = [p for k in ("paths", "include") for p in data.get(k) or [] if isinstance(p, str)]
        if not paths:
            raise ValueError("no file in the read_many_files call")
        return [{"server": server, "tool": "read_file", "arguments": {"file_path": p}} for p in paths]
    if key in FETCH_TOOLS:
        urls = _urls(data)
        if urls:
            return [{"server": server, "tool": "fetch_url", "arguments": {"url": u}} for u in urls]
    return {"server": server, "tool": name, "arguments": data}


def codex_action(payload: dict) -> dict | list[dict]:
    """Codex sends Claude Code's PreToolUse shape; apply_patch carries the whole patch."""
    return tool_action("codex", str(payload.get("tool_name") or ""), payload.get("tool_input"))


def gemini_action(payload: dict) -> dict | list[dict]:
    """Gemini CLI's BeforeTool. An MCP tool comes as mcp_<server>_<tool>, with the server in mcp_context."""
    name = str(payload.get("tool_name") or "")
    data = payload.get("tool_input")
    ctx = payload.get("mcp_context") if isinstance(payload.get("mcp_context"), dict) else {}
    server = ctx.get("server_name") or ctx.get("serverName")
    if isinstance(server, str) and server:
        tool = ctx.get("tool_name") or ctx.get("toolName") or name.removeprefix(f"mcp_{server}_")
        return {"server": server, "tool": str(tool), "arguments": data if isinstance(data, dict) else {"input": data}}
    if name.startswith("mcp_") and not name.startswith("mcp__"):
        # mcp_<server>_<tool>, and either may hold "_": without mcp_context each way to split it is checked, so a rule for
        # the right server always gets its say
        parts = name[len("mcp_"):].split("_")
        args = data if isinstance(data, dict) else {"input": data}
        splits = [("_".join(parts[:i]), "_".join(parts[i:])) for i in range(1, len(parts))] or [(parts[0], parts[0])]
        return [{"server": srv, "tool": tool, "arguments": args} for srv, tool in splits[:6]]
    return tool_action("gemini", name, data)


def copilot_action(payload: dict) -> dict | list[dict]:
    """Copilot CLI sends toolName and toolArgs (a JSON string); VS Code sends Claude Code's tool_name and tool_input."""
    name = str(payload.get("toolName") or payload.get("tool_name") or "")
    data = payload["toolArgs"] if "toolArgs" in payload else payload.get("tool_input")
    if isinstance(data, str):
        data = json.loads(data or "{}")
    return tool_action("copilot", name, data)


def windsurf_action(payload: dict) -> dict | list[dict]:
    """Windsurf's pre-hooks. Only the four it documents are read; anything else raises and is blocked."""
    event = payload.get("agent_action_name")
    info = payload.get("tool_info")
    if not isinstance(info, dict):
        raise ValueError("no tool_info in the hook input")
    if event == "pre_run_command":
        cmd = info.get("command_line")
        if not isinstance(cmd, str) or not cmd:
            raise ValueError("no command in the hook input")
        return {"server": "windsurf", "tool": "Shell", "arguments": {"command": cmd}}
    if event in ("pre_read_code", "pre_write_code"):
        path = info.get("file_path")
        if not isinstance(path, str) or not path:
            raise ValueError("no file path in the hook input")
        if event == "pre_read_code":
            return {"server": "windsurf", "tool": "read_file", "arguments": {"file_path": path}}
        edits = info.get("edits") if isinstance(info.get("edits"), list) else []
        return _write("windsurf", path, "\n".join(str(e.get("new_string") or "") for e in edits if isinstance(e, dict)))
    if event == "pre_mcp_tool_use":
        server, tool = info.get("mcp_server_name"), info.get("mcp_tool_name")
        if not (isinstance(server, str) and server and isinstance(tool, str) and tool):
            raise ValueError("no server or tool name in the hook input")
        data = info.get("mcp_tool_arguments")
        if isinstance(data, str):
            data = json.loads(data or "{}")
        return {"server": server, "tool": tool, "arguments": data if isinstance(data, dict) else {"input": data}}
    raise ValueError(f"Verfy does not handle the Windsurf hook {event!r}")


def _payload(payload: Any) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    return payload


def copilot_payload(payload: Any) -> dict:
    payload = _payload(payload)
    return {**payload, "session_id": payload.get("session_id") or payload.get("sessionId")}


def windsurf_payload(payload: Any) -> dict:
    payload = _payload(payload)
    info = payload.get("tool_info") if isinstance(payload.get("tool_info"), dict) else {}
    return {**payload, "cwd": info.get("cwd") or payload.get("cwd"), "session_id": payload.get("trajectory_id")}


def _decision(out: dict) -> tuple[str, str]:
    h = out["hookSpecificOutput"]
    return h["permissionDecision"], h["permissionDecisionReason"]


def codex_answer(out: dict | None, payload: Any) -> tuple[dict | None, str | None, int]:
    """Codex acts only on deny; it skips an ask and runs the tool, so an ask is sent as a deny."""
    if out is None:
        return None, None, 0
    verdict, reason = _decision(out)
    return _output("deny", (NO_ASK.format(agent="Codex") if verdict == "ask" else "") + reason), None, 0


def gemini_answer(out: dict | None, payload: Any) -> tuple[dict | None, str | None, int]:
    if out is None:
        return {}, None, 0
    verdict, reason = _decision(out)
    # Gemini CLI turns "ask" into its own confirmation prompt (scheduler: hookDecision 'ask' -> ASK_USER), showing systemMessage
    return {"decision": verdict, "reason": reason, "systemMessage": reason}, None, 0


def copilot_answer(out: dict | None, payload: Any) -> tuple[dict | None, str | None, int]:
    """One top-level JSON object, which Copilot CLI and VS Code's Copilot runtime both read. "ask" is sent as it is:
    an interactive session asks the person, and where nobody can answer (autopilot, the cloud agent) Copilot
    treats it as deny. A hook that exits non-zero also denies the call (GitHub's hooks reference)."""
    if out is None:
        return None, None, 0
    verdict, reason = _decision(out)
    return {"permissionDecision": verdict, "permissionDecisionReason": reason}, None, 0


def windsurf_answer(out: dict | None, payload: Any) -> tuple[dict | None, str | None, int]:
    """Windsurf blocks on exit code 2 and shows stderr."""
    if out is None:
        return None, None, 0
    verdict, reason = _decision(out)
    return None, (NO_ASK.format(agent="Windsurf") if verdict == "ask" else "") + reason, 2


# Devin Desktop (Windsurf's new name since 2 June 2026) and Devin CLI share one hook format: PreToolUse with tool_name
# and tool_input, block with exit code 2 (other exit codes, a timeout or unreadable output do not block), no "ask".
# Their tool names are lower case; Claude Code's are not, which is how a Devin call through ~/.claude/settings.json
# (Devin reads it by default) is told apart. https://docs.devin.ai/cli/extensibility/hooks/lifecycle-hooks
DEVIN_TOOLS = {"exec", "read", "write", "edit", "apply_patch", "notebook_read", "notebook_edit", "grep", "glob", "webfetch",
               "get_output", "write_to_process", "kill_shell", "todo_write", "exit_plan_mode", "skill", "run_subagent",
               "read_subagent", "request_scope", "mcp_list_servers", "mcp_list_tools", "mcp_call_tool", "mcp_read_resource"}


def devin_action(payload: dict) -> dict | list[dict]:
    return tool_action("devin", str(payload.get("tool_name") or ""), payload.get("tool_input"))


def devin_answer(out: dict | None, payload: Any) -> tuple[dict | None, str | None, int]:
    if out is None:
        return None, None, 0
    verdict, reason = _decision(out)
    return None, (NO_ASK.format(agent="Devin") if verdict == "ask" else "") + reason, 2


def devin_hook_installed(home: Path | None = None) -> bool:
    try:
        return "verfy hook devin" in devin_config_path(False, home=home).read_text("utf-8-sig")
    except OSError:
        return False


def _output(verdict: str, reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": verdict, "permissionDecisionReason": reason}}


def _reason(decision: dict, receipt: dict | list[dict] | None) -> str:
    rules = "; ".join(f"[{f['rule']}] {f['message'].rstrip('.')}" for f in decision["findings"]) or "no rule matched"
    receipts = receipt if isinstance(receipt, list) else [receipt] if receipt else []
    tail = (" Receipt " if len(receipts) == 1 else " Receipts ") + ", ".join(f"{r['id']} (#{r['seq']})" for r in receipts) + "." if receipts else ""
    if decision["verdict"] == "deny":
        return f"Verfy blocked this action: {rules}.{tail} Do not retry it in another form; explain to the user why it is needed."
    return f"Verfy: this action needs your approval: {rules}.{tail}"


def run_pre_tool_use(payload: Any, *, get_policy: Callable[[str | None], dict], record: Callable[..., dict | None] | None,
                     home: Path | None = None, to_action: Callable[[dict], dict] = action_from_payload) -> dict | None:
    if not isinstance(payload, dict):
        raise ValueError("hook input must be a JSON object")
    if to_action is action_from_payload and not payload.get("tool_name"):
        return fail_safe("no tool name in the hook input")
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    policy = get_policy(cwd)
    tracked = str(payload.get("session_id") or "") if home and (policy.get("session") or {}).get("after_outside_text", "off") != "off" else ""
    actions = to_action(payload)
    actions = actions if isinstance(actions, list) else [actions]
    if not actions:
        raise ValueError("no action in the hook input")
    session = str(payload.get("session_id") or "ses_" + uuid.uuid4().hex[:12])
    # One patch can change several files. Each is checked and the strictest answer wins; then each is recorded with the
    # outcome of the whole call, so a file that passed in a blocked patch is not recorded as written.
    source = sessions.source_of(home, tracked) if tracked else None
    checked = [(action, check(action, policy, {"untrusted": source} if source else None)) for action in actions]
    verdicts = {d["verdict"] for _, d in checked}
    verdict = "deny" if "deny" in verdicts else ("ask" if "ask" in verdicts else "allow")
    status = {"allow": "pending", "ask": "asked", "deny": "blocked"}[verdict]
    if tracked and verdict != "deny":
        for action, decision in checked:
            read = sessions.outside_text(action, decision, policy)
            if read:
                sessions.mark(home, tracked, read)
    findings, receipts = [], []
    for action, decision in checked:
        receipt = None
        if record is not None:
            receipt = record(action=action, decision=decision, session=session, policy=policy, outcome={"status": status, "result_sha256": None})
        if decision["verdict"] != "allow":
            findings += decision["findings"]
            receipts += [receipt] if receipt else []
    if verdict == "allow":
        return None
    return _output(verdict, _reason({"verdict": verdict, "findings": findings}, receipts))


def fail_safe(message: str, mode: str = "ask") -> dict:
    mode = mode if mode in ("ask", "deny") else "ask"
    return _output(mode, f"Verfy could not check this action ({message}), so it was not allowed automatically. Review it yourself.")


# ---------------------------------------------------------------- prompts and tool output

def prompt_secret_reason(text: Any, policy: dict) -> str | None:
    """Why a prompt should not be sent: it holds what looks like a key or token. None when it is fine."""
    if not isinstance(text, str) or policy.get("prompt_secrets", "block") == "off":
        return None
    hits = scan_secrets(text)
    if not hits:
        return None
    what = "; ".join(f"{h['label']} ({h['id']})" for h in hits[:3])
    return ("Verfy stopped this prompt before it was sent: it contains what looks like a secret: " + what + ". A prompt goes to "
            "the model provider and stays in the transcript. Remove the secret, or keep it in an environment variable or a "
            "file the agent reads, and send the prompt again. (\"prompt_secrets\": \"off\" in your policy turns this off.)")


def _record_prompt(record: Callable[..., dict | None] | None, agent: str, payload: dict, policy: dict, reason: str, text: str) -> None:
    if record is None:
        return
    rules = sorted({h["id"] for h in scan_secrets(text)})
    record(agent=agent, action={"server": agent, "tool": "submit_prompt", "arguments": {"prompt": text}},
           decision={"verdict": "deny", "kind": "message", "findings": [{"rule": "VFY-PROMPT-001", "verdict": "deny", "message": reason}] +
                     [{"rule": r, "verdict": "deny", "message": "secret in the prompt"} for r in rules]},
           session=str(payload.get("session_id") or payload.get("conversation_id") or "ses_" + uuid.uuid4().hex[:12]),
           policy=policy, outcome={"status": "blocked", "result_sha256": None})


def side_answer(event: str, payload: dict, get_policy: Callable[[str | None], dict],
                record: Callable[..., dict | None] | None) -> tuple[dict | None, int] | None:
    """The answer for a hook that is not a tool call to check: a prompt about to be sent, a Cursor tool that another
    hook already checks, or a Cursor MCP result. None for a tool call. These never block on an error of their own:
    a prompt guard that stopped every prompt when it broke would be switched off."""
    cursor_event = payload.get("hook_event_name") if event == "cursor" else None
    if event == "cursor" and cursor_event == "preToolUse":
        name = str(payload.get("tool_name") or "")
        if name in ("Shell", "Read") or name.startswith("MCP"):
            return {"permission": "allow"}, 0  # beforeShellExecution, beforeReadFile and beforeMCPExecution check these
        return None
    if event == "prompt" or cursor_event == "beforeSubmitPrompt":
        try:
            cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
            policy = get_policy(cwd)
            text = payload.get("prompt")
            reason = prompt_secret_reason(text, policy)
            if reason:
                _record_prompt(record, "cursor" if event == "cursor" else ("codex" if "turn_id" in payload else "claude-code"), payload, policy, reason, str(text))
        except Exception:  # noqa: BLE001 - see the docstring
            reason = None
        if event == "cursor":
            return ({"continue": False, "user_message": reason} if reason else {"continue": True}), 0
        return ({"decision": "block", "reason": reason} if reason else None), 0
    if cursor_event == "postToolUse":
        try:
            policy = get_policy(payload.get("cwd") if isinstance(payload.get("cwd"), str) else None)
            if policy.get("redact_output", True) is False:
                return {}, 0
            raw = payload.get("tool_output")
            value = raw
            if isinstance(raw, str) and raw[:1] in "[{":
                try:
                    value = json.loads(raw)
                except ValueError:
                    value = raw
            cleaned, hidden = redact_output(value)
            if not hidden:
                return {}, 0
            return {"updated_mcp_tool_output": json.dumps(cleaned) if isinstance(raw, str) and value is not raw else cleaned}, 0
        except Exception:  # noqa: BLE001
            return {}, 0
    return None


def run_hook(event: str, *, stdin: IO[str] | None = None, stdout: IO[str] | None = None,
             get_policy: Callable[[str | None], dict] | None = None, record: Callable[..., dict | None] | None = None,
             fail_mode: Callable[[], str] | None = None, home: Path | None = None) -> int:
    """Entry point for ``verfy hook <event>``. Answers with JSON on stdout and exits 0, except Windsurf, which blocks
    on exit code 2 with the reason on stderr."""
    stdin = stdin or sys.stdin
    stdout = stdout or sys.stdout
    get_policy = get_policy or (lambda cwd: load_policy(None, workspace=cwd))
    if event not in AGENTS:
        print(f"verfy hook: unknown event `{event}` (supported: {', '.join(AGENTS)})", file=sys.stderr)
        return 2
    prepare, to_action, answer = AGENTS[event]
    payload = None
    try:
        raw = stdin.read(MAX_STDIN + 1)
        if len(raw) > MAX_STDIN:
            raise ValueError("hook input is larger than 4 MB")
        payload = prepare(json.loads(raw.removeprefix("\ufeff")))  # Windows PowerShell adds a BOM when its output encoding is UTF-8
        side = side_answer(event, payload, get_policy, record)
        if side is not None:
            body, code = side
            if body is not None:
                stdout.write(json.dumps(body) + "\n")
                stdout.flush()
            return code
        if event == "pre-tool-use" and isinstance(payload, dict) and payload.get("tool_name") in DEVIN_TOOLS:
            # Devin reading Claude Code's settings: answer the way Devin reads, or leave it to Devin's own Verfy hook
            if devin_hook_installed():
                return 0
            _prepare, to_action, answer = AGENTS["devin"]
            if record is not None:
                record = functools.partial(record, agent="devin")
        out = run_pre_tool_use(payload, get_policy=get_policy, record=record, home=home, to_action=to_action)
    except Exception as e:  # noqa: BLE001 - every failure must become ask/deny, never allow
        mode = "ask"
        try:
            mode = fail_mode() if fail_mode else "ask"
        except Exception:  # noqa: BLE001
            mode = "ask"
        out = fail_safe(f"{type(e).__name__}: {str(e)[:200]}", mode)
    body, err, code = answer(out, payload)
    if body is not None:
        stdout.write(json.dumps(body) + "\n")
        stdout.flush()
    if err:
        print(err, file=sys.stderr)
    return code


AGENTS: dict[str, tuple[Callable[[Any], dict], Callable[[dict], Any], Callable[[dict | None, Any], tuple[dict | None, str | None, int]]]] = {
    "pre-tool-use": (lambda p: p, action_from_payload, lambda out, p: (out, None, 0)),
    "cursor": (cursor_payload, cursor_action, lambda out, p: (cursor_answer(out, p.get("hook_event_name") if isinstance(p, dict) else None), None, 0)),
    "codex": (_payload, codex_action, codex_answer),
    "gemini": (_payload, gemini_action, gemini_answer),
    "copilot": (copilot_payload, copilot_action, copilot_answer),
    "windsurf": (windsurf_payload, windsurf_action, windsurf_answer),
    "devin": (_payload, devin_action, devin_answer),
    # Claude Code's UserPromptSubmit: answered by side_answer, never checked as a tool call
    "prompt": (_payload, lambda p: (_ for _ in ()).throw(ValueError("not a tool call")), lambda out, p: (None, None, 0)),
}


# ---------------------------------------------------------------- install

def settings_path(project: bool, cwd: Path | None = None) -> Path:
    if project:
        return (cwd or Path.cwd()) / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def cursor_hooks_path(project: bool, cwd: Path | None = None) -> Path:
    return ((cwd or Path.cwd()) if project else Path.home()) / ".cursor" / "hooks.json"


def with_cursor_hook(config: dict, command: str = CURSOR_COMMAND) -> tuple[dict, bool]:
    """Add Verfy to Cursor's hooks.json. failClosed: by default Cursor lets an action through when a hook crashes."""
    config.setdefault("version", 1)
    hooks = config.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in hooks.json is not an object")
    changed = False
    for event in CURSOR_EVENTS:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"`hooks.{event}` in hooks.json is not a list")
        if not any(isinstance(e, dict) and e.get("command") == command for e in entries):
            entries.append({"command": command, **CURSOR_ENTRY.get(event, {"failClosed": True})})
            changed = True
    return config, changed


def with_hook(settings: dict, command: str = PRE_TOOL_COMMAND, *, event: str = "PreToolUse", entry: dict | None = None) -> tuple[dict, bool]:
    """Add the Verfy hook to a settings object shaped like Claude Code's (Codex and Gemini use the same shape).
    Returns (settings, changed)."""
    out = json.loads(json.dumps(settings))
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in the settings file is not an object")
    pre = hooks.setdefault(event, [])
    if not isinstance(pre, list):
        raise ValueError(f"`hooks.{event}` in the settings file is not a list")
    for group in pre:
        for h in (group or {}).get("hooks", []) if isinstance(group, dict) else []:
            if isinstance(h, dict) and str(h.get("command", "")).startswith("verfy hook"):
                return out, False
    pre.append(entry or {"matcher": "*", "hooks": [{"type": "command", "command": command, "timeout": 10}]})
    return out, True


WINDSURF_EVENTS = ("pre_run_command", "pre_read_code", "pre_write_code", "pre_mcp_tool_use")


def with_claude_hooks(settings: dict) -> tuple[dict, bool]:
    """Claude Code: the PreToolUse hook, and UserPromptSubmit, which stops a prompt that holds a secret."""
    out, a = with_hook(settings)
    out, b = with_hook(out, event="UserPromptSubmit", entry={"hooks": [{"type": "command", "command": PROMPT_COMMAND, "timeout": 10}]})
    return out, a or b


def with_codex_hook(config: dict) -> tuple[dict, bool]:
    """~/.codex/hooks.json; Codex runs it only after the person trusts it in /hooks."""
    out, a = with_hook(config, entry={"matcher": "*", "hooks": [{"type": "command", "command": "verfy hook codex", "timeout": 30}]})
    out, b = with_hook(out, event="UserPromptSubmit", entry={"hooks": [{"type": "command", "command": PROMPT_COMMAND, "timeout": 10}]})
    return out, a or b


def with_gemini_hook(settings: dict) -> tuple[dict, bool]:
    """BeforeTool in ~/.gemini/settings.json. No matcher: every tool. Gemini counts the timeout in milliseconds."""
    return with_hook(settings, event="BeforeTool",
                     entry={"hooks": [{"name": "verfy", "type": "command", "command": "verfy hook gemini", "timeout": 30000}]})


def with_copilot_hook(config: dict) -> tuple[dict, bool]:
    """A hooks file of its own (~/.copilot/hooks/verfy.json or .github/hooks/verfy.json). The CLI runs `bash` or
    `powershell`; VS Code runs `command`."""
    out = json.loads(json.dumps(config))
    out.setdefault("version", 1)
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in the hooks file is not an object")
    pre = hooks.setdefault("preToolUse", [])
    if not isinstance(pre, list):
        raise ValueError("`hooks.preToolUse` in the hooks file is not a list")
    cmd = "verfy hook copilot"
    if any(isinstance(h, dict) and cmd in (h.get("command"), h.get("bash"), h.get("powershell")) for h in pre):
        return out, False
    pre.append({"type": "command", "command": cmd, "bash": cmd, "powershell": cmd, "timeoutSec": 30})
    return out, True


def with_windsurf_hook(config: dict) -> tuple[dict, bool]:
    """Windsurf's hooks.json: one entry per pre-hook. show_output puts Verfy's reason in front of the person."""
    out = json.loads(json.dumps(config))
    hooks = out.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("`hooks` in hooks.json is not an object")
    changed = False
    for event in WINDSURF_EVENTS:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"`hooks.{event}` in hooks.json is not a list")
        if not any(isinstance(e, dict) and e.get("command") == "verfy hook windsurf" for e in entries):
            entries.append({"command": "verfy hook windsurf", "show_output": True})
            changed = True
    return out, changed


def devin_config_path(project: bool, cwd: Path | None = None, home: Path | None = None) -> Path:
    """Devin's config with a "hooks" key: ./.devin/config.json, or ~/.config/devin/config.json (%APPDATA%\\devin on Windows)."""
    if project:
        return (cwd or Path.cwd()) / ".devin" / "config.json"
    home = home or Path.home()
    return home / "AppData" / "Roaming" / "devin" / "config.json" if sys.platform == "win32" else home / ".config" / "devin" / "config.json"


def with_devin_hook(config: dict) -> tuple[dict, bool]:
    """PreToolUse with an empty matcher (every tool) under "hooks" in Devin's config. Devin counts the timeout in seconds."""
    return with_hook(config, entry={"matcher": "", "hooks": [{"type": "command", "command": "verfy hook devin", "timeout": 30}]})


def _under(home_part: tuple[str, ...], project_part: tuple[str, ...]) -> Callable[..., Path]:
    def path(project: bool, cwd: Path | None = None) -> Path:
        return (cwd or Path.cwd()).joinpath(*project_part) if project else Path.home().joinpath(*home_part)
    return path


# agent -> (label, settings file for (project, cwd), add the hook, folder that shows the agent is installed)
INSTALL: dict[str, tuple[str, Callable[..., Path], Callable[[dict], tuple[dict, bool]], tuple[str, ...]]] = {
    "claude-code": ("Claude Code", settings_path, with_claude_hooks, (".claude",)),
    "cursor": ("Cursor", cursor_hooks_path, with_cursor_hook, (".cursor",)),
    "codex": ("Codex", _under((".codex", "hooks.json"), (".codex", "hooks.json")), with_codex_hook, (".codex",)),
    "gemini": ("Gemini CLI", _under((".gemini", "settings.json"), (".gemini", "settings.json")), with_gemini_hook, (".gemini",)),
    "copilot": ("Copilot", _under((".copilot", "hooks", "verfy.json"), (".github", "hooks", "verfy.json")), with_copilot_hook, (".copilot",)),
    "windsurf": ("Windsurf", _under((".codeium", "windsurf", "hooks.json"), (".windsurf", "hooks.json")), with_windsurf_hook, (".codeium", "windsurf")),
    "devin": ("Devin Desktop", devin_config_path, with_devin_hook, (".devin",)),
}
COMMANDS = {"claude-code": PRE_TOOL_COMMAND, "cursor": CURSOR_COMMAND, "codex": "verfy hook codex", "gemini": "verfy hook gemini",
            "copilot": "verfy hook copilot", "windsurf": "verfy hook windsurf",
            "devin": "verfy hook devin"}
