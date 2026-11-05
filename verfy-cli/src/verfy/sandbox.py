"""Check and set up Claude Code's own sandbox. Verfy is not a sandbox and does not build one.

The two cover different ground. Claude Code's sandbox wraps shell commands at the operating system level, so it also
holds a script the agent wrote, which Verfy cannot follow. It does not cover MCP servers, hooks or the built-in Read,
Edit and WebFetch tools, and those are what Verfy watches. The sandbox is off by default, and even when on it lets
commands read most of the machine, credentials included, unless told otherwise. This module reports what is missing
and writes it. https://code.claude.com/docs/en/sandboxing
"""

from __future__ import annotations

import json
import os
from pathlib import Path

# read by default inside the sandbox; a command has no business with these
CREDENTIALS = ["~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.docker/config.json", "~/.netrc", "~/.npmrc", "~/.config/gcloud", "~/.verfy"]


def scopes(cwd: Path, home: Path) -> list[Path]:
    """Claude Code's settings files, the one that wins first."""
    return [cwd / ".claude" / "settings.local.json", cwd / ".claude" / "settings.json", home / ".claude" / "settings.json"]


def _read(path: Path) -> dict:
    try:
        data = json.loads(path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _lists(value: dict | None, key: str) -> list:
    got = (value or {}).get(key)
    return got if isinstance(got, list) else []


def effective(cwd: Path, home: Path) -> dict:
    """The sandbox settings in force: a value from the nearest file that has it, lists merged across files."""
    found = [s for s in (_read(p).get("sandbox") for p in scopes(cwd, home)) if isinstance(s, dict)]

    def first(key: str):
        return next((s[key] for s in found if key in s), None)

    nets = [s["network"] for s in found if isinstance(s.get("network"), dict)]
    return {
        "enabled": first("enabled"),
        "allowUnsandboxedCommands": first("allowUnsandboxedCommands"),
        "excludedCommands": sorted({str(x) for s in found for x in _lists(s, "excludedCommands")}),
        "denyRead": sorted({str(x) for s in found for x in _lists(s.get("filesystem"), "denyRead")}),
        "allowedDomains": sorted({str(x) for s in found for x in _lists(s.get("network"), "allowedDomains")}),
        "allowUnixSockets": sorted({str(x) for n in nets for x in _lists(n, "allowUnixSockets")}),
        "allowAllUnixSockets": next((n["allowAllUnixSockets"] for n in nets if "allowAllUnixSockets" in n), None),
    }


def _too_wide(domain: str) -> bool:
    """`*`, or a wildcard over a whole top-level domain such as `*.com`."""
    host = domain.rsplit(":", 1)[0] if domain.count(":") == 1 else domain
    return host in ("*", "*.*") or (host.startswith("*.") and "." not in host[2:])


def _f(rule: str, severity: str, message: str) -> dict:
    return {"rule": rule, "severity": severity, "message": message}


def check(state: dict, allowed_hosts: list[str], windows: bool = os.name == "nt") -> list[dict]:
    out = []
    if windows:
        out.append(_f("VFY-SBX-006", "medium", "Claude Code's sandbox does not run on native Windows; commands run unsandboxed there. Use WSL2 or a container."))
    if state["enabled"] is not True:
        out.append(_f("VFY-SBX-001", "high", "The sandbox is off, so a script the agent writes and runs is held by nothing but your permissions."))
    if state["allowUnsandboxedCommands"] is not False:
        out.append(_f("VFY-SBX-002", "medium", "A command that fails in the sandbox can ask to run outside it. Set allowUnsandboxedCommands to false."))
    missing = [p for p in CREDENTIALS if p not in state["denyRead"]]
    if missing:
        out.append(_f("VFY-SBX-003", "medium", "Sandboxed commands can read " + ", ".join(missing) + ". Add them to filesystem.denyRead."))
    hosts = [h for h in allowed_hosts if h not in state["allowedDomains"]]
    if hosts:
        out.append(_f("VFY-SBX-004", "low", "Your Verfy policy allows " + ", ".join(hosts) + ", but the sandbox does not, so commands will stop to ask."))
    if state.get("allowAllUnixSockets") is True or any(s.endswith("docker.sock") for s in state.get("allowUnixSockets", [])):
        out.append(_f("VFY-SBX-007", "high", "Commands can reach the Docker socket, and whoever controls Docker controls the machine, sandbox or not."))
    wide = [d for d in state["allowedDomains"] if _too_wide(d)]
    if wide:
        out.append(_f("VFY-SBX-008", "medium", "These allowed domains reach most of the internet: " + ", ".join(wide) + ". List the hosts you need."))
    if state["excludedCommands"]:
        out.append(_f("VFY-SBX-005", "low", "These run outside the sandbox: " + ", ".join(state["excludedCommands"]) + "."))
    return out


def with_sandbox(settings: dict, allowed_hosts: list[str]) -> tuple[dict, bool]:
    """Add what is missing to a settings object. Nothing there is removed. Returns (settings, changed).

    failIfUnavailable is left alone: on a machine without the sandbox it stops Claude Code from starting."""
    out = json.loads(json.dumps(settings))
    box = out.setdefault("sandbox", {})
    if not isinstance(box, dict):
        raise ValueError("`sandbox` in settings.json is not an object")
    box["enabled"] = True
    box["allowUnsandboxedCommands"] = False
    files = box.setdefault("filesystem", {})
    files["denyRead"] = _lists(files, "denyRead") + [p for p in CREDENTIALS if p not in _lists(files, "denyRead")]
    if allowed_hosts:
        net = box.setdefault("network", {})
        net["allowedDomains"] = _lists(net, "allowedDomains") + [h for h in allowed_hosts if h not in _lists(net, "allowedDomains")]
    return out, out != settings
