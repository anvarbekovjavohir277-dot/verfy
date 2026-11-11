"""Verfy policy: what an agent may do without asking.

A policy is plain JSON. Anything you leave out falls back to the defaults in
``data/default_policy.json``, so a two-line policy file is a complete policy.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any

from .canonical import digest

DEFAULT_POLICY: dict[str, Any] = json.loads((Path(__file__).parent / "data" / "default_policy.json").read_text("utf-8"))
TEMPLATES: dict[str, dict] = json.loads((Path(__file__).parent / "data" / "templates.json").read_text("utf-8"))


def merge(base: Any, over: Any) -> Any:
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = merge(base.get(k), v) if k in base else copy.deepcopy(v)
        return out
    return copy.deepcopy(over)


def load_policy(source: str | os.PathLike | dict | None = None, *, workspace: str | None = None, home: str | None = None) -> dict:
    """Merge a policy (path, dict or None) over the defaults and fill in paths."""
    user: dict = {}
    if isinstance(source, dict):
        user = source
    elif source:
        user = json.loads(Path(source).read_text("utf-8"))
    if not isinstance(user, dict):
        raise ValueError("a policy must be a JSON object")
    pol = merge(DEFAULT_POLICY, user)
    if not pol.get("home"):
        pol["home"] = home or os.path.expanduser("~")
    if not pol.get("workspace"):
        pol["workspace"] = workspace or os.getcwd()
    if pol["on_ask"] not in ("deny", "allow", "elicit", "team"):
        raise ValueError("on_ask must be deny, allow, elicit or team")
    wait = pol.get("approval_timeout", 120)
    if not isinstance(wait, int) or isinstance(wait, bool) or not 10 <= wait <= 900:
        raise ValueError("approval_timeout must be a whole number of seconds from 10 to 900")
    if pol.get("fail_mode") not in ("ask", "deny"):
        raise ValueError("fail_mode must be ask or deny (Verfy never fails open)")
    if (pol.get("session") or {}).get("after_outside_text") not in ("off", "ask", "deny"):
        raise ValueError("session.after_outside_text must be off, ask or deny")
    if (pol.get("lock") or {}).get("on_new") not in ("ask", "deny", "allow"):
        raise ValueError("lock.on_new must be ask, deny or allow")
    # read with the default "block" where it is used; left out of the policy so its hash, and receipts, stay the same
    if pol.get("prompt_secrets", "block") not in ("block", "off"):
        raise ValueError("prompt_secrets must be block or off")
    return pol


STRICTNESS = {"off": 0, "allow": 0, "ask": 1, "deny": 2, "block": 2}


def _stricter(a: Any, b: Any) -> Any:
    return b if STRICTNESS.get(b, -1) > STRICTNESS.get(a, 0) else a


def _strings(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def tighten(base: dict, project: Any) -> dict:
    """``base`` with what a repository's policy adds. A policy that arrives with a clone is not yours, so it can make Verfy
    stricter and nothing else: what would loosen it (trust, disabled rules, allow lists, raw receipts) is left out."""
    if not isinstance(project, dict):
        raise ValueError("a policy must be a JSON object")
    out = copy.deepcopy(base)

    def part(name: str) -> dict:
        v = project.get(name)
        return v if isinstance(v, dict) else {}

    files, net, tools, pay = part("files"), part("network"), part("tools"), part("payments")
    for key in ("sensitive", "deny_write"):
        out["files"][key] = list(dict.fromkeys([*out["files"][key], *_strings(files.get(key))]))
    out["network"]["deny"] = list(dict.fromkeys([*out["network"]["deny"], *_strings(net.get("deny"))]))
    for key in ("deny", "ask"):
        out["tools"][key] = list(dict.fromkeys([*out["tools"].get(key, []), *_strings(tools.get(key))]))
    out["files"]["outside_workspace"] = _stricter(out["files"].get("outside_workspace", "ask"), files.get("outside_workspace"))
    out["network"]["unknown"] = _stricter(out["network"].get("unknown", "ask"), net.get("unknown"))
    out["lock"]["on_new"] = _stricter(out["lock"].get("on_new", "ask"), part("lock").get("on_new"))
    out["fail_mode"] = _stricter(out["fail_mode"], project.get("fail_mode"))
    if project.get("prompt_secrets") == "block":
        out["prompt_secrets"] = "block"
    out["session"]["after_outside_text"] = _stricter(out["session"].get("after_outside_text", "off"), part("session").get("after_outside_text"))
    if project.get("on_ask") == "deny":
        out["on_ask"] = "deny"
    for key in ("max_per_call", "ask_above", "daily_budget"):
        v = pay.get(key)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and (out["payments"].get(key) is None or v < out["payments"][key]):
            out["payments"][key] = v
    rules = project.get("rules")
    if isinstance(rules, list):
        out["rules"] = [*out.get("rules", []), *[r for r in rules if isinstance(r, dict) and isinstance(r.get("pattern"), str) and r.get("verdict", "ask") in ("ask", "deny")]]
    return out


def policy_digest(policy: dict) -> str:
    return digest(policy)
