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
    return pol


def policy_digest(policy: dict) -> str:
    return digest(policy)
