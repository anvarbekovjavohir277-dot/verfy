"""Pin the code of an MCP server, not only the text of its tools.

A server started through a package runner (npx, bunx, pnpm dlx, yarn dlx, uvx, pipx) can change its code without
changing a single tool definition, and a config that says ``pkg@latest`` or no version at all runs whatever the
registry serves that day. ``verfy lock check --update`` therefore records, next to the tools, the exact package the
config starts and the registry's own hash of that release:

* npm: ``dist.integrity`` of the version (the sha512 that npm itself checks when it installs it);
* PyPI: the sha256 of every file of the release, combined into one value.

``verfy lock check`` then fails when the config starts another version, drops the version, or when the registry no
longer reports the same files for the locked version. No model is involved; everything here is a string compare.
"""

from __future__ import annotations

import hashlib
import json
import re
import urllib.parse
import urllib.request
from typing import Callable

from . import __version__
from .discover import written_version

NPM = "https://registry.npmjs.org"
PYPI = "https://pypi.org/pypi"
TIMEOUT = 20.0


class PackageError(Exception):
    pass


def fetch_json(url: str, timeout: float = TIMEOUT) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": f"verfy/{__version__} (lock)"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https registry URLs
            data = json.loads(r.read(20_000_000))
    except Exception as e:
        raise PackageError(f"could not read {url.split('/')[2]}: {e}") from None
    if not isinstance(data, dict):
        raise PackageError(f"unexpected answer from {url.split('/')[2]}")
    return data


def package_name(pkg: str, ecosystem: str) -> str:
    """The package without its version: `@scope/name@1.2.3` is `@scope/name`, `name==1.2.3` is `name`."""
    if ecosystem == "npm":
        scope, rest = ("@", pkg[1:]) if pkg.startswith("@") else ("", pkg)
        return scope + rest.split("@", 1)[0]
    return re.split(r"[=<>~!@\[ ;]", pkg, maxsplit=1)[0]


def _npm_url(name: str, part: str) -> str:
    return f"{NPM}/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(part, safe='')}"


def integrity(pkg: str, ecosystem: str, fetch: Callable[[str], dict] | None = None) -> str:
    """The registry's hash of the exact release `pkg` names. Raises PackageError when it names no exact version."""
    version = written_version(pkg, ecosystem)
    if not version:
        raise PackageError(f"`{pkg}` names no exact version")
    fetch = fetch or fetch_json
    name = package_name(pkg, ecosystem)
    if ecosystem == "npm":
        dist = fetch(_npm_url(name, version)).get("dist") or {}
        value = dist.get("integrity")
        if not isinstance(value, str) or not value.startswith("sha512-"):
            raise PackageError(f"npm reports no sha512 integrity for {name}@{version}")
        return value
    files = fetch(f"{PYPI}/{urllib.parse.quote(name)}/{urllib.parse.quote(version)}/json").get("urls") or []
    rows = sorted(f"{f.get('filename')} {(f.get('digests') or {}).get('sha256')}" for f in files if isinstance(f, dict))
    if not rows or any(r.endswith(" None") for r in rows):
        raise PackageError(f"PyPI lists no files with sha256 for {name}=={version}")
    return "pypi-files-sha256:" + hashlib.sha256("\n".join(rows).encode()).hexdigest()


def latest(pkg: str, ecosystem: str, fetch: Callable[[str], dict] | None = None) -> str:
    """The version the registry serves as latest today."""
    fetch = fetch or fetch_json
    name = package_name(pkg, ecosystem)
    if ecosystem == "npm":
        v = (fetch(_npm_url(name, "latest")) or {}).get("version")
    else:
        v = (fetch(f"{PYPI}/{urllib.parse.quote(name)}/json").get("info") or {}).get("version")
    if not isinstance(v, str) or not re.match(r"^\d+\.\d+", v):
        raise PackageError(f"the registry reports no latest version for {name}")
    return v


def check(locked_pkg: str | None, locked_integrity: str | None, written: str | None, ecosystem: str | None,
          fetch: Callable[[str], dict] | None = None) -> dict:
    """Compare what a config starts with what the lock recorded.

    Returns ``{"status": "ok"|"changed"|"unpinned"|"new", "what": str, "integrity": str|None}``; ``changed`` fails
    the check like a changed tool, ``new`` like a new one, ``unpinned`` is a warning (nothing to compare with yet).
    Raises PackageError when the registry cannot be read.
    """
    if written is None:  # not started through a package runner (any more)
        if locked_pkg:
            return {"status": "changed", "what": f"no longer started as the package `{locked_pkg}`", "integrity": None}
        return {"status": "ok", "what": "", "integrity": None}
    exact = written_version(written, ecosystem or "")
    if not exact:
        if locked_pkg:
            return {"status": "changed", "what": f"starts `{written}`, which runs whatever the registry serves today; the lock has `{locked_pkg}`", "integrity": None}
        return {"status": "unpinned", "what": f"starts `{written}` with no exact version, so its code can change at any time; pin it with `verfy lock pin`", "integrity": None}
    now = integrity(written, ecosystem or "", fetch)  # also for a changed one, so `--update` can record it
    if locked_pkg and written != locked_pkg:
        return {"status": "changed", "what": f"starts `{written}`; the lock has `{locked_pkg}`", "integrity": now}
    if not locked_pkg:
        return {"status": "new", "what": f"`{written}` is not in the lock yet", "integrity": now}
    if locked_integrity and now != locked_integrity:
        return {"status": "changed", "what": f"the registry now serves different files for `{written}` (locked {locked_integrity[:23]}, now {now[:23]})", "integrity": now}
    return {"status": "ok", "what": "" if locked_integrity else "integrity not recorded yet; `verfy lock check --update` adds it", "integrity": now}
