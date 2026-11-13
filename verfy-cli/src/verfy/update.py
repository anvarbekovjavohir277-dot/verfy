"""Updates: ``verfy update`` and the opt-in daily check.

Nothing here runs from the hook or the gateway, so Guard never waits for the
network. With updates set to manual (the default) Verfy only goes online when
you run ``verfy update``.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from .fileio import atomic_write

INSTALL_SH = "https://verfy.dev/install.sh"
INSTALL_PS1 = "https://verfy.dev/install.ps1"
# the web page, not the API: GitHub's API allows few anonymous calls per IP, and many people share one
RELEASES = "https://github.com/verfy-dev/verfy-releases/releases/latest"
PYPI = "https://pypi.org/pypi/verfy/json"
CHECK_EVERY = 24 * 3600
MODES = ("manual", "auto")


class UpdateError(Exception):
    pass


def method() -> str:
    """How this copy was installed: standalone, pip, pipx, uv or source."""
    if getattr(sys, "frozen", False):
        return "standalone"
    try:
        from importlib.metadata import distribution
        dist = distribution("verfy")
        if Path(str(dist.locate_file("verfy"))).resolve() != Path(__file__).resolve().parent:
            return "source"  # this code is not the installed copy (a checkout on PYTHONPATH)
        url = json.loads(dist.read_text("direct_url.json") or "{}")
    except Exception:  # not installed as a distribution: running from a checkout
        return "source"
    if url.get("dir_info", {}).get("editable") or str(url.get("url", "")).startswith("file:"):
        return "source"
    prefix = sys.prefix.replace("\\", "/").lower()
    if "/pipx/" in prefix:
        return "pipx"
    if "/uv/tools/" in prefix:
        return "uv"
    return "pip"


def version_key(v: str) -> tuple:
    parts = re.findall(r"\d+", v.split("+")[0])
    return tuple(int(x) for x in parts[:3]) + (0 if re.search(r"[a-z]", v.split("+")[0]) else 1,)


def newer(latest: str, current: str) -> bool:
    return version_key(latest) > version_key(current)


def latest(how: str, timeout: float = 5.0) -> str:
    """The newest version this install method can get."""
    url = RELEASES if how == "standalone" else PYPI
    if how == "standalone" and os.name != "nt" and shutil.which("curl"):
        # the standalone build's own TLS settings may not find this system's certificates; curl does
        try:
            r = subprocess.run(["curl", "-fsSIL", "--max-time", str(int(timeout) + 2), "-o", os.devnull, "-w", "%{url_effective}", url],
                               capture_output=True, text=True, timeout=timeout + 5)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise UpdateError(f"could not reach github.com: {e}") from None
        if r.returncode != 0:
            raise UpdateError(f"could not reach github.com (curl exit {r.returncode})")
        v = r.stdout.strip().rstrip("/").rsplit("/tag/", 1)[-1].removeprefix("v")
        if not re.match(r"^\d+\.\d+\.\d+[a-z0-9.]*$", v):
            raise UpdateError(f"unexpected version {v!r} from github.com")
        return v
    req = urllib.request.Request(url, method="HEAD" if how == "standalone" else "GET", headers={"Accept": "application/json", "User-Agent": "verfy-update"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 (fixed https URL)
            if how == "standalone":
                # .../releases/latest redirects to .../releases/tag/v<version>
                v = r.geturl().rstrip("/").rsplit("/tag/", 1)[-1].removeprefix("v")
            else:
                v = str((json.loads(r.read(2_000_000)).get("info") or {}).get("version", ""))
    except Exception as e:
        raise UpdateError(f"could not reach {url.split('/')[2]}: {e}") from None
    if not re.match(r"^\d+\.\d+\.\d+[a-z0-9.]*$", v):
        raise UpdateError(f"unexpected version {v!r} from {url.split('/')[2]}")
    return v


def settings_path(home: Path) -> Path:
    return home / "update.json"


def settings(home: Path) -> dict:
    try:
        d = json.loads(settings_path(home).read_text("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(home: Path, **changes) -> dict:
    d = {**settings(home), **changes}
    home.mkdir(parents=True, exist_ok=True)
    atomic_write(settings_path(home), json.dumps(d, indent=2) + "\n")
    return d


def command(how: str) -> tuple[list[str], dict] | None:
    """The command that installs the newest version, and its environment; None when there is none."""
    env = {**os.environ, "VERFY_NO_MODIFY_PATH": "1"}
    if how == "standalone":
        exe = Path(sys.executable).resolve()
        # <root>/current/verfy.exe on Windows, <root>/<version>/verfy elsewhere
        env["VERFY_INSTALL_DIR"] = str(exe.parent.parent)
        if os.name == "nt":
            return ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
                    f'$f = Join-Path $env:TEMP ("verfy-install-" + [guid]::NewGuid() + ".ps1"); Invoke-RestMethod {INSTALL_PS1} -OutFile $f; & $f; $c = $LASTEXITCODE; Remove-Item $f; exit $c'], env
        return ["sh", "-c", f'f=$(mktemp) && {{ curl -fsSL {INSTALL_SH} -o "$f" || wget -qO "$f" {INSTALL_SH}; }} && sh "$f"; c=$?; rm -f "$f"; exit $c'], env
    if how == "pip":
        return [sys.executable, "-m", "pip", "install", "--upgrade", "--disable-pip-version-check", "verfy"], env
    if how == "pipx":
        return ["pipx", "upgrade", "verfy"], env
    if how == "uv":
        return ["uv", "tool", "upgrade", "verfy"], env
    return None


def run(how: str) -> int:
    cmd = command(how)
    if cmd is None:
        raise UpdateError("this copy runs from a source checkout; update it with git pull")
    try:
        return subprocess.run(cmd[0], env=cmd[1]).returncode
    except FileNotFoundError:
        raise UpdateError(f"`{cmd[0][0]}` is not available to run the update") from None


def start_in_background(how: str, log: Path) -> bool:
    cmd = command(how)
    if cmd is None:
        return False
    log.parent.mkdir(parents=True, exist_ok=True)
    out = open(log, "a", encoding="utf-8")  # noqa: SIM115 (the child owns it)
    out.write(f"\n--- {time.strftime('%Y-%m-%d %H:%M:%S')} {' '.join(cmd[0][:3])}\n")
    out.flush()
    kw: dict = {"stdin": subprocess.DEVNULL, "stdout": out, "stderr": subprocess.STDOUT, "env": cmd[1]}
    if os.name == "nt":
        kw["creationflags"] = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    try:
        subprocess.Popen(cmd[0], **kw)  # noqa: S603
    except OSError:
        return False
    return True


def maybe_auto(home: Path, current: str, now: float | None = None) -> str | None:
    """With updates set to auto, check at most once a day and start an update in the background.

    Returns a line to print, or None. Never raises."""
    try:
        s = settings(home)
        if s.get("mode") != "auto":
            return None
        now = time.time() if now is None else now
        if now - float(s.get("checked_at", 0)) < CHECK_EVERY:
            return None
        save_settings(home, checked_at=now)
        how = method()
        v = latest(how, timeout=3.0)
        if not newer(v, current):
            return None
        if start_in_background(how, home / "update.log"):
            return f"verfy: updating {current} -> {v} in the background (log: {home / 'update.log'}). New terminals get it when it finishes."
    except Exception:
        return None
    return None
