#!/usr/bin/env python3
"""`verfy run --sandbox` from native Windows, which sends it to `verfy run` inside WSL2.

Needs WSL2 with verfy and srt inside it, and Verfy on Windows. scripts/e2e_sandbox.py checks the sandbox itself inside
WSL2; this one checks the way in from Windows, with a control next to every refusal.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

MARK = "verfy-e2e-marker-7a2d"
failed = []


def check(name: str, ok: bool, result: subprocess.CompletedProcess | None = None) -> None:
    print(("ok    " if ok else "FAIL  ") + name, flush=True)
    if not ok:
        failed.append(name)
        if result is not None:
            print(f"      exit {result.returncode}\n      stdout: {result.stdout[-400:]}\n      stderr: {result.stderr[-400:]}", flush=True)


def run(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(args, input=stdin, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)


def box(*args: str, flags: tuple[str, ...] = (), stdin: str | None = None) -> subprocess.CompletedProcess:
    return run("verfy", "run", "--sandbox", *flags, "--", *args, stdin=stdin)


def wsl(*args: str) -> subprocess.CompletedProcess:
    return run("wsl.exe", "--exec", *args)


def main() -> int:
    work = Path(tempfile.mkdtemp(prefix="verfy-wsl-", dir=Path.home())).resolve()
    os.chdir(work)
    here = wsl("wslpath", "-a", str(work).replace("\\", "/")).stdout.strip()
    check("control: this folder has a path inside WSL", here.startswith("/mnt/"))

    r = box("uname", "-r")
    check("a command started on Windows runs in WSL2", r.returncode == 0 and "WSL2" in r.stdout, r)
    r = box("sh", "-c", "exit 7")
    check("its exit code comes back", r.returncode == 7, r)
    r = box("pwd")
    check("it starts in this folder", r.stdout.strip() == here, r)
    r = box("sh", "-c", 'printf "%s|%s" "$1" "$2"', "x", "a b", "c'd")
    check("arguments stay whole", r.stdout == "a b|c'd", r)
    r = box("cat", stdin=MARK)
    check("stdin reaches it, as an MCP server needs", r.stdout == MARK, r)

    r = box("sh", "-c", f"echo {MARK} > written.txt")
    check("this folder is writable", r.returncode == 0 and MARK in (work / "written.txt").read_text("utf-8"), r)

    secret = Path.home() / ".ssh" / "verfy-e2e-wsl"
    secret.parent.mkdir(exist_ok=True)
    secret.write_text(MARK, "utf-8")
    inside = wsl("wslpath", "-a", str(secret).replace("\\", "/")).stdout.strip()
    check("control: the Windows user's key reads from WSL outside the sandbox", MARK in wsl("cat", inside).stdout)
    r = box("cat", inside)
    check("the Windows user's key does not read inside it", MARK not in r.stdout and r.returncode != 0, r)
    secret.unlink()

    url = "https://example.com/"
    check("control: example.com answers from WSL outside the sandbox", "Example Domain" in wsl("curl", "-sS", "--max-time", "20", url).stdout)
    r = box("curl", "-sS", "--max-time", "20", url)
    check("no host is reachable by default", "Example Domain" not in r.stdout, r)
    r = box("curl", "-sS", "--max-time", "20", url, flags=("--allow-host", "example.com"))
    check("--allow-host reaches WSL", "Example Domain" in r.stdout, r)

    print(f"\n{len(failed)} failed" if failed else "\nOK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
