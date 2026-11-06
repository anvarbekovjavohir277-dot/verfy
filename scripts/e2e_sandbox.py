#!/usr/bin/env python3
"""`verfy run --sandbox` against the real sandbox runtime, on Linux and macOS.

The unit tests stop where `srt` starts. This one needs `verfy`, `srt`, curl and the network, and checks what the
operating system actually refuses. Every refusal has a control next to it, so a broken test cannot pass as a safe sandbox.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from verfy.sandbox import windows_homes

HOME = Path.home()
WORK = Path(tempfile.mkdtemp(prefix="verfy-sandbox-")).resolve()
MARK = "verfy-e2e-marker-5f1c"
SERVER = '''
import json, sys
for line in sys.stdin:
    m = json.loads(line)
    if "id" not in m:
        continue
    if m["method"] == "initialize":
        r = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "demo", "version": "1.0.0"}}
    elif m["method"] == "tools/list":
        r = {"tools": [{"name": "echo", "description": "Echo text", "inputSchema": {"type": "object"}}]}
    else:
        r = {}
    print(json.dumps({"jsonrpc": "2.0", "id": m["id"], "result": r}), flush=True)
'''
failed = []


def check(name: str, ok: bool, result: subprocess.CompletedProcess | None = None) -> None:
    print(("ok    " if ok else "FAIL  ") + name, flush=True)
    if not ok:
        failed.append(name)
        if result is not None:
            print(f"      exit {result.returncode}\n      stdout: {result.stdout[-800:]}\n      stderr: {result.stderr[-800:]}", flush=True)


def run(*cmd: str, env: dict | None = None, stdin: str | None = None, timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=WORK, capture_output=True, text=True, timeout=timeout, env=env, input=stdin)


def box(*cmd: str, flags: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    return run("verfy", "run", "--sandbox", *flags, "--", *cmd)


def main() -> int:
    print(f"verfy {run('verfy', '--version').stdout.strip()}, srt {run('srt', '--version').stdout.strip()}, {sys.platform}")

    r = box("sh", "-c", "echo inside")
    check("a command runs", r.returncode == 0 and "inside" in r.stdout, r)
    r = box("sh", "-c", "exit 7")
    check("its exit code comes back", r.returncode == 7, r)

    # the environment
    secret = {**os.environ, "VERFY_E2E_KEY": MARK}
    show = ("/bin/sh", "-c", "echo key=$VERFY_E2E_KEY path=$PATH")
    check("control: the variable is set outside the sandbox", MARK in run(*show, env=secret).stdout)
    r = run("verfy", "run", "--sandbox", "--", *show, env=secret)
    check("an API key in the environment does not reach the command", r.returncode == 0 and MARK not in r.stdout and "path=/" in r.stdout, r)
    r = run("verfy", "run", "--sandbox", "--allow-env", "VERFY_E2E_KEY", "--", *show, env=secret)
    check("--allow-env passes one variable", r.returncode == 0 and MARK in r.stdout, r)

    # reads
    secrets = [HOME / ".ssh" / "verfy-e2e", HOME / ".verfy" / "verfy-e2e", *[h / ".ssh" / "verfy-e2e" for h in windows_homes()]]
    for path in secrets:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(MARK)
        check(f"control: {path} reads outside the sandbox", MARK in run("cat", str(path)).stdout)
        r = box("cat", str(path))
        check(f"{path} does not read inside it", MARK not in r.stdout and r.returncode != 0, r)
    (WORK / "notes.txt").write_text(MARK)
    (WORK / "server.pem").write_text(MARK)
    r = box("cat", "notes.txt")
    check("a file in this folder reads", MARK in r.stdout, r)
    r = box("cat", "server.pem")
    check("a file the policy calls sensitive does not", MARK not in r.stdout and r.returncode != 0, r)

    # writes
    r = box("sh", "-c", "echo written > out.txt")
    check("this folder is writable", r.returncode == 0 and (WORK / "out.txt").exists(), r)
    outside = HOME / "verfy-e2e-outside"
    outside.mkdir(exist_ok=True)
    r = box("sh", "-c", f"echo written > {outside}/file")
    check("outside it is not", r.returncode != 0 and not (outside / "file").exists(), r)
    r = box("sh", "-c", f"echo written > {outside}/file", flags=("--allow-write", str(outside)))
    check("--allow-write opens one folder", r.returncode == 0 and (outside / "file").exists(), r)
    shutil.rmtree(outside, ignore_errors=True)

    # files that decide what runs later, outside the sandbox
    for name in ("verfy.lock", "verfy.policy.json", ".mcp.json", ".claude/settings.json", ".git/hooks/pre-commit", ".git/config"):
        path = WORK / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
        r = box("/bin/sh", "-c", f"echo {MARK} >> {name}")
        check(f"{name} cannot be changed from inside", MARK not in path.read_text(), r)
        path.unlink()
    shutil.rmtree(WORK / ".git", ignore_errors=True)
    shutil.rmtree(WORK / ".claude", ignore_errors=True)

    # the same files when they are not there: a command must not be able to create them either
    for name in ("verfy.lock", "verfy.policy.json", ".mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".claude/skills/x/SKILL.md",
                 ".cursor/hooks.json", ".cursor/mcp.json", ".git/hooks/pre-commit", ".git/config"):
        r = box("/bin/sh", "-c", f'mkdir -p "$(dirname {name})" && echo {MARK} > {name}')
        check(f"a missing {name} cannot be created from inside", r.returncode != 0 and not (WORK / name).exists(), r)
    left = [n for n in ("verfy.lock", "verfy.policy.json", ".mcp.json", ".claude", ".cursor", *([".git"] if sys.platform == "linux" else [])) if (WORK / n).exists()]
    check(f"and the sandbox leaves nothing in their place {left}", not left)
    shutil.rmtree(WORK / ".git", ignore_errors=True)
    (WORK / ".claude").mkdir()
    r = box("/bin/sh", "-c", f"echo {MARK} > .claude/settings.local.json")
    check("nor in a .claude folder that is there", r.returncode != 0 and not (WORK / ".claude" / "settings.local.json").exists(), r)
    r = box("/bin/sh", "-c", "cat .claude/settings.json")
    check("where a missing file reads as missing", "No such file" in r.stderr, r)
    shutil.rmtree(WORK / ".claude", ignore_errors=True)

    # network
    # Python, not curl: Apple's curl cannot finish a TLS handshake inside the sandbox, whatever the settings
    get = "import sys, urllib.request as u; print(u.urlopen(sys.argv[1], timeout=30).read().decode())"
    fetch = (sys.executable, "-c", get, "https://example.com")
    check("control: example.com answers outside the sandbox", "Example Domain" in run(*fetch).stdout)
    r = box(*fetch)
    check("no host is reachable by default", "Example Domain" not in r.stdout and r.returncode != 0, r)
    r = box(*fetch, flags=("--allow-host", "example.com"))
    check("--allow-host opens one host", "Example Domain" in r.stdout, r)
    r = box(sys.executable, "-c", get, "https://www.iana.org", flags=("--allow-host", "example.com"))
    check("and no other", r.returncode != 0, r)
    policy = WORK / "allow.json"
    policy.write_text(json.dumps({"network": {"allow": ["example.com"]}}))
    r = box(*fetch, flags=("--policy", str(policy)))
    check("network.allow in the policy opens a host", "Example Domain" in r.stdout, r)
    policy.write_text(json.dumps({"network": {"deny": ["example.com"]}}))
    r = box(*fetch, flags=("--policy", str(policy), "--allow-host", "example.com"))
    check("network.deny in the policy wins", "Example Domain" not in r.stdout and r.returncode != 0, r)

    # an MCP server, which Claude Code's sandbox does not cover
    (WORK / "server.py").write_text(SERVER)
    r = run("verfy", "scan", "--json", "--", "verfy", "run", "--sandbox", "--", sys.executable, "server.py")
    check("an MCP server answers from inside", r.returncode == 0 and '"echo"' in r.stdout, r)
    hello = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"e2e","version":"1"}}}\n'
    hello += '{"jsonrpc":"2.0","method":"notifications/initialized"}\n{"jsonrpc":"2.0","id":2,"method":"tools/list"}\n'
    hello += '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{}}}\n'
    policy.write_text(json.dumps({"lock": {"on_new": "allow"}}))
    r = run("verfy", "proxy", "--name", "demo", "--policy", str(policy), "--", "verfy", "run", "--sandbox", "--", sys.executable, "server.py", stdin=hello)
    check("and through the gateway too", '"echo"' in r.stdout, r)
    ledger = HOME / ".verfy" / "ledger.jsonl"
    last = json.loads(ledger.read_text().splitlines()[-1]) if ledger.exists() else {}
    check("the gateway's receipt says the server ran in the sandbox", last.get("sandbox") == "srt", r)
    r = run("verfy", "ledger", "verify")
    check("and the ledger still verifies", r.returncode == 0, r)
    r = run(
        "verfy", "scan", "--json", "--timeout", "120", "--", "verfy", "run", "--sandbox", "--allow-write", "~/.npm", "--allow-host", "registry.npmjs.org",
        "--", "npx", "-y", "@modelcontextprotocol/server-memory@2.1.0", timeout=240,
    )
    check("the npx example from the docs works", r.returncode == 0 and "create_entities" in r.stdout, r)

    # an agent, whose hook runs inside the sandbox with it
    r = box("claude", "--version", flags=("--agent",))
    check("Claude Code starts inside", r.returncode == 0 and "Claude Code" in r.stdout, r)
    r = box("claude", "mcp", "list", flags=("--agent",))
    check("and reads a project that has no .mcp.json", r.returncode == 0, r)
    call = json.dumps({"session_id": "e2e", "tool_name": "Read", "tool_input": {"file_path": "notes.txt"}, "cwd": str(WORK)})
    before = len(ledger.read_text().splitlines())
    r = run("verfy", "run", "--sandbox", "--agent", "--", "verfy", "hook", "pre-tool-use", stdin=call)
    lines = ledger.read_text().splitlines()
    check("its hook signs a receipt from inside", r.returncode == 0 and len(lines) == before + 1, r)
    check("and the receipt says so", json.loads(lines[-1]).get("sandbox") == "srt", r)
    r = run("verfy", "run", "--sandbox", "--agent", "--", "verfy", "lock", "check", "--config", "none.json")
    check("verfy reads a missing lock as missing from inside", "PermissionError" not in r.stderr + r.stdout, r)
    # a server that keeps running, and the hook outside it in the same folder
    held = subprocess.Popen(["verfy", "run", "--sandbox", "--", "sleep", "60"], cwd=WORK, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(8)
    r = run("verfy", "hook", "pre-tool-use", stdin=call)
    check("a hook outside goes on working while a sandboxed server runs", r.returncode == 0 and '"ask"' not in r.stdout and '"deny"' not in r.stdout, r)
    held.terminate()
    held.wait(timeout=30)
    time.sleep(2)
    left = [n for n in ("verfy.lock", "verfy.policy.json", ".mcp.json", ".claude", ".cursor") if (WORK / n).exists()]
    check(f"and a stopped server leaves nothing in their place {left}", not left)
    r = box("cat", str(HOME / ".ssh" / "verfy-e2e"), flags=("--agent",))
    check("an agent still cannot read credentials", MARK not in r.stdout and r.returncode != 0, r)
    r = run("verfy", "hook", "pre-tool-use", stdin=call)
    check("outside the sandbox a receipt does not claim it", "sandbox" not in json.loads(ledger.read_text().splitlines()[-1]), r)

    # it never runs unsandboxed
    verfy = shutil.which("verfy")
    marker = WORK / "ran-unsandboxed"
    empty = WORK / "empty"
    empty.mkdir()
    r = run(verfy, "run", "--sandbox", "--", "/bin/sh", "-c", f"touch {marker}", env={**os.environ, "PATH": str(empty)})
    check("no srt: refuses and does not run the command", r.returncode == 3 and not marker.exists(), r)
    fake = WORK / "bin" / "srt"
    fake.parent.mkdir()
    fake.write_text(f"#!/bin/sh\ntouch {marker}\n")
    fake.chmod(0o755)
    r = run(verfy, "run", "--sandbox", "--", "/bin/sh", "-c", "true", env={**os.environ, "PATH": f"{fake.parent}:{os.environ['PATH']}"})
    check("an srt the command could replace: refused", r.returncode == 3 and not marker.exists(), r)

    for path in secrets:
        path.unlink(missing_ok=True)
    shutil.rmtree(WORK, ignore_errors=True)
    print(f"\n{len(failed)} failed" if failed else "\nOK")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
