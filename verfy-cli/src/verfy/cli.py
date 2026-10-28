"""Command line interface: ``verfy <command>``."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from . import __version__
from . import agentfiles
from . import imports
from . import discover as cfgscan
from . import hook as hooks
from . import lock as locks
from . import team as teamlib
from . import update as updates
from .gateway import Gateway, verfy_home
from .mcp_client import MCPError, expand, list_tools, list_tools_http
from .policy import DEFAULT_POLICY, TEMPLATES, load_policy, policy_digest
from .precheck import check
from .receipts import Key, Ledger, key_id, public_from, read_ledger, receipt_hash, verify_ledger
from .scanner import scan, tool_pin

EXIT = {"allow": 0, "ask": 1, "deny": 2}
GRADES = "ABCDF"

_tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _tty else text


VCOL = {"allow": "32", "ask": "33", "deny": "31"}
SCOL = {"critical": "31;1", "high": "31", "medium": "33", "low": "36", "info": "2"}
GCOL = {"A": "32", "B": "32", "C": "33", "D": "33", "F": "31;1"}


def home_file(name: str) -> Path:
    return verfy_home() / name


def default_policy_path(cwd: Path | None = None) -> Path | None:
    """Project policy, then the team policy pulled by `verfy team pull`, then the user policy."""
    for p in ((cwd or Path(".")) / "verfy.policy.json", home_file("team") / "policy.json", home_file("policy.json")):
        if p.exists():
            return p
    return None


def lock_file(args=None) -> Path:
    given = getattr(args, "lock", None) if args is not None else None
    if given:
        return Path(given)
    if Path("verfy.lock").exists():
        return Path("verfy.lock")
    return home_file("verfy.lock")


def get_policy(args) -> dict:
    src = getattr(args, "policy", None) or default_policy_path()
    return load_policy(src, workspace=getattr(args, "workspace", None))


def get_key(path: str | None, create: bool = False) -> Key:
    p = Path(path) if path else home_file("key.json")
    if p.exists():
        return Key.load(p)
    if not create:
        raise SystemExit(f"verfy: no signing key at {p}. Run `verfy init` first.")
    k = Key.generate()
    k.save(p)
    print(f"[verfy] created signing key {k.kid} at {p}", file=sys.stderr)
    return k


# ---------------------------------------------------------------- init / keys

def cmd_init(args) -> int:
    home = verfy_home()
    home.mkdir(parents=True, exist_ok=True)
    kp = home / "key.json"
    if kp.exists() and not args.force:
        k = Key.load(kp)
        print(f"Signing key   {kp}  ({k.kid}, kept)")
    else:
        k = Key.generate()
        k.save(kp)
        print(f"Signing key   {kp}  ({k.kid}, new)")
    pp = Path("verfy.policy.json") if args.project else home / "policy.json"
    if pp.exists() and not args.force:
        print(f"Policy        {pp}  (kept)")
    elif args.template:
        pp.write_text(json.dumps(TEMPLATES[args.template]["policy"], indent=2) + "\n", "utf-8")
        print(f"Policy        {pp}  (new, template `{args.template}`; everything not listed uses the defaults)")
    else:
        starter = {
            "agent": "my-agent",
            "on_ask": "deny",
            "tools": {"deny": [], "ask": [], "trust": []},
            "network": {"allow": [], "unknown": "ask"},
            "payments": DEFAULT_POLICY["payments"],
            "rules": [],
        }
        pp.write_text(json.dumps(starter, indent=2) + "\n", "utf-8")
        print(f"Policy        {pp}  (new; everything not listed uses the defaults)")
    print(f"Ledger        {home / 'ledger.jsonl'}")
    print(f"Public key    {k.to_json(False)['public']}")
    known = updates.settings(home).get("mode")
    mode = args.updates or known or (_ask_update_mode() if _interactive() else "manual")
    if mode != known:
        updates.save_settings(home, mode=mode)
    how = "checked once a day, installed in the background" if mode == "auto" else "only when you run `verfy update`"
    print(f"Updates       {mode}: {how} (change with `verfy update --auto {'off' if mode == 'auto' else 'on'}`)")
    print("\nNext:")
    print("  verfy scan --discover           check the MCP servers in your Claude Code / Cursor configs")
    print("  verfy hook install --write      guard every Claude Code tool call (PreToolUse hook)")
    print("  verfy wrap <config.json>        put MCP servers behind the gateway (scan, lock, pre-check, receipts)")
    return 0


def _interactive() -> bool:
    return sys.stdin.isatty() and sys.stdout.isatty()


def _ask_update_mode() -> str:
    print()
    print("How should Verfy update itself?")
    print("  1  manual     only when you run `verfy update`; Verfy never goes online on its own (default)")
    print("  2  automatic  once a day, when you run a verfy command, check for a new version and install it in the background")
    try:
        answer = input("Choose 1 or 2 [1]: ").strip().lower()
    except EOFError:
        answer = ""
    print()
    return "auto" if answer in ("2", "a", "auto", "automatic") else "manual"


def cmd_policy_templates(args) -> int:
    width = max(len(n) for n in TEMPLATES)
    for name, t in TEMPLATES.items():
        print(f"{c(name.ljust(width), '1')}  {t['description']}")
    print("\nPreview one with `verfy policy show NAME`, use it with `verfy policy use NAME [--project]`.")
    return 0


def cmd_policy_show(args) -> int:
    print(json.dumps(TEMPLATES[args.name]["policy"], indent=2))
    return 0


def cmd_policy_use(args) -> int:
    pp = Path("verfy.policy.json") if args.project else home_file("policy.json")
    new = json.dumps(TEMPLATES[args.name]["policy"], indent=2) + "\n"
    if pp.exists():
        if pp.read_text("utf-8") == new:
            print(f"{pp} already uses the `{args.name}` template.")
            return 0
        if not args.force:
            print(f"verfy: {pp} exists. Add --force to replace it (a backup is kept).", file=sys.stderr)
            return 1
        backup = pp.with_name(pp.name + f".bak-{int(time.time())}")
        shutil.copy2(pp, backup)
        print(f"Backup        {backup}")
    pp.parent.mkdir(parents=True, exist_ok=True)
    pp.write_text(new, "utf-8")
    print(f"Policy        {pp}  (template `{args.name}`; everything not listed uses the defaults)")
    return 0


def cmd_update(args) -> int:
    home = verfy_home()
    if args.auto:
        mode = "auto" if args.auto == "on" else "manual"
        updates.save_settings(home, mode=mode)
        if mode == "auto":
            print("Automatic updates on: once a day, when you run a verfy command, Verfy checks for a new version and installs it in the background.")
        else:
            print("Automatic updates off: Verfy goes online to update only when you run `verfy update`.")
        return 0
    how = updates.method()
    try:
        latest = updates.latest(how)
    except updates.UpdateError as e:
        print(f"verfy update: {e}", file=sys.stderr)
        return 3
    updates.save_settings(home, checked_at=time.time())
    mode = updates.settings(home).get("mode", "manual")
    if not updates.newer(latest, __version__):
        print(f"verfy {__version__} is the newest version. Automatic updates: {'on' if mode == 'auto' else 'off'}.")
        return 0
    print(f"verfy {__version__} -> {latest} ({how} install)")
    if args.check:
        print("Run `verfy update` to install it.")
        return 1
    try:
        code = updates.run(how)
    except updates.UpdateError as e:
        print(f"verfy update: {e}", file=sys.stderr)
        return 3
    if code != 0:
        print(f"verfy update: the update did not finish (exit {code}); verfy {__version__} is still installed.", file=sys.stderr)
        return 3
    print(f"Updated to verfy {latest}. Open a new terminal to use it.")
    return 0


def cmd_key(args) -> int:
    k = get_key(args.key)
    if args.json:
        print(json.dumps(k.to_json(False), indent=2))
    else:
        print(f"kid     {k.kid}\npublic  {k.to_json(False)['public']}")
    return 0


# ---------------------------------------------------------------- scan

def print_scan(report: dict) -> None:
    g = report["grade"]
    s = report["summary"]
    print(f"{c(report['server'], '1')}  grade {c(g, GCOL[g])}  {report['score']}/100  "
          f"{report['tool_count']} tools  ({s['critical']} critical, {s['high']} high, {s['medium']} medium, {s['low']} low)")
    for t in report["tools"]:
        caps = ", ".join(t["capabilities"]) or "no special capabilities"
        pin = f"  pin:{t['pin']}" if t["pin"] else ""
        print(f"  {c(t['grade'], GCOL[t['grade']])} {t['score']:>3}  {t['name']}  {c('[' + caps + ']', '2')}{pin}")
        for f in t["findings"]:
            where = f"  ({f['where']})" if f["where"] else ""
            print(f"         {c(f['severity'].upper().ljust(8), SCOL[f['severity']])} {f['rule']}  {f['message']}{c(where, '2')}")
    if report.get("removed_tools"):
        print(f"  removed since last pin: {', '.join(report['removed_tools'])}")


def _scan_one(name: str, data, args) -> dict:
    pins = None
    if args.lock:
        pins = locks.server_pins(locks.load_lock(args.lock), name) or {}
    return scan(data, name, pins)


def print_config_scan(report: dict) -> None:
    print(c("Verfy Scan (static config check)", "1") + "  " + c(report["note"], "2"))
    if not report["configs"]:
        print("  No MCP config files found (looked for .mcp.json, ~/.claude.json, Cursor and Claude Desktop configs).")
    for cfg in report["configs"]:
        print(f"  config  {cfg['path']}  ({cfg['source']})" + (c("  " + cfg["error"], "31") if cfg.get("error") else ""))
    for s in report["servers"]:
        worst = s["findings"][0]["severity"] if s["findings"] else None
        mark = c(worst.upper(), SCOL[worst]) if worst else c("OK", "32")
        print(f"  {mark:<8} {s['server']}  [{s['transport']}]")
        for f in s["findings"]:
            print(f"           {c(f['severity'].upper().ljust(8), SCOL[f['severity']])} {f['rule']}  {f['message']}")


def _stdio_launch(spec: dict) -> tuple[list[str], dict] | None:
    """How to start a stdio server from its MCP config entry, skipping a Verfy gateway in front of it. None for remote servers."""
    if "command" not in spec:
        return None
    cmd = [str(spec["command"]), *[str(a) for a in spec.get("args", [])]]
    if Path(cmd[0]).name.lower().startswith("verfy") and "--" in cmd:
        cmd = cmd[cmd.index("--") + 1:]
    env = {**os.environ, **{k: str(v) for k, v in (spec.get("env") or {}).items()}}
    exe = shutil.which(cmd[0], path=env.get("PATH"))  # finds npx.cmd and friends on Windows
    if exe:
        cmd[0] = exe
    return cmd, env


def _remote_target(spec: dict) -> tuple[str, dict[str, str]]:
    """The address and headers of a remote server, with ${VAR} filled in from the environment.
    `headers` is what most clients use; `http_headers`, `env_http_headers` and `bearer_token_env_var` are Codex CLI's."""
    env = os.environ
    url = expand(cfgscan.server_url(spec) or "", env, "the url")
    headers: dict[str, str] = {}
    for key in ("headers", "http_headers"):
        for k, v in (spec.get(key) or {}).items():
            headers[str(k)] = expand(str(v), env, f"header {k}")
    for k, var in (spec.get("env_http_headers") or {}).items():
        if str(var) not in env:
            raise MCPError(f"header {k} reads {var}, which is not set")
        headers[str(k)] = env[str(var)]
    if spec.get("bearer_token_env_var"):
        var = str(spec["bearer_token_env_var"])
        if var not in env:
            raise MCPError(f"bearer_token_env_var names {var}, which is not set")
        headers["Authorization"] = f"Bearer {env[var]}"
    return url, headers


def _live_tools(spec: dict, timeout: float) -> list[dict] | None:
    """Ask one configured server for its tools: start a stdio server, or call a remote one. None if the entry has neither."""
    launch = _stdio_launch(spec)
    if launch is not None:
        return list_tools(launch[0], timeout=timeout, env=launch[1])["tools"]
    if cfgscan.server_url(spec):
        return list_tools_http(*_remote_target(spec), timeout=timeout)["tools"]
    return None


def _live_reports(found: list[dict], args) -> list[dict]:
    reports = []
    for cfg in found:
        for name, spec in cfg["servers"].items():
            try:
                tools = _live_tools(spec, args.timeout)
                if tools is None:
                    print(f"[verfy] skipping `{name}`: no command or url in its config", file=sys.stderr)
                    continue
                live = {"tools": tools}
            except MCPError as e:
                print(f"[verfy] {name}: {e}", file=sys.stderr)
                continue
            reports.append(_scan_one(name, live["tools"], args))
    return reports


def cmd_scan(args) -> int:
    reports = []
    try:
        if args.discover or args.config:
            if args.discover:
                found = cfgscan.discover(extra=[Path(args.config)] if args.config else [])
            else:
                if not Path(args.config).is_file():
                    raise ValueError(f"no such config file: {args.config}")
                found = cfgscan.read_configs([("given", Path(args.config))])
            static = cfgscan.scan_configs(found)
            if not args.live:
                if args.json:
                    print(json.dumps(static, indent=2, ensure_ascii=False))
                else:
                    print_config_scan(static)
                worst = max((cfgscan.SEVERITY_RANK[f["severity"]] for s in static["servers"] for f in s["findings"]), default=0)
                return 2 if worst >= cfgscan.SEVERITY_RANK["high"] else (1 if worst >= cfgscan.SEVERITY_RANK["medium"] else 0)
            if not args.json:
                print_config_scan(static)
                print(c("\n--live: starting each stdio server and asking each remote one for its tools (you asked for this).", "2"))
            reports = _live_reports(found, args)
        elif args.cmd:
            live = list_tools(args.cmd, timeout=args.timeout)
            reports.append(_scan_one(args.server or live["server"].get("name") or "server", live["tools"], args))
        else:
            if not args.file:
                raise SystemExit("verfy scan: give a file, `-` for stdin, --config FILE or -- COMMAND")
            text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text("utf-8")
            reports.append(_scan_one(args.server or (Path(args.file).stem if args.file != "-" else "server"), json.loads(text), args))
    except (MCPError, ValueError, json.JSONDecodeError) as e:
        print(f"verfy scan: {e}", file=sys.stderr)
        return 3
    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2, ensure_ascii=False))
    else:
        for r in reports:
            print_scan(r)
    if args.fail_under:
        limit = GRADES.index(args.fail_under.upper())
        if any(GRADES.index(r["grade"]) > limit for r in reports):
            return 1
    return 0


# ---------------------------------------------------------------- check

def print_check(r: dict) -> None:
    v = r["verdict"]
    print(f"{c(v.upper(), VCOL[v] + ';1')}  {r['tool']}  ({r['kind']})")
    for f in r["findings"]:
        print(f"  {c(f['verdict'].ljust(5), VCOL[f['verdict']])} {f['rule']}  {f['message']}")


def cmd_check(args) -> int:
    pol = get_policy(args)
    if args.args is not None or args.tool:
        try:
            arguments = json.loads(args.args) if args.args else {}
        except json.JSONDecodeError as e:
            raise SystemExit(f"verfy check: --args is not valid JSON: {e}")
        action = {"tool": args.tool or "tool", "server": args.server or "", "arguments": arguments}
    elif args.command or args.cmd:
        action = {"tool": "shell", "server": args.server or "", "arguments": {"command": " ".join(args.command or args.cmd)}}
    else:
        raise SystemExit("verfy check: give a shell command, or --tool NAME --args JSON")
    r = check(action, pol, {"spent_today": args.spent_today})
    if args.json:
        print(json.dumps(r, indent=2, ensure_ascii=False))
    else:
        print_check(r)
    return EXIT[r["verdict"]]


# ---------------------------------------------------------------- proxy / wrap

def cmd_proxy(args) -> int:
    if not args.cmd:
        raise SystemExit("verfy proxy: put the MCP server command after `--`")
    pol = get_policy(args)
    key = get_key(args.key, create=True)
    name = args.name or Path(args.cmd[0]).name
    gw = Gateway(
        args.cmd, server=name, policy=pol, key=key,
        ledger_path=Path(args.ledger) if args.ledger else home_file("ledger.jsonl"),
        lock_path=lock_file(args), home=verfy_home(),
        scans_dir=home_file("scans"),
    )
    return gw.run()


def cmd_wrap(args) -> int:
    path = Path(args.config)
    cfg = json.loads(path.read_text("utf-8"))
    key = "mcpServers" if "mcpServers" in cfg else ("servers" if "servers" in cfg else None)
    if not key:
        raise SystemExit("verfy wrap: no `mcpServers` in that file")
    exe = shutil.which("verfy") or "verfy"
    wrapped = []
    for name, spec in cfg[key].items():
        if not isinstance(spec, dict) or "command" not in spec:
            continue
        if spec["command"] in ("verfy", exe) or Path(spec["command"]).name == "verfy":
            continue
        extra = ["--policy", args.policy] if args.policy else []
        spec["args"] = ["proxy", "--name", name, *extra, "--", spec["command"], *spec.get("args", [])]
        spec["command"] = exe
        wrapped.append(name)
    out = json.dumps(cfg, indent=2, ensure_ascii=False) + "\n"
    if args.write:
        backup = path.with_suffix(path.suffix + ".verfy-backup")
        shutil.copyfile(path, backup)
        path.write_text(out, "utf-8")
        print(f"Wrapped {len(wrapped)} server(s): {', '.join(wrapped) or 'none'}. Backup: {backup}", file=sys.stderr)
    else:
        sys.stdout.write(out)
        print(f"[verfy] would wrap: {', '.join(wrapped) or 'nothing'} (add --write to save)", file=sys.stderr)
    return 0


# ---------------------------------------------------------------- ledger

def _ledger_path(args) -> Path:
    return Path(args.ledger) if args.ledger else home_file("ledger.jsonl")


def cmd_ledger_verify(args) -> int:
    path = _ledger_path(args)
    try:
        receipts = read_ledger(path)
    except ValueError as e:
        print(f"{c('FAILED', '31;1')}  {path}: {e}")
        return 1
    pub = public_from(args.pub) if args.pub else get_key(args.key).public
    kid = getattr(args, "kid", None) or key_id(pub)
    if getattr(args, "kid", None) or getattr(args, "start_after", None):
        receipts = [r for r in receipts if isinstance(r, dict) and r.get("kid") == kid]
    start_prev = getattr(args, "start_after", None)
    start_seq = receipts[0].get("seq", 0) if start_prev and receipts and isinstance(receipts[0].get("seq"), int) else 0
    res = verify_ledger(receipts, pub, start_prev=start_prev, start_seq=start_seq)
    if args.json:
        print(json.dumps(res, indent=2))
    elif res["ok"]:
        print(f"{c('VERIFIED', '32;1')}  {res['count']} receipts, signed by {key_id(pub)}, chain intact.  head {res['head']}")
    else:
        print(f"{c('FAILED', '31;1')}  {len(res['errors'])} problem(s) in {res['count']} receipts:")
        for e in res["errors"]:
            print(f"  #{e['index']}  {e['error']}")
    return 0 if res["ok"] else 1


def cmd_ledger_show(args) -> int:
    receipts = read_ledger(_ledger_path(args))
    for r in receipts[-args.n:]:
        a, d, o = r.get("action", {}), r.get("decision", {}), r.get("outcome", {})
        v = d.get("verdict", "?")
        print(f"#{r.get('seq', '?'):<4} {r.get('issued_at', '')[:19]}  {c(v.ljust(5), VCOL.get(v, '0'))} {o.get('status', '').ljust(8)} "
              f"{a.get('server', '')}/{a.get('tool', '')}  {','.join(d.get('rules', []))}")
    if not receipts:
        print("No receipts yet.")
    return 0


def cmd_verify(args) -> int:
    return cmd_ledger_verify(args)


def cmd_scitt_export(args) -> int:
    from .scitt import export_statement
    key = get_key(args.key)
    receipts = [r for r in read_ledger(_ledger_path(args)) if isinstance(r, dict) and r.get("kid") == key.kid]
    if args.last:
        receipts = receipts[-args.last:]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for r in receipts:
        name = f"{r.get('seq', 0):08d}-{receipt_hash(r)[7:19]}.cose"
        (out / name).write_bytes(export_statement(r, key, issuer=args.issuer))
    print(f"Wrote {len(receipts)} SCITT signed statement(s) (COSE_Sign1) to {out}.")
    return 0


def cmd_scitt_verify(args) -> int:
    from .scitt import CoseError, verify_statement
    pub = public_from(args.pub) if args.pub else get_key(args.key).public
    bad = 0
    for f in args.files:
        try:
            res = verify_statement(Path(f).read_bytes(), pub)
            r = res["receipt"]
            print(f"{c('VERIFIED', '32;1')}  {f}  receipt #{r.get('seq')} {r.get('decision', {}).get('verdict', '?')}  iss {res['issuer']}")
        except CoseError as e:
            bad += 1
            print(f"{c('FAILED', '31;1')}  {f}: {e}")
    return 1 if bad else 0


# ---------------------------------------------------------------- lock

LSTAT = {"ok": "32", "drift": "31;1", "changed": "31;1", "new": "33", "removed": "36"}
RCOL = {"high": "31;1", "medium": "33", "low": "36"}


def print_explain(old: dict | None, new: dict | None) -> dict:
    """Say in words what changed in a tool definition and how risky it looks, before the raw diff."""
    e = locks.explain(old, new)
    print(f"  {c(('risk ' + e['risk']).ljust(11), RCOL[e['risk']])} {e['summary']}")
    for ch in e["changes"]:
        if ch["what"] not in e["summary"]:
            print(f"  {c('-'.ljust(11), '2')} {ch['what']}")
    return e


def _lock_rows(lock: dict, server_filter: str | None = None) -> list[dict]:
    home = verfy_home()
    names = set(lock["servers"])
    for p in (home / "seen").glob("*.json") if (home / "seen").exists() else []:
        try:
            names.add(str(json.loads(p.read_text("utf-8"))["server"]))
        except (ValueError, KeyError, TypeError):
            continue
    names = sorted(names)
    rows = []
    for server in names:
        if server_filter and server != server_filter:
            continue
        seen = locks.load_seen(home, server)
        for row in locks.compare(lock, server, seen.values()):
            rows.append({"server": server, **row})
    return rows


def cmd_lock_status(args) -> int:
    path = lock_file(args)
    try:
        lock = locks.load_lock(path)
    except locks.LockError as e:
        print(f"{c('INVALID', '31;1')}  {path}: {e}")
        return 2
    rows = _lock_rows(lock, args.server)
    if args.json:
        print(json.dumps({"lock": str(path), "digest": locks.lock_digest(lock), "tools": rows}, indent=2))
    else:
        print(f"{c('verfy.lock', '1')}  {path}  ({sum(len(s['tools']) for s in lock['servers'].values())} tools locked)")
        for r in rows:
            print(f"  {c(r['status'].ljust(7), LSTAT[r['status']])} {r['server']}/{r['tool']}  {(r['locked'] or '-')[:19]}  ->  {(r['current'] or '-')[:19]}")
        if not rows:
            print("  Nothing seen yet. Start a server behind `verfy proxy`, or `verfy lock add FILE --server NAME`.")
    return 2 if any(r["status"] == "drift" for r in rows) else (1 if any(r["status"] in ("new", "removed") for r in rows) else 0)


def cmd_lock_diff(args) -> int:
    lock = locks.load_lock(lock_file(args))
    locked = (lock["servers"].get(args.server) or {}).get("tools", {})
    seen = locks.load_seen(verfy_home(), args.server)
    shown = 0
    for name in sorted(set(locked) | set(seen)):
        if args.tool and name not in args.tool:
            continue
        old = locked.get(name, {}).get("definition")
        new = seen.get(name)
        if old is not None and new is not None and tool_pin(old) == tool_pin(new):
            continue
        print(c(f"{args.server}/{name}", "1"))
        print_explain(old, new)
        print(locks.diff(old, new, f"{args.server}/{name}") or f"{args.server}/{name}: removed")
        shown += 1
    if not shown:
        print(f"No differences between verfy.lock and the last definitions seen from `{args.server}`.")
    return 0


def cmd_lock_approve(args) -> int:
    path = lock_file(args)
    seen = locks.load_seen(verfy_home(), args.server)
    if not seen:
        raise SystemExit(f"verfy: nothing seen from `{args.server}` yet; start it behind `verfy proxy` once first")
    lock = locks.load_lock(path)
    locked = (lock["servers"].get(args.server) or {}).get("tools", {})
    todo = [d for name, d in sorted(seen.items()) if (not args.tool or name in args.tool) and locked.get(name, {}).get("digest") != tool_pin(d)]
    if not todo:
        print(f"verfy.lock already matches `{args.server}`.")
        return 0
    for d in todo:
        print(c(f"{args.server}/{d['name']}", "1"))
        print_explain(locked.get(d["name"], {}).get("definition"), d)
        print(locks.diff(locked.get(d["name"], {}).get("definition"), d, f"{args.server}/{d['name']}"))
        report = scan([d], args.server)
        for f in report["tools"][0]["findings"]:
            print(f"  {c(f['severity'].upper().ljust(8), SCOL[f['severity']])} {f['rule']}  {f['message']}")
    if not args.yes:
        if not sys.stdin.isatty():
            raise SystemExit("verfy lock approve: review the diff above, then run again with --yes")
        answer = input(f"Approve {len(todo)} definition(s) for `{args.server}`? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            print("Nothing changed.")
            return 1

    def apply(lk: dict) -> None:
        for d in todo:
            locks.pin(lk, args.server, d, "user")
    locks.update(path, apply)
    print(f"Approved {len(todo)} tool definition(s) for `{args.server}` in {path}. Restart the client to see them.")
    return 0


def cmd_lock_add(args) -> int:
    from .scanner import extract_tools
    data = json.loads(Path(args.file).read_text("utf-8"))
    tools = extract_tools(data)
    path = lock_file(args)

    def apply(lk: dict) -> None:
        for t in tools:
            locks.pin(lk, args.server, t, "user")
    locks.update(path, apply)
    print(f"Locked {len(tools)} tool definition(s) for `{args.server}` in {path}.")
    return 0


def cmd_lock_verify(args) -> int:
    path = lock_file(args)
    try:
        lock = locks.load_lock(path)
    except locks.LockError as e:
        print(f"{c('INVALID', '31;1')}  {e}")
        return 2
    print(f"{c('VALID', '32;1')}  {path}: every digest matches its definition. lock digest {locks.lock_digest(lock)}")
    return 0


def _file_rows(locked: dict, current: dict, root: Path, user: bool) -> list[dict]:
    """Compare agent files and explain each new or changed one."""
    rows = agentfiles.compare(locked, current)
    for r in rows:
        if r["status"] not in ("changed", "new"):
            continue
        old = (locked.get(r["path"]) or {}).get("text") if r["status"] == "changed" else None
        new = current[r["path"]].get("text") if "text" in current[r["path"]] else agentfiles.text_of(root / r["path"][2:] if user else root / r["path"])
        r["explain"] = agentfiles.explain_text(old, new, changed=r["status"] == "changed")
    return rows


def _print_file_rows(rows: list[dict], locked: dict, current: dict, show_ok: bool = True) -> None:
    for r in rows:
        if r["status"] == "ok" and not show_ok:
            continue
        e = r.get("explain")
        tail = f"  {c(('risk ' + e['risk']).ljust(11), RCOL[e['risk']])} {e['summary']}" if e and (r["status"] == "changed" or e["risk"] != "low") else ""
        print(f"  {c(r['status'].ljust(7), LSTAT[r['status']])} {r['path']}{tail}")
        old, new = (locked.get(r["path"]) or {}).get("text"), (current.get(r["path"]) or {}).get("text")
        if r["status"] == "changed" and old is not None and new is not None:
            print(agentfiles.diff_text(old, new, r["path"]))


def cmd_lock_files(args) -> int:
    """Pin the instruction files, skills, commands, hook settings and plugins an agent loads."""
    notes: list[str] = []
    if args.user:
        root = Path.home()
        path = agentfiles.user_lock_path(verfy_home())
        try:
            locked = agentfiles.load_user_lock(path)
        except ValueError as e:
            print(f"{c('INVALID', '31;1')}  {e}")
            return 2
        current = agentfiles.snapshot(agentfiles.user_files(root, notes), root, user=True)
    else:
        root = Path(args.root).resolve() if args.root else Path.cwd()
        path = Path(args.lock)
        try:
            locked = locks.load_lock(path).get("files") or {}
        except locks.LockError as e:
            print(f"{c('INVALID', '31;1')}  {path}: {e}")
            return 2
        current = agentfiles.snapshot(agentfiles.project_files(root, notes), root, user=False)
    rows = _file_rows(locked, current, root, args.user)
    todo = [r for r in rows if r["status"] != "ok"]

    if args.update:
        if not todo:
            print(f"{path} already matches every agent file.")
            return 0
        _print_file_rows(todo, locked, current)
        if not args.yes:
            if not sys.stdin.isatty():
                raise SystemExit("verfy lock files --update: review the changes above, then run again with --yes")
            if input(f"Write {len(todo)} change(s) to {path}? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Nothing changed.")
                return 1
        if args.user:
            agentfiles.save_user_lock(path, agentfiles.entries(current, "user", keep_text=True))
        else:
            locks.update(path, lambda lk: lk.__setitem__("files", agentfiles.entries(current, "user", keep_text=True)))
        print(f"Wrote {len(todo)} change(s) to {path}." + ("" if args.user else " Commit it so the pull request shows what changed."))
        return 0

    if args.json:
        print(json.dumps({"scope": "user" if args.user else "project", "lock": str(path), "files": rows, "notes": notes}, indent=2))
    else:
        print(f"{c('Verfy agent files', '1')}  {'~ (user)' if args.user else root} against {path}  ({len(current)} found, {len(locked)} locked)")
        _print_file_rows(rows, locked, current, show_ok=args.all)
        for n in notes:
            print(f"  {c('note', '2')}    {n}")
        if not todo:
            print(f"{c('OK', '32;1')}  {len(rows)} agent files match.")
        elif not locked:
            print(f"Nothing locked yet. Review the files above, then run `verfy lock files{' --user' if args.user else ''} --update`.")
    if any(r["status"] == "changed" for r in rows):
        return 2
    return 1 if todo else 0


def cmd_import(args) -> int:
    """Read another scanner's findings; with --save the gateway enforces the high ones."""
    try:
        rep = imports.report(args.file, args.format)
    except (OSError, imports.ImportFormatError) as e:
        print(f"verfy import: {e}", file=sys.stderr)
        return 3
    saved = imports.save(verfy_home(), rep) if args.save else None
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(f"{c('Imported', '1')} {len(rep['findings'])} finding(s) from {rep['source']}  ({args.file}, {rep['file_sha256'][:19]})")
        for f in rep["findings"]:
            where = f"{f['server'] or '?'}/{f['tool']}" if f["tool"] else (f["server"] or "?")
            print(f"  {c(f['severity'].upper().ljust(8), SCOL[f['severity']])} {where}  {f['rule']}  {f['message'][:160]}")
        high = rep["summary"]["high"]
        if saved:
            print(f"Saved to {saved}. The Verfy gateway hides the {high} tool finding(s) rated high and denies calls to those tools.")
        elif high:
            print("Run again with --save so the Verfy gateway hides the tools rated high and denies calls to them.")
    return 2 if rep["summary"]["high"] else (1 if rep["summary"]["medium"] else 0)


def _gh(kind: str, msg: str) -> None:
    """A GitHub Actions annotation, printed only when running inside GitHub Actions."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        msg = msg.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        print(f"::{kind} title=Verfy Lock::{msg}")


def _md(text: str) -> str:
    """Text that is safe inside a Markdown table cell."""
    return text.replace("|", "\\|").replace("\n", " ")


def _step_summary(rows: list[dict], errors: list[str], path: Path) -> None:
    out = os.environ.get("GITHUB_STEP_SUMMARY")
    if not out:
        return
    bad = [r for r in rows if r["status"] != "ok"]
    lines = ["### Verfy Lock", ""]
    if not bad and not errors:
        lines.append(f"All {len(rows)} tool definitions match `{path}`.")
    else:
        lines += ["| Status | Server / tool | Risk | What changed | Locked | Now |", "| --- | --- | --- | --- | --- | --- |"]
        lines += [f"| {r['status']} | `{r['server']}/{r['tool']}` | {(r.get('explain') or {}).get('risk', '')} | {_md((r.get('explain') or {}).get('summary', ''))} | `{(r['locked'] or '-')[:19]}` | `{(r['current'] or '-')[:19]}` |" for r in bad]
        lines += [f"| error | {_md(e)} | | | | |" for e in errors]
        lines += ["", "Review the change, then run `verfy lock check --update` locally and commit `verfy.lock`."]
    with open(out, "a", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def cmd_lock_check(args) -> int:
    """Read the tools of every server in an MCP config (stdio servers are started, remote ones asked over HTTP) and compare them with verfy.lock (for CI)."""
    cfg = Path(args.config)
    if not cfg.is_file():
        print(f"verfy lock check: no such config file: {cfg}", file=sys.stderr)
        return 3
    found = cfgscan.read_configs([("given", cfg)])
    if not found or found[0].get("error"):
        print(f"verfy lock check: {cfg}: {found[0].get('error') if found else 'unreadable'}", file=sys.stderr)
        return 3
    servers = {name: spec for f in found for name, spec in f["servers"].items()}
    path = Path(args.lock)
    lock = locks.load_lock(path)
    wanted = set(args.server or [])
    rows: list[dict] = []
    errors: list[str] = []
    current: dict[str, list[dict]] = {}
    for name, spec in sorted(servers.items()):
        if wanted and name not in wanted:
            continue
        try:
            tools = _live_tools(spec, args.timeout)
        except MCPError as e:
            errors.append(f"`{name}`: {e}")
            continue
        if tools is None:
            print(f"[verfy] skipping `{name}`: no command or url in its config", file=sys.stderr)
            continue
        current[name] = tools
        rows += [{"server": name, **r} for r in locks.compare(lock, name, current[name])]
    gone = [s for s in lock["servers"] if s not in servers and (not wanted or s in wanted)]
    for name in gone:
        rows += [{"server": name, **r} for r in locks.compare(lock, name, [])]
    file_rows: list[dict] = []
    files_now: dict = {}
    if "files" in lock and not wanted:
        root = cfg.resolve().parent
        files_now = agentfiles.snapshot(agentfiles.project_files(root), root, user=False)
        file_rows = _file_rows(lock["files"], files_now, root, user=False)

    if args.update:
        return _lock_check_update(args, path, lock, current, gone, rows, errors, files_now if "files" in lock and not wanted else None, file_rows)

    for r in rows:
        if r["status"] in ("drift", "new"):
            old = ((lock["servers"].get(r["server"]) or {}).get("tools", {}).get(r["tool"]) or {}).get("definition")
            new = next((locks.definition(t) for t in current.get(r["server"], []) if t.get("name") == r["tool"]), None)
            r["explain"] = locks.explain(old, new)
    if args.json:
        print(json.dumps({"lock": str(path), "config": str(cfg), "tools": rows, "files": file_rows, "errors": errors}, indent=2))
    else:
        print(f"{c('Verfy Lock check', '1')}  {cfg} against {path}")
        for r in rows:
            print(f"  {c(r['status'].ljust(7), LSTAT[r['status']])} {r['server']}/{r['tool']}  {(r['locked'] or '-')[:19]}  ->  {(r['current'] or '-')[:19]}")
        if file_rows:
            print(f"{c('Agent files', '1')}  ({len(files_now)} found, {len(lock['files'])} locked)")
            _print_file_rows(file_rows, lock["files"], files_now, show_ok=False)
        for e in errors:
            print(f"  {c('error  ', '31;1')} {e}")
    for r in rows:
        if r["status"] == "drift":
            old = lock["servers"][r["server"]]["tools"][r["tool"]]["definition"]
            new = next(locks.definition(t) for t in current[r["server"]] if t.get("name") == r["tool"])
            if not args.json:
                print(c(f"{r['server']}/{r['tool']}", "1"))
                print_explain(old, new)
                print(locks.diff(old, new, f"{r['server']}/{r['tool']}"))
            _gh("error", f"{r['server']}/{r['tool']} changed since it was locked (possible rug pull), risk {r['explain']['risk']}: {r['explain']['summary']}. Locked {r['locked']}, now {r['current']}.")
        elif r["status"] == "new":
            _gh("error", f"{r['server']}/{r['tool']} is not in {path}. Review it, then run `verfy lock check --update` and commit the lock.")
        elif r["status"] == "removed":
            _gh("warning", f"{r['server']}/{r['tool']} is in {path} but the server no longer serves it.")
    for e in errors:
        _gh("error", f"could not read tools from {e}")
    for r in file_rows:
        if r["status"] == "changed":
            _gh("error", f"{r['path']} changed since it was locked, risk {r['explain']['risk']}: {r['explain']['summary']}. Review the diff, then run `verfy lock files --update` and commit the lock.")
        elif r["status"] in ("new", "removed"):
            _gh("warning", f"agent file {r['path']} is {r['status']} compared with {path}.")
    _step_summary(rows + [{"server": "(file)", "tool": r["path"], "status": "drift" if r["status"] == "changed" else r["status"], "locked": r["locked"], "current": r["current"], "explain": r.get("explain")} for r in file_rows if r["status"] != "ok"], errors, path)
    if any(r["status"] == "drift" for r in rows) or any(r["status"] == "changed" for r in file_rows):
        return 2
    if errors:
        return 3
    if any(r["status"] in ("new", "removed") for r in rows + file_rows):
        return 1
    if not args.json:
        print(f"{c('OK', '32;1')}  {len(rows)} tool definitions" + (f" and {len(file_rows)} agent files" if file_rows else "") + f" match {path}.")
    return 0


def _lock_check_update(args, path: Path, lock: dict, current: dict, gone: list[str], rows: list[dict], errors: list[str],
                       files_now: dict | None = None, file_rows: list[dict] | None = None) -> int:
    if errors:
        for e in errors:
            print(f"verfy lock check: could not read tools from {e}", file=sys.stderr)
        print("Nothing changed: every server must answer before the lock is rewritten.", file=sys.stderr)
        return 3
    todo = [r for r in rows if r["status"] != "ok"]
    file_todo = [r for r in file_rows or [] if r["status"] != "ok"]
    if not todo and not file_todo:
        print(f"{path} already matches every server.")
        return 0
    for r in todo:
        old = ((lock["servers"].get(r["server"]) or {}).get("tools", {}).get(r["tool"]) or {}).get("definition")
        new = next((locks.definition(t) for t in current.get(r["server"], []) if t.get("name") == r["tool"]), None)
        print(c(f"{r['server']}/{r['tool']}", "1"))
        print_explain(old, new)
        print(locks.diff(old, new, f"{r['server']}/{r['tool']}") or f"{r['server']}/{r['tool']}: removed")
        if new is not None:
            for f in scan([new], r["server"])["tools"][0]["findings"]:
                print(f"  {c(f['severity'].upper().ljust(8), SCOL[f['severity']])} {f['rule']}  {f['message']}")
    if file_todo:
        print(c("Agent files", "1"))
        _print_file_rows(file_todo, lock.get("files") or {}, files_now or {})
    todo = todo + file_todo
    if not args.yes:
        if not sys.stdin.isatty():
            raise SystemExit("verfy lock check --update: review the changes above, then run again with --yes")
        if input(f"Write {len(todo)} change(s) to {path}? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Nothing changed.")
            return 1

    def apply(lk: dict) -> None:
        for name, tools in current.items():
            entry = lk["servers"].setdefault(name, {"tools": {}})
            names = set()
            for t in tools:
                d = locks.definition(t)
                names.add(d["name"])
                if (entry["tools"].get(d["name"]) or {}).get("digest") != tool_pin(d):
                    locks.pin(lk, name, t, "user")
            for old in set(entry["tools"]) - names:
                del entry["tools"][old]
        for name in gone:
            lk["servers"].pop(name, None)
        if files_now is not None:
            lk["files"] = agentfiles.entries(files_now, "user", keep_text=True)
    locks.update(path, apply)
    print(f"Wrote {len(todo)} change(s) to {path}. Commit it so the pull request shows what changed.")
    return 0


# ---------------------------------------------------------------- hook

def _hook_policy(cwd: str | None) -> dict:
    return load_policy(default_policy_path(Path(cwd) if cwd else None), workspace=cwd)


def _hook_record(*, action: dict, decision: dict, session: str, policy: dict, outcome: dict) -> dict | None:
    kp = home_file("key.json")
    if not kp.exists():
        return None  # `verfy init` not run yet: still guard, just no receipt
    led = Ledger(home_file("ledger.jsonl"), Key.load(kp))
    return led.append(agent=policy.get("agent", "claude-code"), session=session, action=action, decision=decision,
                      outcome=outcome, policy_sha256=policy_digest(policy),
                      include_args=bool((policy.get("receipts") or {}).get("include_args", False)))


def _hook_fail_mode() -> str:
    try:
        return load_policy(default_policy_path()).get("fail_mode", "ask")
    except Exception:  # noqa: BLE001
        return "ask"


def cmd_hook(args) -> int:
    if args.event == "install":
        path = hooks.settings_path(args.project)
        current = json.loads(path.read_text("utf-8")) if path.exists() else {}
        updated, changed = hooks.with_hook(current)
        if not changed:
            print(f"Verfy hook is already in {path}.")
            return 0
        text = json.dumps(updated, indent=2, ensure_ascii=False) + "\n"
        if not args.write:
            sys.stdout.write(text)
            print(f"[verfy] would update {path} (add --write to save; a backup is kept)", file=sys.stderr)
            return 0
        if path.exists():
            shutil.copyfile(path, path.with_suffix(".json.verfy-backup"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, "utf-8")
        print(f"Added `{hooks.PRE_TOOL_COMMAND}` to {path}.")
        return 0
    return hooks.run_hook(args.event, record=_hook_record, get_policy=_hook_policy, fail_mode=_hook_fail_mode)


# ---------------------------------------------------------------- team

def cmd_team_enroll(args) -> int:
    key = get_key(args.key, create=True)
    code = args.code or os.environ.get("VERFY_ENROLL_CODE")
    if not code:
        raise SystemExit("verfy team enroll: pass --code (from Dashboard > Devices > Add device) or set VERFY_ENROLL_CODE")
    data = teamlib.enroll(verfy_home(), args.url, code, key, args.name)
    print(f"Enrolled device {data['device_id']} ({key.kid}) with {data['url']}" + (f" for {data['org']}" if data.get("org") else "") + ".")
    print("The private key stayed on this machine; the team service only has the public key.")
    return 0


def cmd_team_status(args) -> int:
    team = teamlib.load_team(verfy_home())
    if not team:
        print("Not enrolled. Run `verfy team enroll --url URL --code CODE`.")
        return 1
    state_p = home_file("sync-state.json")
    state = json.loads(state_p.read_text("utf-8")) if state_p.exists() else {}
    print(f"Team     {team['url']}\nDevice   {team['device_id']}  ({team['kid']})\nUploaded through seq {state.get('uploaded_seq', 'none')}")
    return 0


def cmd_sync(args) -> int:
    key = get_key(args.key)
    res = teamlib.sync(verfy_home(), _ledger_path(args), key, allow_args=args.allow_args)
    print(f"Uploaded {res['uploaded']} receipt(s): {res['accepted']} new, {res['duplicates']} already there. Head seq {res['head_seq']}.")
    return 0


def cmd_team_pull(args) -> int:
    res = teamlib.pull(verfy_home())
    pol = res["policy"] or {}
    tdir = home_file("team")
    if isinstance(pol, dict) and isinstance(pol.get("body"), dict):
        load_policy(pol["body"])  # refuse a policy this CLI cannot load
        from .fileio import atomic_write
        atomic_write(tdir / "policy.json", json.dumps(pol["body"], indent=2, ensure_ascii=False) + "\n")
        print(f"Team policy v{pol.get('version')} saved to {tdir / 'policy.json'}")
    approved = [r for r in (res["locks"] or {}).get("locks", []) if r.get("status") == "approved" and isinstance(r.get("definition"), dict)]
    good = [r for r in approved if tool_pin(r["definition"]) == r.get("digest")]
    if len(good) != len(approved):
        print(f"[verfy] ignored {len(approved) - len(good)} team lock(s) whose digest does not match the definition", file=sys.stderr)

    def apply(lk: dict) -> None:
        for r in good:
            locks.pin(lk, r["server_id"], r["definition"], "team")
    if good:
        locks.update(lock_file(args), apply)
    print(f"Applied {len(good)} team-approved lock(s) to {lock_file(args)}.")
    return 0


def cmd_team_propose(args) -> int:
    seen = locks.load_seen(verfy_home(), args.server)
    if args.tool not in seen:
        raise SystemExit(f"verfy: `{args.server}/{args.tool}` has not been seen; start the server behind `verfy proxy` first")
    d = seen[args.tool]
    res = teamlib.propose_lock(verfy_home(), args.server, d, tool_pin(d))
    print(f"Proposed {args.server}/{args.tool} {tool_pin(d)[:19]} for team review (status: {res.get('status', 'pending')}).")
    return 0


def _registry_rows(lock: dict) -> list[dict]:
    """Locked pins, plus the pins last seen from each server when they differ from the lock."""
    home = verfy_home()
    rows = []
    for server, entry in sorted(lock["servers"].items()):
        seen = locks.load_seen(home, server)
        for name, t in sorted(entry["tools"].items()):
            rows.append({"server": server, "tool": name, "which": "locked", "pin": t["digest"]})
            if name in seen and tool_pin(seen[name]) != t["digest"]:
                rows.append({"server": server, "tool": name, "which": "seen", "pin": tool_pin(seen[name])})
    return rows


def cmd_team_registry(args) -> int:
    """Verfy Registry: report this team's pins, or ask how widespread a pin is."""
    path = lock_file(args)
    lock = locks.load_lock(path)
    rows = _registry_rows(lock)
    if not rows:
        print(f"No tools in {path} yet.")
        return 0
    if args.action == "report":
        pins = sorted({r["pin"] for r in rows if r["which"] == "locked"})
        stored = teamlib.registry_report(verfy_home(), pins)
        print(f"Reported {len(pins)} pin(s) from {path} to Verfy Registry ({stored} new or refreshed). Only SHA-256 pins were sent: no server names, tool names or definitions.")
        return 0
    found = teamlib.registry_lookup(verfy_home(), [r["pin"] for r in rows])
    for r in rows:
        r.update(found.get(r["pin"]) or {"orgs": None, "first_seen": None, "yours": False})
    if args.json:
        print(json.dumps({"lock": str(path), "pins": rows}, indent=2))
        return 0
    print(f"{c('Verfy Registry', '1')}  pins in {path}" + (" and definitions seen since" if any(r["which"] == "seen" for r in rows) else ""))
    for r in rows:
        if r["orgs"]:
            note = c(f"seen by {r['orgs']} teams", "32") + (f" since {str(r['first_seen'])[:10]}" if r.get("first_seen") else "")
        else:
            note = c("seen by fewer than 3 teams", "33") + (" (yours among them)" if r["yours"] else "")
        print(f"  {r['which'].ljust(6)} {r['server']}/{r['tool']}  {r['pin'][:19]}  {note}")
    if any(r["which"] == "seen" and not r["orgs"] for r in rows):
        print("A changed definition that few other teams have seen can be very new, or served only to you: review the diff (`verfy lock diff SERVER`) before approving it.")
    return 0


# ---------------------------------------------------------------- demo

def cmd_demo(args) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="verfy-demo-"))
    env = {**os.environ, "VERFY_HOME": str(tmp)}
    py = sys.executable
    gateway = [py, "-m", "verfy", "proxy", "--name", "demo", "--", py, "-m", "verfy.demo_server", "--poisoned"]
    pol = {"agent": "demo-agent", "workspace": str(tmp / "project"), "on_ask": "deny"}
    (tmp / "policy.json").write_text(json.dumps(pol), "utf-8")
    calls = [
        ("run_command", {"command": "pytest -q"}),
        ("run_command", {"command": "rm -rf ~"}),
        ("run_command", {"command": "git push --force origin main"}),
        ("read_file", {"path": "~/.ssh/id_rsa"}),
        ("write_file", {"path": "notes.md", "content": "hello"}),
        ("fetch_url", {"url": "http://169.254.169.254/latest/meta-data/"}),
        ("send_payment", {"amount": 12, "currency": "USD", "to": "acme"}),
        ("send_payment", {"amount": 500, "currency": "USD", "to": "acme"}),
        ("add_numbers", {"a": 1, "b": 2, "sidenote": "..."}),
    ]
    msgs = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "demo", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]
    for i, (name, a) in enumerate(calls, 2):
        msgs.append({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": a}})
    proc = subprocess.Popen(gateway, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env, bufsize=1)
    replies = {}

    def ask(m: dict) -> None:
        proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        if "id" not in m:
            return
        while True:
            line = proc.stdout.readline()
            if not line:
                raise SystemExit("verfy demo: the gateway stopped unexpectedly")
            r = json.loads(line)
            if r.get("id") == m["id"]:
                replies[m["id"]] = r
                return

    try:
        for m in msgs:
            ask(m)
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
    print(c("Verfy demo", "1") + f"  (a fake MCP server behind the gateway; files in {tmp})\n")
    listed = [t["name"] for t in replies.get(1, {}).get("result", {}).get("tools", [])]
    print(f"Tools the agent can see: {', '.join(listed)}")
    print(c("  add_numbers was hidden: its description tries to steal ~/.ssh/id_rsa\n", "2"))
    for i, (name, a) in enumerate(calls, 2):
        r = replies.get(i, {})
        res = r.get("result", {})
        blocked = res.get("isError") is True
        text = (res.get("content") or [{}])[0].get("text", "")
        mark = c("BLOCKED", "31;1") if blocked else c("RAN    ", "32;1")
        print(f"{mark}  {name} {json.dumps(a)[:70]}")
        if blocked:
            for ln in text.splitlines()[1:-1]:
                print(c("         " + ln, "2"))
    key = Key.load(tmp / "key.json")
    res = verify_ledger(read_ledger(tmp / "ledger.jsonl"), key.public)
    print()
    print(f"Ledger: {res['count']} signed receipts, " + (c("chain verified", "32;1") if res["ok"] else c("verification FAILED", "31;1")))
    print(f"Try:    VERFY_HOME={tmp} verfy ledger show")
    return 0 if res["ok"] else 1


# ---------------------------------------------------------------- main

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="verfy", description="Verfy: scan MCP tools, pre-check agent actions, sign receipts.")
    ap.add_argument("--version", action="version", version=f"verfy {__version__}")
    sub = ap.add_subparsers(dest="command_name", metavar="command")

    p = sub.add_parser("init", help="create a signing key and a starter policy")
    p.add_argument("--project", action="store_true", help="write verfy.policy.json in this folder instead of ~/.verfy")
    p.add_argument("--force", action="store_true")
    p.add_argument("--template", choices=list(TEMPLATES), help="start from a ready-made policy (see `verfy policy templates`)")
    p.add_argument("--updates", choices=updates.MODES, help="update automatically, or only when you run `verfy update` (asked the first time)")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("policy", help="ready-made policies: strict, read-only, ci")
    pol = p.add_subparsers(dest="policy_cmd", metavar="subcommand", required=True)
    x = pol.add_parser("templates", help="list the templates")
    x.set_defaults(fn=cmd_policy_templates)
    x = pol.add_parser("show", help="print a template")
    x.add_argument("name", choices=list(TEMPLATES))
    x.set_defaults(fn=cmd_policy_show)
    x = pol.add_parser("use", help="write a template as your policy (~/.verfy/policy.json, or ./verfy.policy.json with --project)")
    x.add_argument("name", choices=list(TEMPLATES))
    x.add_argument("--project", action="store_true", help="write ./verfy.policy.json instead")
    x.add_argument("--force", action="store_true", help="replace an existing policy (a backup is kept)")
    x.set_defaults(fn=cmd_policy_use)

    p = sub.add_parser("update", help="install the newest version, or choose automatic updates")
    p.add_argument("--check", action="store_true", help="only report whether a newer version exists (exit 1 if it does)")
    p.add_argument("--auto", choices=["on", "off"], help="turn automatic updates on or off")
    p.set_defaults(fn=cmd_update)

    p = sub.add_parser("key", help="show the public signing key")
    p.add_argument("--key")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_key)

    p = sub.add_parser("scan", help="scan MCP tool definitions")
    p.add_argument("file", nargs="?", help="tools/list JSON file, or - for stdin")
    p.add_argument("--config", help="check how the servers in an MCP config are launched (static)")
    p.add_argument("--discover", action="store_true", help="find Claude Code, Cursor and Claude Desktop MCP configs and check them (static)")
    p.add_argument("--live", action="store_true", help="with --config/--discover: also read each server's tools (stdio servers are started, remote ones asked over HTTP) and scan them")
    p.add_argument("--server", help="name to show for the server")
    p.add_argument("--lock", help="verfy.lock to compare tool definitions with (drift shows as VFY-SCAN-014)")
    p.add_argument("--fail-under", metavar="GRADE", help="exit 1 if any server grades worse than this (A-F)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("check", help="pre-check one action (exit 0 allow, 1 ask, 2 deny)")
    p.add_argument("command", nargs="*", help="a shell command, e.g. verfy check rm -rf ~")
    p.add_argument("--tool")
    p.add_argument("--args", help="tool arguments as JSON")
    p.add_argument("--server")
    p.add_argument("--policy")
    p.add_argument("--workspace")
    p.add_argument("--spent-today", type=float, default=0.0)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_check)

    p = sub.add_parser("proxy", help="run an MCP server behind the Verfy gateway")
    p.add_argument("--name", help="server name used in receipts and verfy.lock")
    p.add_argument("--policy")
    p.add_argument("--workspace")
    p.add_argument("--ledger")
    p.add_argument("--lock", help="verfy.lock path (default ./verfy.lock if present, else ~/.verfy/verfy.lock)")
    p.add_argument("--key")
    p.set_defaults(fn=cmd_proxy)

    p = sub.add_parser("wrap", help="put every server in an MCP config behind the gateway")
    p.add_argument("config")
    p.add_argument("--policy")
    p.add_argument("--write", action="store_true", help="save the change (a backup is kept)")
    p.set_defaults(fn=cmd_wrap)

    p = sub.add_parser("ledger", help="show or verify signed receipts")
    lsub = p.add_subparsers(dest="ledger_cmd", metavar="action")
    v = lsub.add_parser("verify", help="check every signature and the hash chain")
    v.add_argument("--ledger")
    v.add_argument("--key")
    v.add_argument("--pub", help="public key (base64url or key file) of the signer")
    v.add_argument("--kid", help="only verify receipts signed by this key id (files with several devices)")
    v.add_argument("--start-after", metavar="HASH", help="the chain starts mid-way: the first receipt's prev must equal HASH")
    v.add_argument("--json", action="store_true")
    v.set_defaults(fn=cmd_ledger_verify)
    s = lsub.add_parser("show", help="list recent receipts")
    s.add_argument("--ledger")
    s.add_argument("-n", type=int, default=20)
    s.set_defaults(fn=cmd_ledger_show)

    p = sub.add_parser("verify", help="verify the ledger (same as `verfy ledger verify`)")
    p.add_argument("--ledger")
    p.add_argument("--key")
    p.add_argument("--pub", help="public key (base64url or key file) of the signer")
    p.add_argument("--kid", help="only verify receipts signed by this key id (files with several devices)")
    p.add_argument("--start-after", metavar="HASH", help="the chain starts mid-way: the first receipt's prev must equal HASH")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("scitt", help="export receipts as SCITT signed statements (COSE_Sign1) and verify them")
    sc = p.add_subparsers(dest="scitt_cmd", metavar="action")
    x = sc.add_parser("export", help="write one COSE_Sign1 signed statement per receipt")
    x.add_argument("--out", required=True, help="folder for the .cose files")
    x.add_argument("--ledger")
    x.add_argument("--key")
    x.add_argument("--issuer", help="CWT issuer (default: the device key id)")
    x.add_argument("--last", type=int, help="only the newest N receipts")
    x.set_defaults(fn=cmd_scitt_export)
    x = sc.add_parser("verify", help="check .cose statements: COSE signature, subject and the receipt inside")
    x.add_argument("files", nargs="+")
    x.add_argument("--pub", help="public key (base64url or key file) of the signer")
    x.add_argument("--key")
    x.set_defaults(fn=cmd_scitt_verify)

    p = sub.add_parser("lock", help="Verfy Lock: pinned MCP tool definitions and drift")
    lk = p.add_subparsers(dest="lock_cmd", metavar="action")
    x = lk.add_parser("status", help="locked vs last seen digests (exit 2 on drift)")
    x.add_argument("server", nargs="?")
    x.add_argument("--lock")
    x.add_argument("--json", action="store_true")
    x.set_defaults(fn=cmd_lock_status)
    x = lk.add_parser("diff", help="show what changed in a server's tool definitions")
    x.add_argument("server")
    x.add_argument("--tool", action="append")
    x.add_argument("--lock")
    x.set_defaults(fn=cmd_lock_diff)
    x = lk.add_parser("approve", help="review the diff and accept new or changed definitions")
    x.add_argument("server")
    x.add_argument("--tool", action="append")
    x.add_argument("--yes", action="store_true", help="approve without the interactive prompt (after reviewing the diff)")
    x.add_argument("--lock")
    x.set_defaults(fn=cmd_lock_approve)
    x = lk.add_parser("add", help="lock the tools in a saved tools/list answer")
    x.add_argument("file")
    x.add_argument("--server", required=True)
    x.add_argument("--lock")
    x.set_defaults(fn=cmd_lock_add)
    x = lk.add_parser("check", help="read the tools of the servers in an MCP config (stdio and remote) and compare them with verfy.lock (for CI)")
    x.add_argument("--config", default=".mcp.json", help="MCP config with the servers to check (default .mcp.json)")
    x.add_argument("--lock", default="verfy.lock", help="lock file to compare with (default ./verfy.lock)")
    x.add_argument("--server", action="append", help="only check this server (repeatable)")
    x.add_argument("--update", action="store_true", help="show every change and write the current definitions to the lock")
    x.add_argument("--yes", action="store_true", help="with --update: write without the interactive prompt (after reviewing)")
    x.add_argument("--timeout", type=float, default=60.0)
    x.add_argument("--json", action="store_true")
    x.set_defaults(fn=cmd_lock_check)
    x = lk.add_parser("files", help="pin the files an agent loads (CLAUDE.md, AGENTS.md, rules, skills, commands, hooks, plugins)")
    x.add_argument("--user", action="store_true", help="files in your home folder (user instructions, skills, installed plugins), pinned in ~/.verfy/agent-files.lock")
    x.add_argument("--update", action="store_true", help="review the changes and write them to the lock")
    x.add_argument("--yes", action="store_true", help="with --update: write without asking (CI or scripts)")
    x.add_argument("--lock", default="verfy.lock", help="project lock file (default ./verfy.lock)")
    x.add_argument("--root", help="repository folder (default: the current folder)")
    x.add_argument("--all", action="store_true", help="also list files that did not change")
    x.add_argument("--json", action="store_true")
    x.set_defaults(fn=cmd_lock_files)

    x = lk.add_parser("verify", help="check that verfy.lock is well formed and untampered")
    x.add_argument("--lock")
    x.set_defaults(fn=cmd_lock_verify)

    p = sub.add_parser("import", help="read findings from Snyk Agent Scan (--json) or Cisco MCP Scanner (--format raw)")
    p.add_argument("file", help="the other scanner's JSON output")
    p.add_argument("--format", choices=["auto", "snyk", "cisco"], default="auto")
    p.add_argument("--save", action="store_true", help="keep the findings so the Verfy gateway hides tools rated high")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_import)

    p = sub.add_parser("hook", help="Claude Code hook (pre-tool-use) or `hook install`")
    p.add_argument("event", choices=["pre-tool-use", "install"])
    p.add_argument("--project", action="store_true", help="install into ./.claude/settings.json instead of ~/.claude/settings.json")
    p.add_argument("--write", action="store_true", help="save the settings change (a backup is kept)")
    p.set_defaults(fn=cmd_hook)

    p = sub.add_parser("sync", help="upload new receipts to Verfy Cloud (same as `verfy team sync`)")
    p.add_argument("--ledger")
    p.add_argument("--key")
    p.add_argument("--allow-args", action="store_true", help="also upload receipts that contain tool arguments")
    p.set_defaults(fn=cmd_sync)

    p = sub.add_parser("team", help="Verfy Cloud for your team: enroll, sync, pull policy and locks, propose lock updates")
    tm = p.add_subparsers(dest="team_cmd", metavar="action")
    x = tm.add_parser("enroll", help="register this device's public key with your team")
    x.add_argument("--url", required=True, help="the Verfy Cloud address, https://verfy-tech.vercel.app")
    x.add_argument("--code", help="one-time enrollment code from Dashboard > Devices")
    x.add_argument("--name", help="device name shown in the dashboard")
    x.add_argument("--key")
    x.set_defaults(fn=cmd_team_enroll)
    x = tm.add_parser("status", help="show enrollment and upload state")
    x.set_defaults(fn=cmd_team_status)
    x = tm.add_parser("sync", help="upload new receipts")
    x.add_argument("--ledger")
    x.add_argument("--key")
    x.add_argument("--allow-args", action="store_true")
    x.set_defaults(fn=cmd_sync)
    x = tm.add_parser("pull", help="fetch the team policy and team-approved locks")
    x.add_argument("--lock")
    x.set_defaults(fn=cmd_team_pull)
    x = tm.add_parser("propose", help="ask team admins to approve a changed tool definition")
    x.add_argument("server")
    x.add_argument("tool")
    x.set_defaults(fn=cmd_team_propose)
    x = tm.add_parser("registry", help="Verfy Registry: has anyone else seen these tool definitions? (report | lookup)")
    x.add_argument("action", choices=["report", "lookup"], help="report: send this team's pins (SHA-256 only, no names); lookup: how many teams saw each pin")
    x.add_argument("--lock", help="verfy.lock to read (default ./verfy.lock, else ~/.verfy/verfy.lock)")
    x.add_argument("--json", action="store_true")
    x.set_defaults(fn=cmd_team_registry)

    p = sub.add_parser("demo", help="see the gateway block a poisoned tool and risky calls")
    p.set_defaults(fn=cmd_demo)
    return ap


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd_after = None
    if "--" in argv:
        i = argv.index("--")
        argv, cmd_after = argv[:i], argv[i + 1:]
    ap = build_parser()
    args = ap.parse_args(argv)
    args.cmd = cmd_after
    if not hasattr(args, "fn"):
        if getattr(args, "command_name", None) in ("ledger", "lock", "team", "scitt"):
            ap.parse_args([args.command_name, "--help"])
        ap.print_help()
        return 0
    try:
        code = args.fn(args)
    except BrokenPipeError:
        return 0
    except (FileNotFoundError, PermissionError) as e:
        print(f"verfy: {e}", file=sys.stderr)
        return 3
    except teamlib.TeamError as e:
        print(f"verfy: {e}", file=sys.stderr)
        return 4
    except locks.LockError as e:
        print(f"verfy: {e}", file=sys.stderr)
        return 2
    # the opt-in daily update check: only for commands a person types, never the hook, gateway or sync
    if args.command_name in AUTO_UPDATE_AFTER and sys.stderr.isatty() and not os.environ.get("CI"):
        line = updates.maybe_auto(verfy_home(), __version__)
        if line:
            print(line, file=sys.stderr)
    return code


AUTO_UPDATE_AFTER = {"init", "key", "scan", "check", "wrap", "ledger", "verify", "scitt", "lock", "team", "demo"}


if __name__ == "__main__":
    sys.exit(main())
