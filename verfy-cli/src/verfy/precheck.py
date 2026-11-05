"""Pre-check an agent action before it runs.

An action is what an MCP client sends in ``tools/call``::

    {"tool": "run_command", "server": "shell", "arguments": {"command": "rm -rf ~"}}

``check(action, policy)`` returns ``allow``, ``ask`` or ``deny`` with the
rules that fired. Verfy works out what kind of action it is (shell, file,
network, payment, message, SQL) from the tool name and its arguments, so it
needs no per-tool configuration.
"""

from __future__ import annotations

import re
from typing import Any

from ._util import (
    PATTERNS, VERDICT_RANK, first_match, flatten_strings, host_match, is_within, name_match, normpath,
    resolve, rx, scan_secrets, to_posix, words,
)
from .policy import DEFAULT_POLICY, load_policy

VERSION = "verfy.check/1"

SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
WRAPPERS = {"nohup", "time", "command", "builtin", "exec", "nice", "ionice", "stdbuf", "timeout", "watch", "caffeinate"}
NETWORK_CMDS = {"curl", "wget", "nc", "ncat", "netcat", "scp", "rsync", "ftp", "sftp", "http", "https", "httpie", "telnet", "socat", "aria2c", "Invoke-WebRequest", "iwr", "irm"}
READERS = {"cat", "less", "more", "head", "tail", "base64", "xxd", "od", "strings", "grep", "egrep", "rg", "awk", "sed", "cut", "sort", "uniq", "tac", "nl", "bat", "jq", "gpg", "openssl", "cp", "scp", "rsync", "tar", "zip", "7z", "source", "."}
SYSTEM_DIRS = {"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/root", "/sbin", "/srv", "/sys", "/usr", "/var", "/System", "/Library", "/Applications", "/Users", "/private"}
WINDOWS_DIRS = {"/c/windows", "/c/program files", "/c/program files (x86)", "/c/programdata", "/c/users"}
SECRET_ENV = r"\$\{?[A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE|CREDENTIAL|ACCESS_KEY|AUTH)[A-Za-z0-9_]*\}?"
CONTENT_KEYS = {"content", "contents", "text", "data", "body", "new_string", "old_string", "patch", "diff", "new_str", "file_text", "edits"}
EXAMPLE_SUFFIXES = (".example", ".sample", ".template", ".dist")

PUBLISH = {
    "npm": {"publish", "unpublish", "deprecate"}, "pnpm": {"publish"}, "yarn": {"publish", "npm"},
    "twine": {"upload"}, "cargo": {"publish", "yank"}, "gem": {"push", "yank"}, "poetry": {"publish"},
    "flit": {"publish"}, "docker": {"push"}, "podman": {"push"},
    "kubectl": {"delete", "apply", "replace", "scale", "rollout", "drain", "edit", "patch", "create", "cordon", "taint"},
    "helm": {"install", "upgrade", "uninstall", "delete", "rollback"},
    "terraform": {"apply", "destroy", "import", "taint"}, "tofu": {"apply", "destroy", "import"},
    "pulumi": {"up", "destroy", "update"}, "fly": {"deploy", "destroy"}, "flyctl": {"deploy", "destroy"},
    "firebase": {"deploy"}, "wrangler": {"deploy", "publish"}, "serverless": {"deploy", "remove"},
    "sls": {"deploy", "remove"}, "heroku": {"destroy", "releases:rollback", "ps:scale", "config:set", "apps:destroy"},
}


def _f(rule: str, verdict: str, message: str) -> dict:
    return {"rule": rule, "verdict": verdict, "message": message}


# ---------------------------------------------------------------- shell parsing

def tokenize(cmd: str) -> list[dict]:
    """Split a command line into simple commands.

    Each segment has ``argv``, redirect targets (``out``/``inp``) and a
    ``pipe`` number shared by commands joined with ``|``.
    """
    segs: list[dict] = []
    cur = {"argv": [], "out": [], "inp": [], "pipe": 0}
    pipe = 0
    tok: list[str] = []
    has_tok = False
    redirect = None  # "out" | "inp" | "skip"
    i, n = 0, len(cmd)
    q = None
    depth = 0

    def end_token():
        nonlocal tok, has_tok, redirect
        if has_tok:
            t = "".join(tok)
            if redirect:
                if redirect != "skip" and not t.startswith("&"):
                    cur[redirect].append(t)
                redirect = None
            else:
                cur["argv"].append(t)
        tok, has_tok = [], False

    def end_seg(new_pipe: bool):
        nonlocal cur, pipe
        end_token()
        if cur["argv"] or cur["out"] or cur["inp"]:
            segs.append(cur)
        if new_pipe:
            pipe += 1
        cur = {"argv": [], "out": [], "inp": [], "pipe": pipe}

    while i < n:
        c = cmd[i]
        if q == "'":
            if c == "'":
                q = None
            else:
                tok.append(c)
            i += 1
            continue
        if q == '"':
            if c == "\\" and i + 1 < n and cmd[i + 1] in '$`"\\\n':
                tok.append(cmd[i + 1])
                i += 2
                continue
            if c == '"':
                q = None
            else:
                tok.append(c)
            i += 1
            continue
        if depth > 0:
            tok.append(c)
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            tok.append(cmd[i + 1])
            has_tok = True
            i += 2
            continue
        if c in "'\"":
            q = c
            has_tok = True
            i += 1
            continue
        if c == "$" and i + 1 < n and cmd[i + 1] == "(":
            tok.append("$(")
            has_tok = True
            depth = 1
            i += 2
            continue
        if c == "`":
            j = cmd.find("`", i + 1)
            j = n if j < 0 else j
            tok.append(cmd[i:j + 1])
            has_tok = True
            i = j + 1
            continue
        if c in " \t":
            end_token()
            i += 1
            continue
        if c == "\n" or c == ";":
            end_seg(True)
            i += 1
            continue
        if c == "&":
            if i + 1 < n and cmd[i + 1] == "&":
                end_seg(True)
                i += 2
                continue
            if i + 1 < n and cmd[i + 1] == ">":
                end_token()
                redirect = "out"
                i += 2 + (1 if i + 2 < n and cmd[i + 2] == ">" else 0)
                continue
            if tok and tok[-1] in "<>":
                tok.append(c)
                i += 1
                continue
            end_seg(True)
            i += 1
            continue
        if c == "|":
            if i + 1 < n and cmd[i + 1] == "|":
                end_seg(True)
                i += 2
                continue
            end_seg(False)
            i += 1
            continue
        if c in "()":
            end_seg(True)
            i += 1
            continue
        if c in "<>":
            digits = "".join(tok)
            if has_tok and not digits.isdigit():
                end_token()
            else:
                tok, has_tok = [], False
            kind = "out" if c == ">" else "inp"
            i += 1
            if i < n and cmd[i] in ">|":
                i += 1
            if i < n and cmd[i] == "&":
                kind = "skip"
                i += 1
            elif c == "<" and i < n and cmd[i] == "<":
                kind = "skip"
                i += 1
            redirect = kind
            continue
        tok.append(c)
        has_tok = True
        i += 1
    end_seg(False)
    return segs


def _normalize(seg: dict) -> dict:
    argv = list(seg["argv"])
    s = {"name": "", "args": [], "out": seg["out"], "inp": seg["inp"], "pipe": seg["pipe"], "sudo": False, "xargs": False}
    while argv:
        a = argv[0]
        if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", a):
            argv.pop(0)
            continue
        base = a.rsplit("/", 1)[-1]
        if base in ("sudo", "doas"):
            s["sudo"] = True
            argv.pop(0)
            while argv and argv[0].startswith("-"):
                opt = argv.pop(0)
                if opt in ("-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U") and argv:
                    argv.pop(0)
            continue
        if base == "env":
            argv.pop(0)
            while argv and (argv[0].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0])):
                argv.pop(0)
            if not argv:
                s["name"] = "env"
                return s
            continue
        if base == "xargs":
            s["xargs"] = True
            argv.pop(0)
            while argv and argv[0].startswith("-"):
                opt = argv.pop(0)
                if opt in ("-I", "-n", "-P", "-d", "-L", "-s", "-E") and argv:
                    argv.pop(0)
            continue
        if base in WRAPPERS:
            argv.pop(0)
            while argv and argv[0].startswith("-"):
                opt = argv.pop(0)
                if opt in ("-n", "-s", "-k", "-c") and argv:
                    argv.pop(0)
            if base == "timeout" and argv and re.match(r"^\d", argv[0]):
                argv.pop(0)
            continue
        break
    if argv:
        s["name"] = argv[0].rsplit("/", 1)[-1]
        s["args"] = argv[1:]
    return s


def parse_shell(cmd: str, depth: int = 0) -> list[dict]:
    out: list[dict] = []
    for raw in tokenize(cmd):
        s = _normalize(raw)
        s["depth"] = depth
        out.append(s)
        if depth >= 3:
            continue
        inner = None
        if s["name"] in SHELLS and "-c" in s["args"]:
            k = s["args"].index("-c")
            if k + 1 < len(s["args"]):
                inner = s["args"][k + 1]
        elif s["name"] == "eval" and s["args"]:
            inner = " ".join(s["args"])
        elif s["name"] == "ssh":
            ops = []
            skip = False
            for a in s["args"]:
                if skip:
                    skip = False
                    continue
                if a.startswith("-"):
                    skip = a in ("-i", "-p", "-l", "-o", "-F", "-J", "-L", "-R", "-D", "-W", "-b", "-c", "-E", "-e", "-m", "-O", "-Q", "-S", "-w")
                    continue
                ops.append(a)
            if len(ops) >= 2:
                inner = " ".join(ops[1:])
        if inner:
            for x in parse_shell(inner, depth + 1):
                x["sudo"] = x["sudo"] or (s["name"] != "ssh" and s["sudo"])
                out.append(x)
        for tokn in s["args"] + [s["name"]]:
            for m in re.finditer(r"\$\(([^()]*)\)|`([^`]*)`", tokn):
                body = m.group(1) if m.group(1) is not None else m.group(2)
                if body and body.strip():
                    out.extend(parse_shell(body, depth + 1))
    return out


def operands(args: list[str]) -> list[str]:
    out, end = [], False
    for a in args:
        if not end and a == "--":
            end = True
            continue
        if not end and a.startswith("-") and a != "-":
            continue
        out.append(a)
    return out


def _written(s: dict) -> list[str]:
    p = list(s["out"])
    n, a = s["name"], s["args"]
    ops = operands(a)
    if n in ("cp", "mv", "install", "ln") and len(ops) >= 2:
        p.append(ops[-1])
        if n == "mv":
            p.extend(ops[:-1])
    elif n == "rsync" and len(ops) >= 2:
        p.append(ops[-1])
    elif n == "tee":
        p.extend(ops)
    elif n in ("rm", "unlink", "rmdir", "shred", "truncate", "touch"):
        p.extend(ops)
    elif n in ("chmod", "chown", "chgrp"):
        p.extend(ops[1:])
    elif n == "sed" and any(x == "-i" or (x.startswith("-i") and not x.startswith("--")) or x.startswith("--in-place") for x in a):
        p.extend(ops[1:])
    elif n == "dd":
        p.extend(x[3:] for x in a if x.startswith("of="))
    return [x for x in p if x and "://" not in x and (re.match(r"^[A-Za-z]:[\\/]", x) or not re.match(r"^[^/]*@?[^/]+:", x))]


def _read(s: dict) -> list[str]:
    p = list(s["inp"])
    if s["name"] in READERS:
        ops = operands(s["args"])
        if s["name"] in ("grep", "egrep", "rg", "sed", "awk", "jq") and ops:
            ops = ops[1:]
        if s["name"] in ("cp", "scp", "rsync") and len(ops) >= 2:
            ops = ops[:-1]
        p.extend(ops)
    if s["name"] == "dd":
        p.extend(x[3:] for x in s["args"] if x.startswith("if="))
    return [x for x in p if x and "://" not in x]


def _uploads(s: dict) -> list[str]:
    """Local files a network command sends somewhere."""
    n, a = s["name"], s["args"]
    out = []
    if n in ("curl", "http", "httpie"):
        for i, x in enumerate(a):
            if x in ("-d", "--data", "--data-binary", "--data-raw", "--data-urlencode", "-F", "--form") and i + 1 < len(a):
                v = a[i + 1]
                if v.startswith("@"):
                    out.append(v[1:])
                m = re.search(r"=@([^;]+)", v) or re.search(r"=<([^;]+)", v)
                if m:
                    out.append(m.group(1))
            if x in ("-T", "--upload-file") and i + 1 < len(a):
                out.append(a[i + 1])
            if n != "curl" and re.match(r"^[^=@]+@(.+)$", x):
                out.append(re.match(r"^[^=@]+@(.+)$", x).group(1))
    elif n == "wget":
        out.extend(x.split("=", 1)[1] for x in a if x.startswith("--post-file=") or x.startswith("--body-file="))
    elif n in ("scp", "rsync", "sftp"):
        ops = operands(a)
        if len(ops) >= 2 and ":" in ops[-1]:
            out.extend(o for o in ops[:-1] if ":" not in o)
    return [x for x in out if x and x != "-"]


def _env_dump(s: dict) -> bool:
    n, a = s["name"], s["args"]
    if n == "env":
        return not operands(a)
    if n == "printenv":
        return True
    if n == "export" and (not a or a == ["-p"]):
        return True
    if n == "declare" and ("-x" in a or "-p" in a):
        return True
    if n == "set" and not a:
        return True
    return False


def _urls(text: str) -> list[str]:
    return re.findall(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>`]+", text or "")


class _Ctx:
    def __init__(self, policy: dict):
        self.p = policy
        self.home = normpath(to_posix(policy["home"]))
        # a home folder on a drive letter means Windows, where file names ignore case
        self.win = bool(re.match(r"^/[a-z](?:/|$)", self.home))
        if self.win:
            self.home = self.home.lower()
        self.ws = self.path(policy["workspace"], "/")
        self.vdir = self.path("~/.verfy")

    def path(self, p: str, cwd: str | None = None) -> str:
        out = resolve(p, self.home, cwd or self.ws)
        return out.lower() if self.win else out

    def match(self, patterns: list[str], path: str) -> str | None:
        """The first pattern that matches, reported as written."""
        for pat in patterns or []:
            if first_match([to_posix(pat).lower() if self.win else pat], path, self.home):
                return pat
        return None

    def sensitive(self, path: str) -> str | None:
        base = path.rsplit("/", 1)[-1]
        if base.endswith(EXAMPLE_SUFFIXES):
            return None
        return self.match(self.p["files"]["sensitive"], path)

    def protected(self, path: str) -> str | None:
        return self.match(self.p["files"]["deny_write"], path)

    def guards_verfy(self, path: str) -> tuple[str, str] | None:
        """(verdict, pattern) when changing ``path`` could switch Verfy off or approve something for the agent."""
        for verdict in ("deny", "ask"):
            hit = self.match(PATTERNS["self_protect"][verdict], path)
            if hit:
                return verdict, hit
        return None

    def verfy_secret(self, path: str) -> bool:
        """``path`` is Verfy's folder in the home folder, or the signing key or device token in it."""
        return path == self.vdir or any(path == self.vdir + "/" + f for f in SECRET["files"])

    def holds_verfy(self, path: str) -> bool:
        """``path`` is a folder Verfy's folder is inside (the home folder, ``/``, ...)."""
        return path != self.vdir and is_within(self.vdir, path)

    def allowed_outside(self, path: str) -> bool:
        return self.match(self.p["files"]["allow_write"], path) is not None

    def catastrophic(self, path: str) -> bool:
        if self.win and (re.match(r"^/[a-z]$", path) or path in WINDOWS_DIRS):
            return True
        return path in ("/", self.home, self.ws) or path in SYSTEM_DIRS or is_within(self.ws, path)


SECRET = PATTERNS["self_protect"]["secret"]
SECRET_MSG = " With them an agent can sign its own receipts or upload as this device. Run it yourself if you meant it."


def _home_vars(p: str) -> str:
    """``$HOME/x``, ``%USERPROFILE%\\x`` and the like as ``~/x``, so they resolve like ``~``."""
    return re.sub(r"^(?:\$HOME|\$\{HOME\}|%USERPROFILE%|\$env:USERPROFILE|\$env:HOME)(?=$|[\\/])", "~", p, flags=re.I)


def _resolvable(p: str, here: str | None) -> bool:
    return "$" not in p and "`" not in p and (here is not None or p.startswith(("/", "~")))


def _verfy_secret(s: dict, ctx: "_Ctx", here: str | None) -> dict | None:
    """A finding when one command reads, copies or looks for Verfy's signing key or device token."""
    parts = [x for t in [s["name"], *s["args"], *s["inp"], *s["out"]] for x in (t, *t.split("=")[1:]) if x]
    for p in parts:
        h = _home_vars(p)
        if rx(SECRET["token"], "i").search(p) or (_resolvable(h, here) and ctx.verfy_secret(ctx.path(h, here))):
            return _f("VFY-SELF-006", "deny", f"Reads Verfy's signing key or device token ({p})." + SECRET_MSG)
    n = s["name"].lower().removesuffix(".exe")
    if n in SECRET["finders"] and any(rx(SECRET["name"], "i").search(p) for p in parts[1:]):
        return _f("VFY-SELF-007", "ask", "Looks for a file named like Verfy's signing key or device token.")
    if n in SECRET["readers"]:
        ops = operands(s["args"])
        if n in ("cp", "rsync", "scp", "robocopy", "xcopy", "copy-item", "cpi") and len(ops) >= 2:
            ops = ops[:-1]  # the last one is where the copy goes
        for p in ops:
            h = _home_vars(p)
            if _resolvable(h, here) and ctx.holds_verfy(ctx.path(h, here)):
                return _f("VFY-SELF-007", "ask", f"Reads or copies {p}, which holds Verfy's signing key and device token.")
    return None


def _self_finding(hit: tuple[str, str], p: str) -> dict:
    verdict, pat = hit
    if verdict == "deny":
        return _f("VFY-SELF-001", "deny", f"Changes {p}, which Verfy relies on to guard this agent (`{pat}`). Make this change yourself if you meant it.")
    return _f("VFY-SELF-002", "ask", f"Changes the MCP config {p}, which could take a server out from behind the Verfy gateway.")


def _verfy_command(s: dict) -> dict | None:
    """A finding when the agent runs Verfy (or pip) to approve, reset or remove Verfy itself."""
    n, a = s["name"].lower().removesuffix(".exe"), s["args"]
    if re.match(r"^python[0-9.]*$|^py$", n) and a[:2] == ["-m", "verfy"]:
        n, a = "verfy", a[2:]
    if n == "verfy":
        words_ = [x for x in a if not x.startswith("-")]
        if words_[:2] in (["lock", "approve"], ["lock", "add"]):
            return _f("VFY-SELF-003", "deny", f"`verfy {' '.join(words_[:2])}` approves a tool change for the agent. A person has to review and run it.")
        if words_[:2] == ["lock", "check"] and "--update" in a:
            return _f("VFY-SELF-003", "deny", "`verfy lock check --update` writes verfy.lock for the agent. A person has to review and run it.")
        if words_[:2] == ["sandbox", "sync"] and "--write" in a:
            return _f("VFY-SELF-003", "deny", "`verfy sandbox sync --write` changes Claude Code's settings. A person has to review and run it.")
        if words_[:2] == ["lock", "rollback"] and "--write" in a:
            return _f("VFY-SELF-003", "deny", "`verfy lock rollback --write` rewrites an MCP config. A person has to review and run it.")
        if words_[:2] == ["lock", "files"] and "--update" in a:
            return _f("VFY-SELF-003", "deny", "`verfy lock files --update` approves changed instruction files for the agent. A person has to review and run it.")
        if words_[:1] == ["import"] and "--save" in a:
            return _f("VFY-SELF-003", "deny", "`verfy import --save` changes which tools the Verfy gateway blocks. A person has to review and run it.")
        if words_[:2] == ["policy", "use"]:
            return _f("VFY-SELF-003", "deny", "`verfy policy use` replaces the policy Verfy enforces. A person has to choose and run it.")
        if words_[:1] == ["init"] and "--force" in a:
            return _f("VFY-SELF-003", "deny", "`verfy init --force` replaces the signing key, which starts a new receipt chain.")
        # --url as well as --code: with only --url, the code can come from VERFY_ENROLL_CODE
        if words_[:2] == ["team", "enroll"] or (words_[:1] == ["init"] and any(x.split("=", 1)[0] in ("--url", "--code") for x in a)):
            return _f("VFY-SELF-003", "deny", "Connects this device to a Verfy Cloud, which decides where its receipts go. A person has to run it.")
        if words_[:3] == ["team", "auto-sync", "off"]:
            return _f("VFY-SELF-003", "deny", "`verfy team auto-sync off` stops this device's receipts from reaching your team. A person has to run it.")
        return None
    pip = n in ("pip", "pip3", "pipx") or (n == "uv" and a[:1] in (["pip"], ["tool"])) or (re.match(r"^python[0-9.]*$|^py$", n) and a[:2] == ["-m", "pip"])
    if pip and "uninstall" in a and any(x.lower() == "verfy" for x in a):
        return _f("VFY-SELF-004", "deny", "Uninstalls Verfy.")
    return None


def _url_parts(url: str) -> tuple[str, str, str] | None:
    """(host, userinfo, path and query) of a URL, or None if it is not one."""
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://([^/?#]*)([^#]*)", url)
    if not m:
        return None
    authority, rest = m.group(1), m.group(2)
    userinfo = ""
    if "@" in authority:
        userinfo, authority = authority.rsplit("@", 1)
    host = authority
    if host.startswith("["):
        host = host[1:].split("]", 1)[0]
    else:
        host = host.split(":", 1)[0]
    return host.lower().rstrip("."), userinfo, rest


def _on_allow_list(url: str, ctx: _Ctx) -> bool:
    parts = _url_parts(url)
    return bool(parts) and any(host_match(pat, parts[0]) for pat in ctx.p["network"]["allow"])


def check_url(url: str, ctx: _Ctx) -> list[dict]:
    out: list[dict] = []
    parts = _url_parts(url)
    if not parts:
        return out
    host, userinfo, rest = parts
    net = ctx.p["network"]
    for pat in net["deny"]:
        if host_match(pat, host):
            out.append(_f("VFY-NET-001", "deny", f"`{host}` is on the network deny list (`{pat}`)."))
            break
    else:
        if net["allow"] and not any(host_match(pat, host) for pat in net["allow"]):
            v = net.get("unknown", "ask")
            if v in ("ask", "deny"):
                out.append(_f("VFY-NET-002", v, f"`{host}` is not on the network allow list."))
    if ":" in userinfo:
        out.append(_f("VFY-NET-003", "deny", "The URL carries a username and password."))
    for k, v in re.findall(r"[?&]([^=&#]+)=([^&#]*)", rest):
        if re.search(r"(?:token|secret|password|passwd|api[_-]?key|access[_-]?key|auth|sig(?:nature)?|session)", k, re.I) and len(v) >= 8:
            out.append(_f("VFY-NET-003", "deny", f"The URL carries a credential in `{k}`."))
            break
    return out


# ---------------------------------------------------------------- shell checks

def _delete_targets(t: str, s: dict, ctx: _Ctx, cwd: str | None) -> list[dict]:
    if t in ("/", "/*", "~", "~/", "~/*", "$HOME", "${HOME}", "$HOME/", "$HOME/*", "${HOME}/*", "/.", "~/."):
        return [_f("VFY-SH-001", "deny", f"Recursive delete of `{t}` would wipe far more than intended.")]
    if "$" in t or "`" in t:
        return [_f("VFY-SH-002", "ask", f"Recursive delete of `{t}`, a path built from a variable.")]
    if cwd is None and not t.startswith("/") and not t.startswith("~"):
        return [_f("VFY-SH-002", "ask", f"Recursive delete of `{t}` after changing to an unknown folder.")]
    stripped = re.sub(r"(?:/\*|/\.\*|/)+$", "", t) if t not in ("*", ".*", "./*") else "."
    stripped = stripped or "/"
    abs_ = ctx.path(stripped, cwd)
    wildcard_root = t in ("*", ".*", "./*", "./", ".", "..", "../", "../*") or t.endswith("/*")
    if ctx.catastrophic(abs_):
        return [_f("VFY-SH-001", "deny", f"Recursive delete of `{t}` would wipe the system, the home folder or the whole project.")]
    if not is_within(abs_, ctx.ws) and not ctx.allowed_outside(abs_):
        return [_f("VFY-SH-002", "ask", f"Recursive delete of `{t}`, which is outside the project.")]
    if wildcard_root and abs_ == ctx.ws:
        return [_f("VFY-SH-001", "deny", f"Recursive delete of `{t}` would wipe the whole project.")]
    return []


def _git_command(args: list[str]) -> list[str]:
    """The git subcommand and what follows it, past git's own options."""
    a = list(args)
    while a and a[0].startswith("-"):
        opt = a.pop(0)
        if opt in ("-C", "-c", "--git-dir", "--work-tree") and a:
            a.pop(0)
    return a


def _pushes(cmd: str) -> bool:
    return any(s["name"] == "git" and _git_command(s["args"])[:1] == ["push"] for s in parse_shell(cmd))


def _git(args: list[str]) -> str | None:
    a = _git_command(args)
    if not a:
        return None
    sub, rest = a[0], a[1:]
    if sub == "push":
        if any(x in ("--force", "-f", "--mirror") or (x.startswith("-") and not x.startswith("--") and "f" in x[1:]) for x in rest) or any(x.startswith("+") for x in operands(rest)):
            return "Force-push rewrites shared history."
        if "--delete" in rest or "-d" in rest or any(x.startswith(":") for x in operands(rest)):
            return "Deletes a branch on the remote."
    if sub == "reset" and "--hard" in rest:
        return "`git reset --hard` throws away uncommitted work."
    if sub == "clean" and any(x.startswith("-") and not x.startswith("--") and "f" in x for x in rest + ["--force" if "--force" in rest else ""]):
        return "`git clean -f` deletes untracked files for good."
    if sub == "clean" and "--force" in rest:
        return "`git clean --force` deletes untracked files for good."
    if sub == "checkout" and ("." in operands(rest) or ("--" in rest and rest[-1] != "--")):
        return "`git checkout --` discards uncommitted changes."
    if sub == "restore" and "--staged" not in rest and operands(rest):
        return "`git restore` discards uncommitted changes."
    if sub == "branch" and ("-D" in rest or ("--delete" in rest and "--force" in rest)):
        return "Force-deletes a branch, including unmerged work."
    if sub == "stash" and rest[:1] and rest[0] in ("drop", "clear"):
        return "Deletes stashed work."
    if sub in ("filter-branch", "filter-repo"):
        return "Rewrites the whole repository history."
    if sub == "reflog" and rest[:1] == ["expire"]:
        return "Expires the reflog, which removes the way back."
    if sub == "update-ref" and "-d" in rest:
        return "Deletes a ref directly."
    return None


def _publish(s: dict) -> str | None:
    n, a = s["name"], s["args"]
    ops = operands(a)
    first = ops[0] if ops else ""
    if n in PUBLISH and first in PUBLISH[n]:
        return f"`{n} {first}` changes something outside this computer."
    if n in ("vercel", "netlify") and ("--prod" in a or "--production" in a):
        return f"`{n}` deploys to production."
    if n == "gh" and len(ops) >= 2 and (ops[0], ops[1]) in {("release", "create"), ("release", "delete"), ("repo", "delete"), ("repo", "archive"), ("pr", "merge"), ("secret", "set"), ("secret", "delete")}:
        return f"`gh {ops[0]} {ops[1]}` changes the shared repository."
    if n in ("aws", "gcloud", "az", "doctl", "oci") and any(re.search(r"(?:^|-)(?:delete|remove|rm|terminate|destroy|purge|deregister)(?:$|-)", x) for x in a):
        return f"`{n}` command deletes cloud resources."
    if n == "stripe" and any(x in ("create", "delete", "update", "post", "refunds", "payouts", "transfers", "charges") for x in a):
        return "`stripe` command can move money or change billing."
    return None


def check_shell(cmd: str, ctx: _Ctx) -> tuple[list[dict], bool]:
    """Findings for one shell command, plus whether it touches the network."""
    out: list[dict] = []
    segs = parse_shell(cmd)
    cwd: str | None = ctx.ws
    network = any(s["name"] in NETWORK_CMDS for s in segs)
    sensitive_reads: list[str] = []
    env_dumped = False

    for s in segs:
        n, a = s["name"], s["args"]
        secret = _verfy_secret(s, ctx, cwd if s["depth"] == 0 else ctx.ws)
        if secret:
            out.append(secret)
        if s["depth"] == 0 and n == "cd":
            ops = operands(a)
            if not ops:
                cwd = ctx.home
            elif ops[0] == "-" or "$" in ops[0] or "`" in ops[0]:
                cwd = None
            elif cwd is not None or ops[0].startswith("/") or ops[0].startswith("~"):
                cwd = ctx.path(ops[0], cwd)
            continue
        here = cwd if s["depth"] == 0 else ctx.ws

        if n == "rm":
            recursive = any(x in ("-r", "-R", "--recursive") or (x.startswith("-") and not x.startswith("--") and ("r" in x or "R" in x)) for x in a)
            if recursive:
                tg = operands(a)
                if s["xargs"] and not tg:
                    out.append(_f("VFY-SH-002", "ask", "Recursive delete of paths that come from a pipeline."))
                for t in tg:
                    out.extend(_delete_targets(t, s, ctx, here))
        if n == "find" and ("-delete" in a or ("-exec" in a and "rm" in a)):
            ops = [x for x in a if not x.startswith("-")][:1] or ["."]
            p = ctx.path(ops[0], here) if here is not None else None
            if p is None:
                out.append(_f("VFY-SH-002", "ask", "`find -delete` after changing to an unknown folder."))
            elif ctx.catastrophic(p) and p != ctx.ws:
                out.append(_f("VFY-SH-001", "deny", f"`find {ops[0]} -delete` can wipe the system or home folder."))
            elif not is_within(p, ctx.ws) and not ctx.allowed_outside(p):
                out.append(_f("VFY-SH-002", "ask", f"`find {ops[0]} -delete` deletes files outside the project."))
        if n == "git":
            why = _git(a)
            if why:
                out.append(_f("VFY-SH-004", "ask", why))
        why = _publish(s)
        if why:
            out.append(_f("VFY-SH-009", "ask", why))
        if s["sudo"]:
            out.append(_f("VFY-SH-006", "ask", f"`{n or 'command'}` runs with administrator rights."))
        if n == "su":
            out.append(_f("VFY-SH-006", "ask", "Switches user with `su`."))
        if n == "chmod":
            ops = operands(a)
            mode = ops[0] if ops else ""
            if re.match(r"^0?[0-7]?[0-7][0-7][2367]$", mode) or re.search(r"(?:^|,)[ao]*[+=][rwxXst]*w", mode) or re.match(r"^\+?w$", mode):
                out.append(_f("VFY-SH-012", "ask", f"`chmod {mode}` lets every user change these files."))
        own = _verfy_command(s)
        if own:
            out.append(own)
        for p in _written(s):
            if "$" in p or "`" in p:
                continue
            abs_ = ctx.path(p, here)
            own = ctx.guards_verfy(abs_)
            if own:
                out.append(_self_finding(own, p))
                continue
            hit = ctx.protected(abs_)
            if hit:
                out.append(_f("VFY-SH-011", "deny", f"Changes {p}, which is protected (`{hit}`)."))
        for p in _read(s):
            if "$" in p or "`" in p:
                continue
            abs_ = ctx.path(p, here)
            if ctx.sensitive(abs_):
                sensitive_reads.append(p)
        if _env_dump(s):
            env_dumped = True
        if n in NETWORK_CMDS:
            for p in _uploads(s):
                abs_ = ctx.path(p, here)
                if ctx.sensitive(abs_):
                    out.append(_f("VFY-SH-008", "deny", f"Uploads the sensitive file {p}."))
                else:
                    out.append(_f("VFY-SH-015", "ask", f"Uploads the local file {p}."))
            for x in a:
                if re.search(SECRET_ENV, x):
                    out.append(_f("VFY-SH-008", "deny", "Sends a secret environment variable over the network."))
                    break

    if not any(f["rule"] == "VFY-SELF-006" for f in out):
        flat = " ".join(" ".join([s["name"], *s["args"], *s["inp"], *s["out"]]) for s in segs)
        if rx(SECRET["text"], "i").search(cmd) or rx(SECRET["text"], "i").search(flat):
            out.append(_f("VFY-SELF-006", "deny", "Names Verfy's folder and its signing key or device token in one command." + SECRET_MSG))

    for p in dict.fromkeys(sensitive_reads):
        if network:
            out.append(_f("VFY-SH-008", "deny", f"Reads the sensitive file {p} in a command that also uses the network."))
        else:
            out.append(_f("VFY-SH-007", "ask", f"Reads the sensitive file {p}."))
    if env_dumped:
        if network:
            out.append(_f("VFY-SH-008", "deny", "Prints environment variables in a command that also uses the network."))
        else:
            out.append(_f("VFY-SH-007", "ask", "Prints environment variables, which often hold secrets."))

    for rule, verdict, pat, flags, msg in PATTERNS["shell_patterns"]:
        if any(f["rule"] == rule for f in out):
            continue
        if rx(pat, flags).search(cmd):
            out.append(_f(rule, verdict, msg))
    if network:
        for u in _urls(cmd):
            out.extend(check_url(u, ctx))
    return out, network


# ---------------------------------------------------------------- classification

def _num(v: Any) -> float | None:
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str) and re.match(r"^\s*-?\d+(?:\.\d+)?\s*$", v):
        return float(v)
    return None


def _command_string(v: Any) -> str | None:
    if isinstance(v, str):
        return v
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return " ".join(x if re.match(r"^[A-Za-z0-9_./=:@%+,-]+$", x) else "'" + x.replace("'", "'\\''") + "'" for x in v)
    return None


def classify(tool: str, args: dict) -> str:
    w = set(words(tool.split("/")[-1]))
    keys = {str(k).lower(): v for k, v in args.items()}
    verbs = PATTERNS["verbs"]
    exec_words = set(PATTERNS["capabilities"]["exec"]["name"])
    for k in PATTERNS["command_keys"]:
        if k in keys and _command_string(keys[k]) is not None:
            cmd = _command_string(keys[k])
            if w & exec_words or k != "command" or re.search(r"[\s|;&<>$]", cmd):
                if not (k == "command" and set(keys) & set(PATTERNS["path_keys"]) and not (w & exec_words)):
                    return "shell"
    for k in PATTERNS["sql_keys"]:
        if isinstance(keys.get(k), str) and re.match(r"^\s*(?:select|insert|update|delete|drop|create|alter|truncate|with|grant|revoke|replace|merge|upsert)\b", keys[k], re.I):
            return "sql"
    has_amount = any(_num(keys.get(k)) is not None for k in PATTERNS["amount_keys"])
    if has_amount and (w & set(verbs["payment"]) or "currency" in keys or w & set(PATTERNS["capabilities"]["payment"]["name"])):
        return "payment"
    if any(k in keys for k in PATTERNS["path_keys"]):
        sub = set(words(keys["command"])) if isinstance(keys.get("command"), str) else set()
        for vw in (sub, w):
            if vw & set(verbs["delete"]):
                return "file_delete"
            if vw & set(verbs["write"]):
                return "file_write"
            if vw & set(verbs["read"]):
                return "file_read"
        return "file_write" if set(keys) & CONTENT_KEYS else "file_read"
    if any(isinstance(keys.get(k), str) for k in PATTERNS["url_keys"]):
        return "network"
    if w & set(verbs["message"]) and set(keys) & {"to", "recipient", "recipients", "channel", "body", "text", "message", "subject", "chat_id", "content"}:
        return "message"
    return "other"


def _paths(args: dict) -> list[tuple[str, str]]:
    out = []
    for k, v in args.items():
        lk = str(k).lower()
        if lk in PATTERNS["path_keys"]:
            vals = v if isinstance(v, list) else [v]
            out.extend((lk, x) for x in vals if isinstance(x, str) and x)
    return out


# ---------------------------------------------------------------- main entry

def check(action: dict, policy: dict | None = None, context: dict | None = None) -> dict:
    """Judge one agent action.

    ``context`` may carry ``spent_today`` (for the daily budget), ``tool`` (the
    scan result for this tool: ``{"critical": bool, "pin": "ok|new|changed"}``),
    ``known_tools`` (names the server listed; anything else is denied) and
    ``untrusted`` (what brought outside text into this session, see sessions.py)."""
    complete = policy and all(k in policy for k in DEFAULT_POLICY) and policy.get("home") and policy.get("workspace")
    pol = policy if complete else load_policy(policy)
    ctx = _Ctx(pol)
    context = context or {}
    tool = str(action.get("tool") or action.get("name") or "")
    server = str(action.get("server") or "")
    args = action.get("arguments", action.get("args", {}))
    if not isinstance(args, dict):
        args = {"input": args}
    full = f"{server}/{tool}" if server else tool
    out: list[dict] = []

    def listed(key: str) -> str | None:
        for pat in pol["tools"].get(key, []):
            if name_match(pat, full) or name_match(pat, tool):
                return pat
        return None

    hit = listed("deny")
    if hit:
        out.append(_f("VFY-TOOL-001", "deny", f"`{full}` is on the tool deny list (`{hit}`)."))
    hit = listed("ask")
    if hit:
        out.append(_f("VFY-TOOL-002", "ask", f"`{full}` always needs approval (`{hit}`)."))
    meta = context.get("tool") or {}
    if meta.get("critical"):
        out.append(_f("VFY-TOOL-003", "deny", f"`{tool}` failed the Verfy scan with a critical finding."))
    known = context.get("known_tools")
    if known is not None and tool not in known:
        out.append(_f("VFY-TOOL-005", "deny", f"`{tool}` is not in the tool list Verfy scanned for this server."))
    if meta.get("pin") == "changed":
        out.append(_f("VFY-TOOL-004", "deny", f"`{tool}` changed since it was approved (possible rug pull)."))
    if meta.get("pin") == "new":
        v = (pol.get("lock") or {}).get("on_new", "ask")
        if v in ("ask", "deny"):
            out.append(_f("VFY-TOOL-006", v, f"`{tool}` is not in verfy.lock yet. Review it with `verfy lock approve`."))
    if meta.get("pin") == "unverified":
        out.append(_f("VFY-TOOL-007", "ask", f"verfy.lock could not be read, so `{tool}` was not checked against it."))

    kind = classify(tool, args)
    trusted = listed("trust") is not None
    network = kind in ("network", "message")

    if not trusted:
        if "glob" in words(tool) and isinstance(args.get("pattern"), str) and rx(SECRET["token"], "i").search(args["pattern"]):
            out.append(_f("VFY-SELF-006", "deny", f"Lists Verfy's signing key or device token ({args['pattern']})." + SECRET_MSG))
        touchy = False  # a key file read, or a write outside the project
        if kind == "shell":
            cmd = next(_command_string(args[k]) for k in args if str(k).lower() in PATTERNS["command_keys"] and _command_string(args[k]) is not None)
            fs, network = check_shell(cmd, ctx)
            out.extend(fs)
            touchy = _pushes(cmd) or any(f["rule"] in ("VFY-SH-007", "VFY-SH-008") for f in fs)
        elif kind == "sql":
            sql = next(args[k] for k in args if str(k).lower() in PATTERNS["sql_keys"] and isinstance(args[k], str))
            for rule, verdict, pat, flags, msg in PATTERNS["sql_patterns"]:
                if rx(pat, flags).search(sql):
                    out.append(_f(rule, verdict, msg))
        elif kind.startswith("file_"):
            for key, p in _paths(args):
                abs_ = ctx.path(p)
                reading = kind == "file_read" or (kind == "file_write" and key in ("source", "src", "source_path", "from") and "move" not in words(tool))
                if rx(SECRET["token"], "i").search(p) or ctx.verfy_secret(ctx.path(_home_vars(p))):
                    out.append(_f("VFY-SELF-006", "deny", f"Reads or changes Verfy's signing key or device token ({p})." + SECRET_MSG))
                    continue
                if reading and {"grep", "search"} & set(words(tool)) and ctx.holds_verfy(ctx.path(_home_vars(p))):
                    out.append(_f("VFY-SELF-007", "ask", f"Searches {p}, which holds Verfy's signing key and device token."))
                if reading:
                    hit = ctx.sensitive(abs_)
                    if hit:
                        out.append(_f("VFY-FS-003", "ask", f"Reads the sensitive file {p} (`{hit}`)."))
                        touchy = True
                    continue
                own = ctx.guards_verfy(abs_)
                if own:
                    out.append(_self_finding(own, p))
                    continue
                hit = ctx.protected(abs_)
                if hit:
                    out.append(_f("VFY-FS-001", "deny", f"Changes {p}, which is protected (`{hit}`)."))
                    continue
                if kind == "file_delete" and ctx.catastrophic(abs_):
                    out.append(_f("VFY-FS-004", "deny", f"Deletes {p}, which would wipe the system, the home folder or the whole project."))
                    continue
                hit = ctx.sensitive(abs_)
                if hit:
                    out.append(_f("VFY-FS-003", "ask", f"Changes the sensitive file {p} (`{hit}`)."))
                if not is_within(abs_, ctx.ws) and not ctx.allowed_outside(abs_):
                    touchy = True
                    v = pol["files"].get("outside_workspace", "ask")
                    if v in ("ask", "deny"):
                        out.append(_f("VFY-FS-002", v, f"Changes {p}, which is outside the project."))
        elif kind == "payment":
            out.extend(_check_payment(args, pol, context))
        urls = [v for k, v in args.items() if str(k).lower() in PATTERNS["url_keys"] and isinstance(v, str)]
        if kind in ("network", "message"):
            for v in urls:
                out.extend(check_url(v, ctx))
        for path_, text in flatten_strings(args):
            for s in scan_secrets(text):
                if s["severity"] == "high" and (network or kind in ("network", "message", "payment")):
                    out.append(_f("VFY-SEC-001", "deny", f"Would send a {s['label']} out of this computer (in `{path_ or 'arguments'}`)."))
                else:
                    out.append(_f("VFY-SEC-001", "ask", f"Contains a {s['label']} (in `{path_ or 'arguments'}`)."))
        after = (pol.get("session") or {}).get("after_outside_text", "off")
        listed_site = kind == "network" and bool(urls) and all(_on_allow_list(u, ctx) for u in urls)
        if context.get("untrusted") and after in ("ask", "deny") and (touchy or (network and not listed_site) or kind in ("message", "payment", "file_delete")):
            out.append(_f("VFY-SESSION-001", after, f"This session read outside text ({context['untrusted']}), which can carry instructions, so a person has to approve this."))

    for r in pol.get("rules", []):
        if not name_match(r.get("tool", "*"), full) and not name_match(r.get("tool", "*"), tool):
            continue
        pat = rx(r["pattern"], r.get("flags", ""))
        for path_, text in flatten_strings(args):
            if r.get("arg") and path_ != r["arg"]:
                continue
            if pat.search(text):
                out.append(_f(r.get("id", "custom"), r.get("verdict", "ask"), r.get("message", "Matches a custom rule.")))
                break

    disabled = set(pol.get("disabled_rules", []))
    seen: set[tuple[str, str]] = set()
    findings = []
    for f in out:
        key = (f["rule"], f["message"])
        if f["rule"] in disabled or key in seen:
            continue
        seen.add(key)
        findings.append(f)
    findings.sort(key=lambda f: -VERDICT_RANK[f["verdict"]])
    verdict = findings[0]["verdict"] if findings else "allow"
    return {"v": VERSION, "verdict": verdict, "kind": kind, "tool": full, "findings": findings, "reaches_network": bool(network)}


def payment_amount(args: dict) -> float | None:
    keys = {str(k).lower(): v for k, v in args.items()}
    for k in PATTERNS["amount_keys"]:
        v = _num(keys.get(k))
        if v is not None:
            return v / 100 if k == "amount_cents" else v
    return None


def _check_payment(args: dict, pol: dict, context: dict) -> list[dict]:
    out = []
    pay = pol["payments"]
    keys = {str(k).lower(): v for k, v in args.items()}
    amount = payment_amount(args)
    if amount is None:
        return out
    if amount < 0:
        out.append(_f("VFY-PAY-006", "deny", "The amount is negative."))
        return out
    spent = float(context.get("spent_today") or 0)
    if pay.get("max_per_call") is not None and amount > pay["max_per_call"]:
        out.append(_f("VFY-PAY-001", "deny", f"{amount:g} is over the per-payment limit of {pay['max_per_call']:g}."))
    elif pay.get("daily_budget") is not None and spent + amount > pay["daily_budget"]:
        out.append(_f("VFY-PAY-002", "deny", f"This payment would take today's spending to {spent + amount:g}, over the daily budget of {pay['daily_budget']:g}."))
    elif pay.get("ask_above") is not None and amount > pay["ask_above"]:
        out.append(_f("VFY-PAY-003", "ask", f"{amount:g} is above the approval threshold of {pay['ask_above']:g}."))
    cur = keys.get("currency") or keys.get("ccy")
    if isinstance(cur, str) and pay.get("currencies") and cur.upper() not in [c.upper() for c in pay["currencies"]]:
        out.append(_f("VFY-PAY-004", "ask", f"Currency {cur.upper()} is not on the allowed list."))
    if pay.get("recipients"):
        for k in PATTERNS["recipient_keys"]:
            if isinstance(keys.get(k), str):
                if not any(name_match(p, keys[k]) for p in pay["recipients"]):
                    out.append(_f("VFY-PAY-005", "ask", f"`{keys[k]}` is not on the list of known recipients."))
                break
    return out
