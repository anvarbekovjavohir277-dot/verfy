"""The Verfy gateway: a stdio MCP proxy that sits between a client and a server.

    client (Claude, Cursor, ...)  <->  verfy proxy  <->  real MCP server

* ``tools/list`` answers are scanned and compared with ``verfy.lock``. Tools
  with a critical finding, or whose definition drifted from the locked digest,
  are hidden from the agent. The first time a server is seen its tools are
  locked (trust on first use); a tool added later needs approval.
* ``tools/call`` requests are pre-checked. Denied calls never reach the server;
  ``ask`` calls are blocked, allowed, sent to the user for approval (MCP
  elicitation) or put in the team's approval queue (``"team"``: the call waits
  up to ``approval_timeout`` seconds for an owner or admin), depending on
  ``on_ask`` in the policy.
* Every call, allowed or blocked, gets a signed receipt in the ledger.
* Secrets in tool results and resources (API keys, tokens, private keys) are
  replaced with ``[REDACTED:<rule>]`` before the agent sees them, unless the
  policy sets ``"redact_output": false``. The receipt hashes the original result.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, IO

from .imports import blocked_tools
from . import sessions
from . import team as teamlib
from ._util import redact_output, flatten_strings
from .lock import LockError, load_lock, pin, safe_name, save_seen, server_pins, update
from .policy import policy_digest
from .precheck import check, payment_amount
from .receipts import Key, Ledger, read_ledger
from . import sandbox as sandboxes
from .scanner import scan, unsafe_tools, prompt_tool, text_findings


def verfy_home() -> Path:
    return Path(os.environ.get("VERFY_HOME") or Path.home() / ".verfy")


def spent_today(receipts: list[dict], server: str | None = None) -> float:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total = 0.0
    for r in receipts:
        a = r.get("action", {})
        if not str(r.get("issued_at", "")).startswith(today) or a.get("kind") != "payment":
            continue
        if r.get("outcome", {}).get("status") != "ok" or not isinstance(a.get("args"), dict):
            continue
        amt = payment_amount(a["args"])
        total += amt or 0
    return total


class Gateway:
    def __init__(self, command: list[str], *, server: str, policy: dict, key: Key, ledger_path: Path,
                 lock_path: Path, home: Path | None = None, scans_dir: Path | None = None, session: str | None = None,
                 stdin: IO[bytes] | None = None, stdout: IO[bytes] | None = None,
                 log: Callable[[str], None] | None = None, team_transport: Callable | None = None, poll_seconds: float = 2.0):
        self.command = command
        self.server = server
        self.policy = policy
        self.policy_sha = policy_digest(policy)
        self.ledger = Ledger(ledger_path, key)
        self.lock_path = lock_path
        self.home = home or lock_path.parent
        self.scans_dir = scans_dir
        self.session = session or "ses_" + uuid.uuid4().hex[:12]
        self.inp = stdin or sys.stdin.buffer
        self.out = stdout or sys.stdout.buffer
        self.log = log or (lambda m: print("[verfy] " + m, file=sys.stderr, flush=True))
        self.lock = threading.Lock()
        self.ledger_lock = threading.Lock()
        self.pending: dict[str, tuple] = {}
        self.elicits: dict[str, tuple] = {}
        self.tool_meta: dict[str, dict] = {}
        self.imported: dict[str, dict] = {}  # tools another scanner rated high (verfy scan import --save)
        self.hidden_prompts: set[str] = set()
        self.client_caps: dict = {}
        self.spent = spent_today(read_ledger(ledger_path))
        self.child: subprocess.Popen | None = None
        self.outside: str | None = None  # the first tool that brought outside text into this session
        self.server_lock = threading.Lock()
        self.team_transport = team_transport
        self.poll_seconds = poll_seconds
        self._n = 0

    # ------------------------------------------------------------ plumbing
    def _key(self, msg_id: Any) -> str:
        return json.dumps(msg_id)

    def to_client(self, msg: dict) -> None:
        data = (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self.lock:
            self.out.write(data)
            self.out.flush()

    def to_server(self, msg: dict | bytes) -> None:
        data = msg if isinstance(msg, bytes) else (json.dumps(msg, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        assert self.child and self.child.stdin
        try:
            with self.server_lock:  # team approvals forward from their own threads
                self.child.stdin.write(data)
                self.child.stdin.flush()
        except (BrokenPipeError, OSError):
            self.log("server stdin closed")

    def run(self) -> int:
        try:
            self.child = subprocess.Popen(self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        except FileNotFoundError:
            self.log(f"cannot start `{self.command[0]}`: command not found")
            return 127
        except OSError as e:
            self.log(f"cannot start `{self.command[0]}`: {e.strerror or e}")
            return 126
        self.log(f"gateway up for `{self.server}` (session {self.session}, key {self.ledger.key.kid})")
        t = threading.Thread(target=self._pump_server, daemon=True)
        t.start()
        try:
            for line in iter(self.inp.readline, b""):
                if line.strip():
                    self.from_client(line)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                self.child.stdin.close()
            except OSError:
                pass
        try:
            code = self.child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.child.terminate()
            code = self.child.wait()
        t.join(timeout=2)
        if self.child.stdout:
            self.child.stdout.close()
        return code

    def _pump_server(self) -> None:
        assert self.child and self.child.stdout
        for line in iter(self.child.stdout.readline, b""):
            if line.strip():
                try:
                    self.from_server(line)
                except Exception as e:  # never let one bad message kill the gateway
                    self.log(f"error handling server message: {e!r}")
                    with self.lock:
                        self.out.write(line if line.endswith(b"\n") else line + b"\n")
                        self.out.flush()

    # ------------------------------------------------------------ client side
    def _refuse(self, msg_id, code: int, message: str) -> None:
        self.log(message)
        self.to_client({"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}})

    def from_client(self, line: bytes) -> None:
        """Only what Verfy could read goes on: a server with a laxer parser must not see a call Verfy did not."""
        if not line.strip():
            return
        try:
            msg = json.loads(line)
        except ValueError:
            self._refuse(None, -32700, "Verfy forwards only valid JSON, so this message was dropped.")
            return
        for m in msg if isinstance(msg, list) else [msg]:
            if not isinstance(m, dict):
                self._refuse(None, -32600, "Verfy forwards only JSON-RPC objects, so this message was dropped.")
                continue
            try:
                self._client_msg(m)
            except Exception as e:  # noqa: BLE001 - one bad message must not stop the gateway, and is never forwarded
                self._refuse(m.get("id"), -32603, f"Verfy could not check this message ({type(e).__name__}), so it was dropped.")

    def _client_msg(self, msg: dict) -> None:
        method = msg.get("method")
        if method is None and "id" in msg and self._key(msg["id"]) in self.elicits:
            self._elicit_answer(msg)
            return
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method == "initialize":
            caps = params.get("capabilities")
            self.client_caps = caps if isinstance(caps, dict) else {}
        if method == "tools/list" and "id" in msg:
            self.pending[self._key(msg["id"])] = ("list",)
        if method == "resources/read" and "id" in msg:
            self.pending[self._key(msg["id"])] = ("read", str(params.get("uri", "")))
        if method == "prompts/list" and "id" in msg:
            self.pending[self._key(msg["id"])] = ("prompts",)
        if method == "resources/list" and "id" in msg:
            self.pending[self._key(msg["id"])] = ("resources",)
        if method == "prompts/get" and "id" in msg:
            name = str(params.get("name", ""))
            if name in self.hidden_prompts:
                self._refuse(msg["id"], -32602, f"Verfy hid the prompt `{name}`: it changed since it was approved, or it failed the scan.")
                return
            self.pending[self._key(msg["id"])] = ("prompt", name)
        if method == "tools/call":
            if "id" in msg:
                self._call(msg)
            else:  # a notification gets no answer, but a server might still run it
                self.log("dropped a tools/call without an id")
            return
        self.to_server(msg)

    def _call(self, msg: dict) -> None:
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            self._refuse(msg["id"], -32602, "Tool arguments must be an object, so Verfy did not forward this call.")
            return
        action = {"server": self.server, "tool": name, "arguments": args}
        meta = self.tool_meta.get(name)
        decision = check(action, self.policy, {"spent_today": self.spent, "tool": meta, "known_tools": list(self.tool_meta), "untrusted": self.outside})
        if name in self.imported:
            f = self.imported[name]
            decision["findings"] = [{"rule": "VFY-IMP-001", "verdict": "deny", "message": f"`{name}` is rated high by {f['source']} ({f['rule']}): {f['message'][:200]}"}, *decision.get("findings", [])]
            decision["verdict"] = "deny"
        v = decision["verdict"]
        # what a server answers is outside text, unless the policy trusts that tool
        if v != "deny" and not self.outside and not sessions.trusted(self.policy, f"{self.server}/{name}", name):
            self.outside = f"{self.server}/{name}"
        if v == "allow":
            self._forward(msg, action, decision)
        elif v == "deny":
            self._block(msg, action, decision, "Verfy blocked this call.")
        else:
            mode = self.policy.get("on_ask", "deny")
            if mode == "allow":
                decision["approved_by"] = "policy"
                self._forward(msg, action, decision)
            elif mode == "elicit" and "elicitation" in self.client_caps:
                self._n += 1
                eid = f"verfy-elicit-{self._n}"
                self.elicits[self._key(eid)] = (msg, action, decision)
                reasons = "; ".join(f"[{f['rule']}] {f['message']}" for f in decision["findings"])
                self.to_client({
                    "jsonrpc": "2.0", "id": eid, "method": "elicitation/create",
                    "params": {
                        "message": f"Verfy: `{self.server}/{name}` needs your approval. {reasons}",
                        "requestedSchema": {
                            "type": "object",
                            "properties": {"approve": {"type": "boolean", "title": "Allow this action", "description": reasons[:500]}},
                            "required": ["approve"],
                        },
                    },
                })
            elif mode == "team":
                threading.Thread(target=self._ask_team, args=(msg, action, decision), daemon=True).start()
            else:
                self._block(msg, action, decision, "Verfy needs a person to approve this call, so it was not run.")

    def _ask_team(self, msg: dict, action: dict, decision: dict) -> None:
        """Wait for an owner or admin to decide in the dashboard. Anything but an approval refuses the call."""
        wait = int(self.policy.get("approval_timeout", 120))
        name = f"{self.server}/{action['tool']}"
        try:
            req = teamlib.request_approval(self.home, self.server, action["tool"], decision["kind"], self.ledger.hash(action["arguments"]),
                                           decision["findings"], wait, transport=self.team_transport)
            self.log(f"ASK {name} -> waiting up to {wait}s for your team to approve it in the dashboard")
            deadline = time.monotonic() + wait + 5
            state = req
            while state.get("status") == "pending" and time.monotonic() < deadline:
                time.sleep(self.poll_seconds)
                state = teamlib.approval_status(self.home, req["id"], transport=self.team_transport)
        except (teamlib.TeamError, OSError, ValueError, KeyError) as e:
            self._block(msg, action, decision, f"Verfy could not reach your team to approve this call ({e}), so it was not run.")
            return
        if state.get("status") == "approved":
            decision["approved_by"] = "team:" + str(state.get("decided_by") or "admin")[:90]
            self._forward(msg, action, decision)
            return
        decision["approved_by"] = None
        why = {"rejected": "Your team rejected this call.", "expired": "Nobody on your team approved this call in time."}
        note = f" Note: {state['note']}" if state.get("note") else ""
        self._block(msg, action, decision, why.get(str(state.get("status")), "Your team did not approve this call.") + note, status="declined")

    def _elicit_answer(self, msg: dict) -> None:
        msg0, action, decision = self.elicits.pop(self._key(msg["id"]))
        res = msg.get("result") or {}
        if res.get("action") == "accept" and (res.get("content") or {}).get("approve") is True:
            decision["approved_by"] = "user"
            self._forward(msg0, action, decision)
        else:
            decision["approved_by"] = None
            self._block(msg0, action, decision, "The user did not approve this call.", status="declined")

    def _forward(self, msg: dict, action: dict, decision: dict) -> None:
        self.pending[self._key(msg["id"])] = ("call", action, decision)
        self.to_server(msg)

    def _block(self, msg: dict, action: dict, decision: dict, headline: str, status: str = "blocked") -> None:
        r = self._receipt(action, decision, {"status": status, "result_sha256": None})
        reasons = "\n".join(f"- [{f['rule']}] {f['message']}" for f in decision["findings"]) or "- no rule matched"
        text = f"{headline}\n{reasons}\nReceipt {r['id']} (#{r['seq']})."
        self.log(f"{decision['verdict'].upper()} {self.server}/{action['tool']} -> {status} ({', '.join(f['rule'] for f in decision['findings'])})")
        self.to_client({"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [{"type": "text", "text": text}], "isError": True}})

    def _receipt(self, action: dict, decision: dict, outcome: dict) -> dict:
        meta = self.tool_meta.get(action["tool"]) or {}
        with self.ledger_lock:
            receipt = self.ledger.append(
                agent=self.policy.get("agent", "agent"), session=self.session, action=action, decision=decision,
                outcome=outcome, policy_sha256=self.policy_sha, tool_sha256=meta.get("sha256"),
                include_args=bool(self.policy.get("receipts", {}).get("include_args", False)),
                sandbox=sandboxes.running_in(self.command),
            )
        # `verfy sync` uploads the ledger in VERFY_HOME, so only that one is uploaded automatically
        if self.ledger.path == verfy_home() / "ledger.jsonl":
            teamlib.sync_soon(verfy_home())
        return receipt

    # ------------------------------------------------------------ server side
    def from_server(self, line: bytes) -> None:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            with self.lock:
                self.out.write(line)
                self.out.flush()
            return
        if isinstance(msg, dict) and "id" in msg and "method" not in msg:
            p = self.pending.pop(self._key(msg["id"]), None)
            if p and p[0] == "list" and isinstance(msg.get("result"), dict):
                msg["result"] = self._filter_tools(msg["result"])
            elif p and p[0] == "call":
                _, action, decision = p
                result = msg.get("result")
                failed = "error" in msg or (isinstance(result, dict) and result.get("isError") is True)
                r = self._receipt(action, decision, {"status": "error" if failed else "ok", "result_sha256": self.ledger.hash(result if result is not None else msg.get("error"))})
                if decision["kind"] == "payment" and not failed:
                    self.spent += payment_amount(action["arguments"]) or 0
                self.log(f"{decision['verdict'].upper()} {self.server}/{action['tool']} -> {r['outcome']['status']} (receipt #{r['seq']})")
                self._redact(msg, f"{self.server}/{action['tool']}")
            elif p and p[0] == "read":
                self._redact(msg, f"{self.server} resource {p[1]}")
            elif p and p[0] == "prompts" and isinstance(msg.get("result"), dict):
                msg["result"] = self._filter_prompts(msg["result"])
            elif p and p[0] == "resources" and isinstance(msg.get("result"), dict):
                msg["result"] = self._filter_resources(msg["result"])
            elif p and p[0] == "prompt":
                self._redact(msg, f"{self.server} prompt {p[1]}")
                self._check_prompt(msg, p[1])
        self.to_client(msg)

    def _redact(self, msg: dict, what: str) -> None:
        if self.policy.get("redact_output", True) is False:
            return
        n = 0
        for k in ("result", "error"):
            if k in msg:
                msg[k], hidden = redact_output(msg[k])
                n += hidden
        if n:
            self.log(f"redacted {n} secret{'s' if n != 1 else ''} in the output of {what}")

    def _filter_prompts(self, result: dict) -> dict:
        """Prompts are pinned like tools. Their first listing is locked as it is, once the server has a lock."""
        prompts = [p for p in result.get("prompts") or [] if isinstance(p, dict) and isinstance(p.get("name"), str)]
        as_tools = [prompt_tool(p) for p in prompts]
        try:
            pins = server_pins(load_lock(self.lock_path), self.server)
        except LockError as e:
            self.log(f"{e}; prompts from `{self.server}` were not checked against it")
            pins = None
        first_use = pins is not None and not any(k.startswith("prompt:") for k in pins)
        if first_use:
            def lock_all(lock: dict) -> None:
                for t in as_tools:
                    pin(lock, self.server, t, "first-use")
            update(self.lock_path, lock_all)
        report = scan(as_tools, self.server, None if first_use or pins is None else {k: v for k, v in pins.items() if k.startswith("prompt:")})
        on_new = (self.policy.get("lock") or {}).get("on_new", "ask")
        hidden = {t["name"] for t in report["tools"] if t["pin"] == "changed" or (t["pin"] == "new" and on_new != "allow") or any(f["severity"] == "critical" for f in t["findings"])}
        self.hidden_prompts = {n.removeprefix("prompt:") for n in hidden}
        if hidden:
            self.log(f"hidden prompts from `{self.server}`: {', '.join(sorted(self.hidden_prompts))}")
        return {**result, "prompts": [p for p in prompts if p["name"] not in self.hidden_prompts]}

    def _filter_resources(self, result: dict) -> dict:
        """A resource list changes all the time, so it is not pinned, but what it tells the model is scanned."""
        keep = []
        for r in result.get("resources") or []:
            texts = [str(r.get(k)) for k in ("name", "title", "description") if isinstance(r, dict) and r.get(k)]
            if any(f["severity"] == "critical" for t in texts for f in text_findings(t)):
                self.log(f"hid a resource from `{self.server}` that failed the scan: {str(r.get('uri'))[:80]}")
                continue
            keep.append(r)
        return {**result, "resources": keep}

    def _check_prompt(self, msg: dict, name: str) -> None:
        """A prompt's text is not in the lock, because it depends on its arguments, so it is scanned when it is fetched."""
        for _, text in flatten_strings(msg.get("result") or {}):
            if any(f["severity"] == "critical" for f in text_findings(text)):
                self.log(f"blocked the prompt `{name}` from `{self.server}`: its text failed the scan")
                msg.pop("result", None)
                msg["error"] = {"code": -32001, "message": f"Verfy blocked the prompt `{name}`: its text failed the scan."}
                return

    def _filter_tools(self, result: dict) -> dict:
        tools = result.get("tools")
        if not isinstance(tools, list):
            return result
        tools_ok = [t for t in tools if isinstance(t, dict) and isinstance(t.get("name"), str)]
        try:
            pins = server_pins(load_lock(self.lock_path), self.server)
            lock_ok = True
        except LockError as e:
            self.log(f"{e}; every tool from `{self.server}` will need approval")
            pins, lock_ok = None, False
        first_use = lock_ok and pins is None
        report = scan(tools_ok, self.server, pins if pins is not None else {})
        if first_use:
            def lock_all(lock: dict) -> None:
                if lock["servers"].get(self.server) is None:  # another session may have locked it meanwhile
                    for t in tools_ok:
                        pin(lock, self.server, t, "first-use")
            update(self.lock_path, lock_all)
            self.log(f"locked {len(tools_ok)} tool definitions from `{self.server}` in {self.lock_path} (first use)")
        for t in report["tools"]:
            status = "unverified" if not lock_ok else ("ok" if first_use else t["pin"])
            self.tool_meta[t["name"]] = {
                "sha256": t["sha256"], "grade": t["grade"], "pin": status,
                "critical": any(f["severity"] == "critical" and f["rule"] != "VFY-SCAN-014" for f in t["findings"]),
            }
        save_seen(self.home, self.server, tools_ok)
        if self.scans_dir:
            self.scans_dir.mkdir(parents=True, exist_ok=True)
            (self.scans_dir / f"{safe_name(self.server)}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", "utf-8")
        hidden = unsafe_tools(report) if self.policy.get("hide_unsafe_tools", True) else set()
        if self.policy.get("hide_unsafe_tools", True):
            self.imported = blocked_tools(self.home, self.server)
            if self.imported:
                self.log("hidden because another scanner rated them high: " + ", ".join(f"{t} ({f['source']})" for t, f in sorted(self.imported.items())))
            hidden |= set(self.imported)
        self.log(f"scanned {report['tool_count']} tools from `{self.server}`: grade {report['grade']} ({report['score']}/100)" + (f", hidden: {', '.join(sorted(hidden))}" if hidden else ""))
        out = dict(result)
        out["tools"] = [t for t in tools_ok if t["name"] not in hidden]
        return out
