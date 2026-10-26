"""Verfy CLI test suite. Run from verfy-cli/: ``python -m unittest discover -s tests``."""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import canonical, check, digest, load_policy, scan  # noqa: E402
from verfy import ed25519  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402
from verfy.gateway import Gateway  # noqa: E402
from verfy.lock import load_lock, server_pins  # noqa: E402
from verfy.precheck import parse_shell  # noqa: E402
from verfy.receipts import Key, Ledger, read_ledger, sign_receipt, unb64u, verify_ledger, verify_receipt  # noqa: E402

FX = ROOT / "tests" / "fixtures"
NODE = shutil.which("node")
PY = sys.executable


def load(name):
    return json.loads((FX / name).read_text("utf-8"))


class Fixtures(unittest.TestCase):
    def test_precheck(self):
        data = load("precheck.json")
        for c in data["cases"]:
            with self.subTest(c["name"]):
                r = check(c["action"], {**data["policy"], **c["policy"]}, c["context"])
                got = {"verdict": r["verdict"], "kind": r["kind"], "rules": sorted({f["rule"] for f in r["findings"]})}
                self.assertEqual(got, c["expect"])

    def test_scan(self):
        for c in load("scan.json"):
            with self.subTest(c["file"]):
                data = json.loads((ROOT / "examples" / "tools" / c["file"]).read_text("utf-8"))
                rep = scan(data, Path(c["file"]).stem, c.get("pins"))
                if c.get("pins"):
                    got = {"score": rep["score"], "grade": rep["grade"], "removed": rep["removed_tools"], "pinstatus": {t["name"]: t["pin"] for t in rep["tools"]}}
                else:
                    got = {"score": rep["score"], "grade": rep["grade"], "tools": [
                        {"name": t["name"], "sha256": t["sha256"], "score": t["score"], "grade": t["grade"], "capabilities": t["capabilities"],
                         "rules": sorted({x["rule"] for x in t["findings"]})} for t in rep["tools"]]}
                self.assertEqual(got, c["expect"])

    def test_canonical(self):
        for c in load("canonical.json"):
            self.assertEqual(canonical(c["value"]), c["canonical"])


class Engine(unittest.TestCase):
    def test_every_verdict_has_findings(self):
        pol = load_policy({"home": "/h", "workspace": "/h/p"})
        r = check({"tool": "Bash", "arguments": {"command": "rm -rf ~"}}, pol)
        self.assertEqual(r["verdict"], "deny")
        self.assertTrue(all(f["message"] for f in r["findings"]))

    def test_substitution_is_parsed(self):
        names = [s["name"] for s in parse_shell("echo $(rm -rf ~) `whoami`")]
        self.assertIn("rm", names)
        self.assertIn("whoami", names)
        r = check({"tool": "Bash", "arguments": {"command": "echo $(rm -rf ~)"}}, {"home": "/h", "workspace": "/h/p"})
        self.assertEqual(r["verdict"], "deny")

    def test_policy_errors(self):
        with self.assertRaises(ValueError):
            load_policy({"on_ask": "maybe"})

    def test_scan_input_shapes(self):
        tool = {"name": "t", "description": "x", "inputSchema": {"type": "object"}}
        for shape in ([tool], {"tools": [tool]}, {"jsonrpc": "2.0", "id": 1, "result": {"tools": [tool]}}, tool):
            self.assertEqual(scan(shape)["tool_count"], 1)
        with self.assertRaises(ValueError):
            scan("nope")

    def test_numbers_match_javascript(self):
        self.assertEqual(canonical([1e-7, 0.00001, 1e21, 100.0, 2.5]), "[1e-7,0.00001,1e+21,100,2.5]")


class Crypto(unittest.TestCase):
    VECTORS = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_rfc8032_pure_python(self):
        for sk, pk, m, sig in self.VECTORS:
            sk, pk, m, sig = (bytes.fromhex(x) for x in (sk, pk, m, sig))
            a, _ = ed25519._expand(sk)
            self.assertEqual(ed25519._compress(ed25519._mul(a, ed25519._G)), pk)
            self.assertEqual(ed25519._sign_py(sk, m), sig)
            self.assertTrue(ed25519._verify_py(pk, m, sig))
            self.assertFalse(ed25519._verify_py(pk, m + b"!", sig))

    def test_public_api(self):
        for sk, pk, m, sig in self.VECTORS:
            sk, pk, m, sig = (bytes.fromhex(x) for x in (sk, pk, m, sig))
            self.assertEqual(ed25519.public_key(sk), pk)
            self.assertEqual(ed25519.sign(sk, m), sig)
            self.assertTrue(ed25519.verify(pk, m, sig))

    def test_receipt_tamper(self):
        k = Key.generate()
        r = sign_receipt({"seq": 0, "prev": None, "action": {"tool": "x"}}, k)
        self.assertTrue(verify_receipt(r, k.public))
        bad = json.loads(json.dumps(r))
        bad["action"]["tool"] = "y"
        self.assertFalse(verify_receipt(bad, k.public))
        self.assertFalse(verify_receipt(r, Key.generate().public))

    def test_ledger_chain(self):
        with tempfile.TemporaryDirectory() as d:
            k = Key.generate()
            led = Ledger(Path(d) / "l.jsonl", k)
            pol = load_policy({})
            for i in range(5):
                act = {"server": "s", "tool": "Bash", "arguments": {"command": f"echo {i}"}}
                led.append(agent="a", session="s", action=act, decision=check(act, pol), outcome={"status": "ok", "result_sha256": None}, policy_sha256="sha256:0")
            rs = read_ledger(Path(d) / "l.jsonl")
            self.assertTrue(verify_ledger(rs, k.public)["ok"])
            self.assertFalse(verify_ledger(rs[:2] + rs[3:], k.public)["ok"])
            self.assertFalse(verify_ledger([rs[1], rs[0]] + rs[2:], k.public)["ok"])
            # reopening continues the chain
            led2 = Ledger(Path(d) / "l.jsonl", k)
            self.assertEqual(led2.seq, 5)

    def test_key_file_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            k = Key.generate()
            k.save(Path(d) / "k.json")
            self.assertEqual(Key.load(Path(d) / "k.json").public, k.public)
            if os.name == "posix":
                self.assertEqual(os.stat(Path(d) / "k.json").st_mode & 0o777, 0o600)


@unittest.skipUnless(NODE, "node is not installed")
class CrossEngine(unittest.TestCase):
    def test_javascript_fixtures(self):
        p = subprocess.run([NODE, str(ROOT / "tests" / "test_engine.mjs")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)

    def test_python_verifies_javascript(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "js.jsonl"
            p = subprocess.run([NODE, str(ROOT / "tests" / "test_engine.mjs"), "--sign-out", str(out)], capture_output=True, text=True, check=True)
            pub = unb64u(p.stdout.strip())
            self.assertTrue(verify_ledger(read_ledger(out), pub)["ok"])

    def test_javascript_verifies_python(self):
        with tempfile.TemporaryDirectory() as d:
            k = Key.generate()
            path = Path(d) / "py.jsonl"
            led = Ledger(path, k)
            pol = load_policy({})
            for act in ({"server": "s", "tool": "pay", "arguments": {"amount": 0.1, "currency": "USD", "memo": "ünï ✓ 😀"}},
                        {"server": "s", "tool": "Bash", "arguments": {"command": "rm -rf ~"}}):
                led.append(agent="py", session="s", action=act, decision=check(act, pol), outcome={"status": "ok", "result_sha256": digest({"x": 1e-7})}, policy_sha256="sha256:0", include_args=True)
            p = subprocess.run([NODE, str(ROOT / "tests" / "test_engine.mjs"), "--verify", str(path), k.to_json()["public"]], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)


class GatewayTests(unittest.TestCase):
    """Drive the real gateway over pipes with the demo MCP server behind it."""

    def run_gateway(self, messages, server_args=(), policy=None, home=None, client_answer=None, **gw_options):
        home = Path(home or tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, home, True)
        pol = load_policy({"workspace": str(home / "project"), **(policy or {})})
        r_in, w_in = os.pipe()
        r_out, w_out = os.pipe()
        cin, cout = os.fdopen(r_in, "rb"), os.fdopen(w_out, "wb")
        gw = Gateway([PY, "-m", "verfy.demo_server", *server_args], server="demo", policy=pol, key=Key.generate(),
                     ledger_path=home / "ledger.jsonl", lock_path=home / "verfy.lock", home=home, scans_dir=home / "scans",
                     stdin=cin, stdout=cout, log=lambda m: None, **gw_options)
        env_pp = os.environ.get("PYTHONPATH", "")
        os.environ["PYTHONPATH"] = str(ROOT / "src") + (os.pathsep + env_pp if env_pp else "")
        t = threading.Thread(target=lambda: (gw.run(), cout.close()))
        t.start()
        to_gw = os.fdopen(w_in, "wb")
        from_gw = os.fdopen(r_out, "rb")
        replies = {}
        for m in messages:
            to_gw.write((json.dumps(m) + "\n").encode())
            to_gw.flush()
            if "id" not in m:
                continue
            while True:
                line = from_gw.readline()
                self.assertTrue(line, "gateway closed early")
                msg = json.loads(line)
                if msg.get("method") == "elicitation/create":
                    to_gw.write((json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": client_answer}) + "\n").encode())
                    to_gw.flush()
                    continue
                if msg.get("id") == m["id"]:
                    replies[m["id"]] = msg
                    break
        to_gw.close()
        t.join(timeout=15)
        from_gw.close()
        cin.close()
        os.environ["PYTHONPATH"] = env_pp
        return replies, gw, home

    INIT = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}]

    def call(self, i, name, args):
        return {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": name, "arguments": args}}

    def test_blocks_and_receipts(self):
        msgs = self.INIT + [self.call(2, "run_command", {"command": "ls"}), self.call(3, "run_command", {"command": "rm -rf ~"}),
                            self.call(4, "add_numbers", {"a": 1, "b": 2, "sidenote": "x"}), self.call(5, "nope", {})]
        rep, gw, home = self.run_gateway(msgs, ["--poisoned"])
        names = [t["name"] for t in rep[1]["result"]["tools"]]
        self.assertNotIn("add_numbers", names)
        self.assertFalse(rep[2]["result"]["isError"])
        self.assertTrue(rep[3]["result"]["isError"])
        self.assertIn("VFY-SH-001", rep[3]["result"]["content"][0]["text"])
        self.assertIn("VFY-TOOL-003", rep[4]["result"]["content"][0]["text"])
        self.assertIn("VFY-TOOL-005", rep[5]["result"]["content"][0]["text"])
        rs = read_ledger(home / "ledger.jsonl")
        self.assertEqual([r["outcome"]["status"] for r in rs], ["ok", "blocked", "blocked", "blocked"])
        self.assertTrue(verify_ledger(rs, gw.ledger.key.public)["ok"])
        self.assertTrue((home / "scans" / "demo.json").exists())

    def test_rug_pull(self):
        home = Path(tempfile.mkdtemp())
        self.run_gateway(self.INIT, home=home)
        pins = server_pins(load_lock(home / "verfy.lock"), "demo")
        self.assertIn("read_file", pins)
        home2 = Path(tempfile.mkdtemp())
        shutil.copy(home / "verfy.lock", home2 / "verfy.lock")
        rep, _, _ = self.run_gateway(self.INIT + [self.call(2, "read_file", {"path": "a.txt"})], ["--rugpull"], home=home2)
        self.assertNotIn("read_file", [t["name"] for t in rep[1]["result"]["tools"]])
        self.assertIn("VFY-TOOL-004", rep[2]["result"]["content"][0]["text"])

    def test_secrets_in_output_are_redacted(self):
        msgs = self.INIT + [self.call(2, "read_file", {"path": ".env"})]
        rep, _, home = self.run_gateway(msgs, ["--leaky"], policy={"files": {"sensitive": []}, "on_ask": "allow"})
        text = rep[2]["result"]["content"][0]["text"]
        self.assertIn("[REDACTED:openai-key]", text)
        self.assertIn("[REDACTED:github-token]", text)
        self.assertIn("DEBUG=1", text)
        self.assertNotIn("sk-proj-", text)
        self.assertNotIn("ghp_", text)
        receipt = read_ledger(home / "ledger.jsonl")[0]
        self.assertEqual(receipt["outcome"]["status"], "ok")
        rep, _, _ = self.run_gateway(msgs, ["--leaky"], policy={"files": {"sensitive": []}, "on_ask": "allow", "redact_output": False})
        self.assertIn("ghp_", rep[2]["result"]["content"][0]["text"])

    def test_redaction_covers_every_secret(self):
        from verfy._util import redact, redact_output
        a, b = "ghp_" + "a1B2" * 9, "ghp_" + "c3D4" * 9
        self.assertEqual(redact(f"{a} and {b}"), "[REDACTED:github-token] and [REDACTED:github-token]")
        out, n = redact_output({"content": [{"type": "text", "text": a}, {"type": "image", "data": "AKIA" + "B" * 16, "mimeType": "image/png"}]})
        self.assertEqual(n, 1)
        self.assertEqual(out["content"][0]["text"], "[REDACTED:github-token]")
        self.assertEqual(out["content"][1]["data"], "AKIA" + "B" * 16)

    def team_home(self):
        from verfy.team import save_team
        home = Path(tempfile.mkdtemp())
        save_team(home, {"url": "https://verfy.example.test", "token": "atd_" + "x" * 43, "kid": "atl_" + "0" * 16, "device_id": "d1"})
        return home

    def fake_team(self, answers):
        sent = []

        def transport(method, url, body, headers):
            sent.append((method, url, body))
            if method == "POST":
                return 201, {"id": "a1", "status": "pending", "expires_at": "2026-10-24T12:00:00Z"}
            return 200, answers.pop(0) if len(answers) > 1 else answers[0]
        return transport, sent

    def test_team_approval_queue(self):
        ask = self.call(2, "run_command", {"command": "git push --force"})
        transport, sent = self.fake_team([{"status": "pending"}, {"status": "approved", "decided_by": "Alice"}])
        rep, _, home = self.run_gateway(self.INIT + [ask], policy={"on_ask": "team"}, home=self.team_home(), team_transport=transport, poll_seconds=0.01)
        self.assertFalse(rep[2]["result"]["isError"])
        method, url, body = sent[0]
        self.assertEqual((method, url), ("POST", "https://verfy.example.test/api/v1/approvals"))
        self.assertTrue(body["args_sha256"].startswith("sha256:"))
        self.assertNotIn("git push", json.dumps(body))  # only the hash of the arguments leaves the machine
        self.assertEqual(sent[-1][1], "https://verfy.example.test/api/v1/approvals/a1")
        r = read_ledger(home / "ledger.jsonl")[0]
        self.assertEqual((r["decision"]["approved_by"], r["outcome"]["status"]), ("team:Alice", "ok"))

        transport, _ = self.fake_team([{"status": "rejected", "note": "not on Friday"}])
        rep, _, home = self.run_gateway(self.INIT + [ask], policy={"on_ask": "team"}, home=self.team_home(), team_transport=transport, poll_seconds=0.01)
        self.assertTrue(rep[2]["result"]["isError"])
        self.assertIn("rejected", rep[2]["result"]["content"][0]["text"])
        self.assertIn("not on Friday", rep[2]["result"]["content"][0]["text"])
        self.assertEqual(read_ledger(home / "ledger.jsonl")[0]["outcome"]["status"], "declined")

        rep, _, _ = self.run_gateway(self.INIT + [ask], policy={"on_ask": "team"})  # not enrolled: refused, never run
        self.assertTrue(rep[2]["result"]["isError"])
        self.assertIn("could not reach your team", rep[2]["result"]["content"][0]["text"])
        with self.assertRaises(ValueError):
            load_policy({"on_ask": "team", "approval_timeout": 5})

    def test_on_ask_modes(self):
        ask = self.call(2, "run_command", {"command": "git push --force"})
        rep, _, _ = self.run_gateway(self.INIT + [ask])
        self.assertTrue(rep[2]["result"]["isError"])
        rep, _, home = self.run_gateway(self.INIT + [ask], policy={"on_ask": "allow"})
        self.assertFalse(rep[2]["result"]["isError"])
        self.assertEqual(read_ledger(home / "ledger.jsonl")[0]["decision"]["approved_by"], "policy")

    def test_elicitation(self):
        init = [dict(self.INIT[0], params={**self.INIT[0]["params"], "capabilities": {"elicitation": {}}})] + self.INIT[1:]
        ask = self.call(2, "run_command", {"command": "git push --force"})
        rep, _, home = self.run_gateway(init + [ask], policy={"on_ask": "elicit"}, client_answer={"action": "accept", "content": {"approve": True}})
        self.assertFalse(rep[2]["result"]["isError"])
        self.assertEqual(read_ledger(home / "ledger.jsonl")[0]["decision"]["approved_by"], "user")
        rep, _, home = self.run_gateway(init + [ask], policy={"on_ask": "elicit"}, client_answer={"action": "decline"})
        self.assertTrue(rep[2]["result"]["isError"])
        self.assertEqual(read_ledger(home / "ledger.jsonl")[0]["outcome"]["status"], "declined")

    def test_daily_budget(self):
        msgs = self.INIT + [self.call(i, "send_payment", {"amount": 18, "currency": "USD", "to": "acme"}) for i in range(2, 14)]
        rep, _, _ = self.run_gateway(msgs)
        ran = [i for i in range(2, 14) if not rep[i]["result"]["isError"]]
        self.assertEqual(len(ran), 11)  # 11 x 18 = 198 <= 200, the 12th would pass the budget
        self.assertIn("VFY-PAY-002", rep[13]["result"]["content"][0]["text"])


class CLI(unittest.TestCase):
    def run_cli(self, *args, home=None):
        out, err = io.StringIO(), io.StringIO()
        old = os.environ.get("VERFY_HOME")
        os.environ["VERFY_HOME"] = home or tempfile.mkdtemp()
        try:
            from contextlib import redirect_stderr, redirect_stdout
            with redirect_stdout(out), redirect_stderr(err):
                code = cli_main(list(args))
        finally:
            if old is None:
                os.environ.pop("VERFY_HOME", None)
            else:
                os.environ["VERFY_HOME"] = old
        return code, out.getvalue(), err.getvalue()

    def test_check_exit_codes(self):
        self.assertEqual(self.run_cli("check", "ls -la")[0], 0)
        self.assertEqual(self.run_cli("check", "git push --force")[0], 1)
        self.assertEqual(self.run_cli("check", "--", "rm", "-rf", "/")[0], 2)
        code, out, _ = self.run_cli("check", "--tool", "send_payment", "--args", '{"amount": 500}', "--json")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["findings"][0]["rule"], "VFY-PAY-001")

    def test_scan_and_fail_under(self):
        code, out, _ = self.run_cli("scan", str(ROOT / "examples/tools/poisoned-math.json"), "--fail-under", "C")
        self.assertEqual(code, 1)
        self.assertIn("VFY-SCAN-001", out)
        code, out, _ = self.run_cli("scan", str(ROOT / "examples/tools/filesystem.json"), "--fail-under", "B", "--json")
        self.assertEqual((code, json.loads(out)["grade"]), (0, "A"))

    def test_scan_live_server(self):
        env_pp = os.environ.get("PYTHONPATH", "")
        os.environ["PYTHONPATH"] = str(ROOT / "src")
        try:
            code, out, _ = self.run_cli("scan", "--json", "--", PY, "-m", "verfy.demo_server", "--poisoned")
        finally:
            os.environ["PYTHONPATH"] = env_pp
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["grade"], "F")

    def test_init_wrap_and_ledger(self):
        home = tempfile.mkdtemp()
        self.assertEqual(self.run_cli("init", home=home)[0], 0)
        self.assertTrue(Path(home, "key.json").exists())
        cfg = Path(home, "cfg.json")
        cfg.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["-y", "server-fs", "/tmp"]}, "web": {"url": "https://x"}}}))
        code, out, _ = self.run_cli("wrap", str(cfg), home=home)
        wrapped = json.loads(out)["mcpServers"]
        self.assertEqual(wrapped["fs"]["args"][:4], ["proxy", "--name", "fs", "--"])
        self.assertEqual(wrapped["web"], {"url": "https://x"})
        code, out, _ = self.run_cli("ledger", "verify", home=home)
        self.assertEqual(code, 0)

    def test_ledger_show_json_preserves_recent_signed_receipts(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "receipts.jsonl"
            key = Key.generate()
            ledger = Ledger(path, key)
            for i in range(3):
                ledger.append(
                    agent="test", session="synthetic",
                    action={"server": "demo", "tool": "echo", "arguments": {"message": f"hello {i} ✓"}},
                    decision={"verdict": "allow", "rules": []},
                    outcome={"status": "ok", "result_sha256": None},
                    policy_sha256="sha256:0", include_args=True,
                )
            stored = read_ledger(path)
            before = path.read_bytes()
            for options, expected in [(("-n", "2"), stored[-2:]), (("-n", "5"), stored), ((), stored)]:
                with self.subTest(options=options):
                    code, out, err = self.run_cli("ledger", "show", "--json", "--ledger", str(path), *options, home=home)
                    self.assertEqual(code, 0, err)
                    receipts = json.loads(out)
                    self.assertEqual(receipts, expected)
                    self.assertTrue(all("sig" in r and verify_receipt(r, key.public) for r in receipts))
            self.assertEqual(path.read_bytes(), before)

    def test_ledger_show_json_empty_ledger(self):
        with tempfile.TemporaryDirectory() as home:
            path = Path(home) / "ledger.jsonl"
            for exists in (False, True):
                with self.subTest(exists=exists):
                    if exists:
                        path.touch()
                    code, out, err = self.run_cli("ledger", "show", "--json", home=home)
                    self.assertEqual(code, 0, err)
                    self.assertEqual(json.loads(out), [])
            code, out, err = self.run_cli("ledger", "show", home=home)
            self.assertEqual(code, 0, err)
            self.assertEqual(out, "No receipts yet.\n")


if __name__ == "__main__":
    unittest.main()
