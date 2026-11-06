"""Tests for Cursor's hook and for reaching the sandbox from Windows. Run from verfy-cli/: ``python -m unittest discover -s tests``."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import cli, hook, lock, sandbox  # noqa: E402
from verfy._util import real_file  # noqa: E402
from verfy.policy import load_policy  # noqa: E402
from verfy.precheck import check  # noqa: E402
from verfy.scanner import tool_pin  # noqa: E402


def shell(command):
    return {"hook_event_name": "beforeShellExecution", "conversation_id": "conv1", "command": command, "cwd": "/home/you/project", "sandbox": False}


def mcp(server="github", tool="create_issue", args='{"title": "x"}'):
    return {"hook_event_name": "beforeMCPExecution", "conversation_id": "conv1", "mcp_server_name": server, "tool_name": tool, "tool_input": args, "command": "npx server"}


def read(path):
    return {"hook_event_name": "beforeReadFile", "conversation_id": "conv1", "file_path": path, "content": "the file", "workspace_roots": ["/home/you/project"]}


class CursorHookTests(unittest.TestCase):
    def run_hook(self, payload, policy=None, fail_mode=None, raw=None):
        records = []
        out = io.StringIO()
        pol = load_policy({"home": "/home/you", "workspace": "/home/you/project", **(policy or {})})

        def record(**kw):
            records.append(kw)
            return {"id": "rcpt_test", "seq": len(records) - 1}
        code = hook.run_hook("cursor", stdin=io.StringIO(raw if raw is not None else json.dumps(payload)), stdout=out,
                             get_policy=lambda cwd: pol, record=record, fail_mode=fail_mode)
        self.assertEqual(code, 0)
        return json.loads(out.getvalue()), records

    def test_a_dangerous_command_is_denied_and_recorded(self):
        out, records = self.run_hook(shell("rm -rf ~"))
        self.assertEqual(out["permission"], "deny")
        self.assertIn("Verfy blocked this action", out["user_message"])
        self.assertEqual(out["agent_message"], out["user_message"])
        self.assertEqual(records[0]["action"]["server"], "cursor")
        self.assertEqual(records[0]["session"], "conv1")

    def test_a_byte_order_mark_from_powershell_changes_nothing(self):
        # Windows PowerShell puts one before the JSON when its output encoding is UTF-8
        self.assertEqual(self.run_hook(None, raw="\ufeff" + json.dumps(shell("ls -la")))[0], {"permission": "allow"})
        self.assertEqual(self.run_hook(None, raw="\ufeff" + json.dumps(shell("rm -rf ~")))[0]["permission"], "deny")

    def test_an_ordinary_command_gets_an_answer(self):
        # Cursor counts no output as a failure, so "allow" has to be said
        self.assertEqual(self.run_hook(shell("ls -la"))[0], {"permission": "allow"})

    def test_mcp_arguments_arrive_as_a_json_string(self):
        out, records = self.run_hook(mcp(), policy={"tools": {"deny": ["github/create_issue"]}})
        self.assertEqual(out["permission"], "deny")
        self.assertEqual(records[0]["action"], {"server": "github", "tool": "create_issue", "arguments": {"title": "x"}})

    def test_the_terminal_and_mcp_hooks_can_ask_a_person(self):
        out, _ = self.run_hook(mcp(tool="delete_repo"), policy={"tools": {"ask": ["github/delete_repo"]}})
        self.assertEqual(out["permission"], "ask")

    def test_a_server_name_with_underscores_stays_whole(self):
        _, records = self.run_hook(mcp(server="my__server", tool="a__b"))
        self.assertEqual((records[0]["action"]["server"], records[0]["action"]["tool"]), ("my__server", "a__b"))

    def test_a_read_cannot_wait_for_a_person(self):
        out, _ = self.run_hook(read("/home/you/.ssh/id_rsa"))
        self.assertEqual(out["permission"], "deny")
        self.assertEqual(set(out), {"permission", "user_message"})  # anything else does not match Cursor's schema, which blocks the read

    def test_an_ordinary_read_is_allowed(self):
        self.assertEqual(self.run_hook(read("/home/you/project/main.py"))[0], {"permission": "allow"})

    def test_what_it_cannot_read_is_never_allowed(self):
        for payload in ({"hook_event_name": "beforeShellExecution"}, {"hook_event_name": "beforeMCPExecution", "tool_name": "x"},
                        {"hook_event_name": "beforeReadFile"}, {"hook_event_name": "preToolUse"}, {}, mcp(args="{not json")):
            self.assertNotEqual(self.run_hook(payload)[0]["permission"], "allow", payload)
        for raw in ("nope", "[]", ""):
            self.assertEqual(self.run_hook(None, raw=raw)[0]["permission"], "deny", raw)
        self.assertEqual(self.run_hook(None, raw="nope", fail_mode=lambda: "allow")[0]["permission"], "deny")

    def test_a_broken_terminal_hook_asks_by_default_and_denies_if_told(self):
        payload = {"hook_event_name": "beforeShellExecution"}
        self.assertEqual(self.run_hook(payload)[0]["permission"], "ask")
        self.assertEqual(self.run_hook(payload, fail_mode=lambda: "deny")[0]["permission"], "deny")

    def test_the_agent_cannot_remove_the_hook(self):
        for command in ("rm .cursor/hooks.json", "echo {} > ~/.cursor/hooks.json"):
            self.assertEqual(self.run_hook(shell(command))[0]["permission"], "deny", command)
        pol = load_policy({"home": "/home/you", "workspace": "/home/you/project"})
        for path in ("/home/you/.cursor/hooks.json", "/home/you/project/.cursor/hooks.json"):
            decision = check({"server": "claude-code", "tool": "write_file", "arguments": {"file_path": path, "content": "{}"}}, pol)
            self.assertEqual(decision["verdict"], "deny", path)


class CursorInstallTests(unittest.TestCase):
    def test_it_adds_three_hooks_that_fail_closed_and_keeps_the_rest(self):
        config, changed = hook.with_cursor_hook({"version": 1, "hooks": {"afterFileEdit": [{"command": "./format.sh"}], "beforeShellExecution": [{"command": "./mine.sh"}]}})
        self.assertTrue(changed)
        self.assertEqual(config["hooks"]["afterFileEdit"], [{"command": "./format.sh"}])
        self.assertEqual(config["hooks"]["beforeShellExecution"][0], {"command": "./mine.sh"})
        for event in hook.CURSOR_EVENTS:
            self.assertEqual(config["hooks"][event][-1], {"command": "verfy hook cursor", "failClosed": True})
        self.assertFalse(hook.with_cursor_hook(config)[1])

    def test_a_new_file_has_the_version_cursor_requires(self):
        self.assertEqual(hook.with_cursor_hook({})[0]["version"], 1)

    def test_it_refuses_a_file_it_cannot_understand(self):
        with self.assertRaises(ValueError):
            hook.with_cursor_hook({"hooks": []})
        with self.assertRaises(ValueError):
            hook.with_cursor_hook({"hooks": {"beforeReadFile": {}}})

    def test_install_writes_only_with_write_and_keeps_a_backup(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        path = tmp / ".cursor" / "hooks.json"
        with mock.patch.object(hook, "cursor_hooks_path", return_value=path):
            self.assertTrue(cli._install_hook(False, False, cursor=True)[1])
            self.assertFalse(path.exists())
            cli._install_hook(False, True, cursor=True)
            self.assertIn("beforeMCPExecution", json.loads(path.read_text("utf-8"))["hooks"])
            path.write_text('{"version": 1, "hooks": {}}', "utf-8")
            cli._install_hook(False, True, cursor=True)
        self.assertEqual(path.with_suffix(".json.verfy-backup").read_text("utf-8"), '{"version": 1, "hooks": {}}')


class EnvironmentTests(unittest.TestCase):
    OUTSIDE = {"PATH": "/bin", "HOME": "/home/you", "LC_ALL": "C", "XDG_CACHE_HOME": "/c", "VERFY_HOME": "/v", "AWS_SECRET_ACCESS_KEY": "k1",
               "GITHUB_TOKEN": "k2", "ANTHROPIC_API_KEY": "k3", "VERFY_BRIDGE_HEADERS": "k4", "API_KEY": "k5"}

    def test_keys_stay_outside(self):
        got = sandbox.runtime_env(self.OUTSIDE)
        self.assertEqual(set(got), {"PATH", "HOME", "LC_ALL", "XDG_CACHE_HOME", "VERFY_HOME", sandbox.MARK_ENV})
        self.assertEqual(got[sandbox.MARK_ENV], "srt")

    def test_a_named_variable_goes_in_and_nothing_else(self):
        got = sandbox.runtime_env(self.OUTSIDE, ["API_KEY", "NOT_SET"])
        self.assertEqual(got["API_KEY"], "k5")
        self.assertNotIn("NOT_SET", got)
        self.assertNotIn("GITHUB_TOKEN", got)

    def test_an_agent_keeps_its_own_key_only(self):
        got = sandbox.runtime_env(self.OUTSIDE, agent=True)
        self.assertEqual(got["ANTHROPIC_API_KEY"], "k3")
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", got)


class AttackRegressionTests(unittest.TestCase):
    """What an internal attack run got past Verfy. Each one stays closed."""

    def setUp(self):
        self.pol = load_policy({"home": "/home/you", "workspace": "/home/you/project"})

    def verdict(self, command):
        return check({"tool": "Bash", "arguments": {"command": command}}, self.pol)["verdict"]

    def test_home_spelled_as_a_variable_is_home(self):
        for command in ("cat $HOME/.ssh/id_rsa", "cat ${HOME}/.aws/credentials", "dd if=$HOME/.ssh/id_rsa", "base64 $HOME/.ssh/id_rsa"):
            self.assertNotEqual(self.verdict(command), "allow", command)

    def test_everyday_commands_stay_allowed(self):
        for command in ("npm test", "git status", "git remote -v", "git config user.name me", "python3 -c 'print(1)'", "node -e 'console.log(1)'", "mv a.txt b.txt",
                        "rsync -a src/ dst/", "crontab -l", "systemctl status x", "docker run --rm alpine echo hi", "docker run -v $(pwd):/app node:20 npm test",
                        "curl -o out.json https://example.com/a", "cat README.md", "$HOME/.cargo/bin/cargo build", "git rm old.txt", "pytest -q", "ls -la"):
            self.assertEqual(self.verdict(command), "allow", command)

    def test_a_pin_covers_what_a_client_acts_on(self):
        base = {"name": "t", "description": "d", "inputSchema": {"type": "object"}}
        for extra in ({"annotations": {"readOnlyHint": True}}, {"title": "x"}, {"outputSchema": {"type": "object"}}):
            self.assertNotEqual(tool_pin({**base, **extra}), tool_pin(base))
        self.assertEqual(tool_pin(base), tool_pin({**base, "_meta": {"x": 1}}))

    def test_a_lock_keeps_what_the_pin_covers(self):
        tool = {"name": "t", "description": "d", "inputSchema": {}, "annotations": {"readOnlyHint": True}}
        self.assertEqual(tool_pin(lock.definition(tool)), tool_pin(tool))

    def test_a_changed_annotation_is_explained(self):
        old = {"name": "t", "description": "d", "inputSchema": {}}
        got = lock.explain(old, {**old, "annotations": {"readOnlyHint": True}})
        self.assertEqual(got["risk"], "medium")
        self.assertIn("annotations", got["summary"] + str(got["changes"]))

    def test_the_sandbox_closes_what_runs_later_even_if_it_is_missing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        with mock.patch.object(Path, "cwd", return_value=tmp):
            deny = sandbox.runtime_settings({})["filesystem"]["denyWrite"]
            agent = sandbox.runtime_settings({}, agent=True)["filesystem"]["denyWrite"]
        for path in ("./verfy.lock", "./verfy.policy.json", "./.mcp.json", "./.claude", "./.claude/settings.json", "./.cursor", "./.cursor/mcp.json", "./.git/hooks", "./.git/config"):
            self.assertIn(path, deny)
            self.assertIn(path, agent)

    def test_what_the_runtime_leaves_in_place_of_a_missing_file_counts_as_missing(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "verfy.policy.json").write_text("")
        (tmp / "verfy.lock").write_text("")
        self.assertFalse(real_file(tmp / "verfy.policy.json"))
        self.assertFalse(real_file(tmp))
        self.assertFalse(real_file(tmp / "nothing"))
        self.assertNotEqual(cli.default_policy_path(tmp), tmp / "verfy.policy.json")
        self.assertEqual(lock.load_lock(tmp / "verfy.lock"), lock.empty_lock())
        (tmp / "verfy.policy.json").write_text("{}")
        self.assertTrue(real_file(tmp / "verfy.policy.json"))
        self.assertEqual(cli.default_policy_path(tmp), tmp / "verfy.policy.json")

    @unittest.skipIf(sys.platform == "win32", "no /dev/null")
    def test_a_device_in_place_of_a_file_counts_as_missing(self):
        self.assertFalse(real_file(Path("/dev/null")))
        self.assertEqual(lock.load_lock("/dev/null"), lock.empty_lock())

    def test_a_broken_lock_with_something_in_it_still_stops(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "verfy.lock").write_text("not json")
        with self.assertRaises(lock.LockError):
            lock.load_lock(tmp / "verfy.lock")


class GatewayInputTests(unittest.TestCase):
    """Only what Verfy could read and check reaches the server."""

    def gateway(self):
        from verfy.gateway import Gateway
        g = Gateway.__new__(Gateway)
        g.sent, g.answers, g.logged = [], [], []
        g.to_server = g.sent.append
        g.to_client = g.answers.append
        g.log = g.logged.append
        g.elicits, g.pending, g.client_caps = {}, {}, {}
        g._call = lambda msg: g.sent.append(("checked", msg))
        g._key = lambda i: repr(i)
        return g

    def test_a_line_that_is_not_json_is_dropped_and_answered(self):
        g = self.gateway()
        g.from_client(b'{"method":"tools/call","id":1,}')
        self.assertEqual(g.sent, [])
        self.assertEqual(g.answers[0]["error"]["code"], -32700)

    def test_a_tools_call_without_an_id_goes_nowhere(self):
        g = self.gateway()
        g.from_client(b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"x"}}')
        self.assertEqual(g.sent, [])

    def test_a_tools_call_in_a_batch_is_checked(self):
        g = self.gateway()
        g.from_client(b'[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}, 5]')
        self.assertEqual(g.sent[0][0], "checked")
        self.assertEqual(g.answers[0]["error"]["code"], -32600)

    def test_params_of_the_wrong_type_do_not_stop_it(self):
        g = self.gateway()
        g.from_client(b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":["x"]}')
        g.from_client(b'{"jsonrpc":"2.0","id":2,"method":"resources/read","params":3}')
        self.assertEqual(len(g.sent), 2)

    def test_blank_lines_are_ignored(self):
        g = self.gateway()
        g.from_client(b"  \n")
        self.assertEqual((g.sent, g.answers), ([], []))


class WindowsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def test_inside_wsl_the_windows_users_keys_are_closed_too(self):
        for name in ("you", "Public", "Default"):
            (self.tmp / "c" / "Users" / name).mkdir(parents=True)
        (self.tmp / "c" / "Users" / "notes.txt").write_text("")
        homes = sandbox.windows_homes(self.tmp)
        self.assertEqual([h.name for h in homes], ["you"])
        with mock.patch.object(sandbox, "windows_homes", return_value=homes):
            deny = sandbox.runtime_settings({})["filesystem"]["denyRead"]
            agent = sandbox.runtime_settings({}, agent=True)["filesystem"]["denyRead"]
        for rules in (deny, agent):
            self.assertIn(f"{homes[0].as_posix()}/.ssh", rules)
            self.assertIn(f"{homes[0].as_posix()}/.aws", rules)

    def test_no_mounted_drives_add_nothing(self):
        self.assertEqual(sandbox.windows_homes(self.tmp / "missing"), [])

    def test_without_wsl_nothing_runs(self):
        with self.assertRaisesRegex(ValueError, "was not run"):
            sandbox.wsl_command(["run"], Path("."), which=lambda _: None)

    def test_without_verfy_or_srt_inside_wsl_nothing_runs(self):
        with self.assertRaisesRegex(ValueError, "was not run"):
            sandbox.wsl_command(["run"], Path("."), which=lambda _: "wsl.exe", run=lambda *a, **k: types.SimpleNamespace(returncode=1))

    def test_the_arguments_are_passed_on_and_never_through_a_shell_string(self):
        command = sandbox.wsl_command(["run", "--sandbox", "--", "sh", "-c", "echo 'a b'; rm x"], Path("/w"), which=lambda _: "wsl.exe",
                                      run=lambda *a, **k: types.SimpleNamespace(returncode=0))
        self.assertEqual(command[:7], ["wsl.exe", "--cd", str(Path("/w")), "--exec", "bash", "-lc", 'exec verfy "$@"'])
        self.assertEqual(command[-3:], ["sh", "-c", "echo 'a b'; rm x"])

    def test_the_check_leaves_stdin_to_the_command(self):
        seen = {}

        def run(command, **kw):
            seen.update(kw)
            return types.SimpleNamespace(returncode=0)
        sandbox.wsl_command(["run"], Path("/w"), which=lambda _: "wsl.exe", run=run)
        self.assertEqual(seen["stdin"], sandbox.subprocess.DEVNULL)

    def test_every_flag_reaches_verfy_inside_wsl(self):
        args = types.SimpleNamespace(agent=True, allow_host=["a.dev"], allow_write=["out"], allow_env=["KEY"], policy="p.json", cmd=["node", "x.js"])
        with mock.patch.object(sandbox, "wsl_command", return_value=["wsl"]) as built, mock.patch.object(cli.subprocess, "run", return_value=types.SimpleNamespace(returncode=7)):
            self.assertEqual(cli._run_in_wsl(args), 7)
        self.assertEqual(built.call_args[0][0], ["run", "--sandbox", "--agent", "--allow-host", "a.dev", "--allow-write", "out", "--allow-env", "KEY", "--policy", "p.json", "--", "node", "x.js"])

    def test_refusing_is_exit_3(self):
        args = types.SimpleNamespace(agent=False, allow_host=[], allow_write=[], allow_env=[], policy=None, cmd=["x"])
        with mock.patch.object(sandbox, "wsl_command", side_effect=ValueError("no")), mock.patch.object(cli.subprocess, "run") as ran:
            self.assertEqual(cli._run_in_wsl(args), 3)
        ran.assert_not_called()


if __name__ == "__main__":
    unittest.main()
