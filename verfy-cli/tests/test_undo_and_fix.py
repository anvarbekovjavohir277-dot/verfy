"""Tests for ``verfy setup --undo`` and ``verfy posture --fix``. Run from verfy-cli/: ``python -m unittest discover -s tests``."""

from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import agents, cli, hook, posture, wrapcfg  # noqa: E402


class Home(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.cwd = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.addCleanup(shutil.rmtree, self.cwd, True)
        no_path = mock.patch("shutil.which", return_value=None)
        no_path.start()
        self.addCleanup(no_path.stop)

    def put(self, rel, data, base=None):
        p = (base or self.home) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n", "utf-8")
        return p

    def read(self, rel, base=None):
        return json.loads(((base or self.home) / rel).read_text("utf-8"))

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(Path, "home", return_value=self.home), mock.patch.object(Path, "cwd", return_value=self.cwd), \
                redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(args))
        return code, out.getvalue() + err.getvalue()


class UndoTests(Home):
    BEFORE = {
        ".claude/settings.json": {"permissions": {"allow": ["Bash(npm test)"]},
                                  "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "my-linter"}]}]}},
        ".cursor/mcp.json": {"mcpServers": {"fs": {"command": "npx", "args": ["-y", "fs@1.0.0"], "env": {"A": "1"}},
                                            "bare": {"command": "fs-server"},
                                            "login": {"url": "https://mcp.example.com/mcp"},
                                            "keyed": {"type": "http", "url": "https://k.example.com/mcp", "headers": {"Authorization": "Bearer ${K}"}}}},
        ".gemini/settings.json": {"theme": "x", "mcpServers": {"db": {"command": "uvx", "args": ["db-mcp"]}}},
    }

    def setup_then(self):
        for rel, data in self.BEFORE.items():
            self.put(rel, data)
        self.put(".codex/x", "")
        code, out = self.cli("setup", "--write")
        self.assertEqual(code, 0, out)
        self.assertIn("verfy hook cursor", (self.home / ".cursor/hooks.json").read_text("utf-8"))
        self.assertEqual(self.read(".cursor/mcp.json")["mcpServers"]["keyed"]["command"], "verfy")

    def test_undo_puts_every_file_back_as_it_was(self):
        self.setup_then()
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        for rel, data in self.BEFORE.items():
            self.assertEqual(self.read(rel), data, rel)
        # files that setup made and that held nothing but Verfy's hook are gone, each with a backup
        for rel in (".cursor/hooks.json", ".codex/hooks.json"):
            self.assertFalse((self.home / rel).exists(), rel)
            self.assertTrue((self.home / (rel + ".verfy-backup")).exists(), rel)
        self.assertIn("Restart the agents", out)
        # nothing is left to undo, and setup would add it all again
        code, out = self.cli("setup", "--undo")
        self.assertEqual(code, 0)
        self.assertIn("Verfy is not in any agent's files", out)
        code, out = self.cli("setup")
        self.assertIn("add the hook", out)

    def test_files_come_back_byte_for_byte(self):
        compact = b'{"mcpServers":{"api":{"url":"https://mcp.example.com/mcp","headers":{"Authorization":"Bearer ${K}"}}}}'
        crlf = b'{\r\n    "permissions": {"allow": ["Bash(npm test)"]}\r\n}\r\n'
        (self.home / ".cursor").mkdir()
        (self.home / ".cursor/mcp.json").write_bytes(compact)
        (self.home / ".claude").mkdir()
        (self.home / ".claude/settings.json").write_bytes(crlf)
        before = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        self.assertEqual(self.cli("setup", "--write")[0], 0)
        self.assertIn(b"\r\n", (self.home / ".claude/settings.json").read_bytes())  # setup keeps CRLF too
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        after = {p.relative_to(self.home): p.read_bytes() for p in self.home.rglob("*") if p.is_file() and not p.name.endswith(".verfy-backup")}
        self.assertEqual(after, before)
        # folders that setup made only for a hooks file are gone too
        self.assertEqual(sorted(p.name for p in self.home.iterdir()), [".claude", ".cursor"])

    def test_a_settings_file_with_comments_and_no_sandbox_is_not_reported(self):
        self.setup_then()
        self.put(".config/Code/User/settings.json", '{\n  // mine\n  "editor.fontSize": 14\n}\n')
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        self.assertNotIn("VS Code", out)

    def test_without_write_nothing_changes(self):
        self.setup_then()
        snapshot = {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        code, out = self.cli("setup", "--undo")
        self.assertEqual(code, 0, out)
        self.assertIn("Nothing changed yet. Run `verfy setup --undo --write`", out)
        self.assertIn("take out Verfy's hook", out)
        self.assertIn("take out from behind the gateway: fs, bare, keyed", out)
        self.assertIn("key, receipts and policy", out)
        self.assertEqual({p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()}, snapshot)

    def test_a_remote_server_without_its_backup_is_left_and_named(self):
        self.setup_then()
        (self.home / ".cursor/mcp.json.verfy-backup").unlink()
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        servers = self.read(".cursor/mcp.json")["mcpServers"]
        self.assertEqual(servers["fs"], self.BEFORE[".cursor/mcp.json"]["mcpServers"]["fs"])
        self.assertEqual(servers["bare"], {"command": "fs-server"})
        self.assertEqual(servers["keyed"]["command"], "verfy")  # still behind the gateway, not broken
        self.assertIn("left as it is: keyed (remote (https://k.example.com/mcp)", out)

    def test_changes_made_after_setup_are_kept(self):
        self.setup_then()
        cfg = self.read(".cursor/mcp.json")
        cfg["mcpServers"]["fs"]["env"]["B"] = "2"
        cfg["mcpServers"]["new"] = {"command": "later"}
        self.put(".cursor/mcp.json", cfg)
        self.cli("setup", "--undo", "--write")
        servers = self.read(".cursor/mcp.json")["mcpServers"]
        self.assertEqual(servers["fs"], {"command": "npx", "args": ["-y", "fs@1.0.0"], "env": {"A": "1", "B": "2"}})
        self.assertEqual(servers["new"], {"command": "later"})

    def test_one_agent_and_hooks_only(self):
        self.setup_then()
        code, out = self.cli("setup", "--undo", "--agent", "gemini", "--hooks-only", "--write")
        self.assertEqual(code, 0, out)
        gemini = self.read(".gemini/settings.json")
        self.assertNotIn("hooks", gemini)
        self.assertEqual(gemini["mcpServers"]["db"]["command"], "verfy")  # --hooks-only: the gateway stays
        self.assertIn("verfy hook cursor", (self.home / ".cursor/hooks.json").read_text("utf-8"))  # another agent: untouched

    def test_project_files(self):
        self.put(".mcp.json", {"mcpServers": {"fs": {"command": "npx", "args": ["fs"]}}}, self.cwd)
        self.cli("setup", "--project", "--agent", "claude-code", "--write")
        self.assertEqual(self.read(".mcp.json", self.cwd)["mcpServers"]["fs"]["command"], "verfy")
        self.assertTrue((self.cwd / ".claude/settings.json").exists())
        code, out = self.cli("setup", "--undo", "--project", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read(".mcp.json", self.cwd), {"mcpServers": {"fs": {"command": "npx", "args": ["fs"]}}})
        self.assertFalse((self.cwd / ".claude/settings.json").exists())

    def test_a_broken_file_stops_only_itself(self):
        self.setup_then()
        self.put(".gemini/settings.json", "{not json")
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 1)
        self.assertIn("not changed", out)
        self.assertEqual((self.home / ".gemini/settings.json").read_text("utf-8"), "{not json")
        self.assertFalse((self.home / ".cursor/hooks.json").exists())

    def test_copilot_and_devin_and_windsurf_hooks(self):
        for key in ("copilot", "devin", "windsurf"):
            self.cli("setup", "--agent", key, "--hooks-only", "--write")
        devin = hook.devin_config_path(False, home=self.home)
        made = [self.home / ".copilot/hooks/verfy.json", devin, self.home / ".codeium/windsurf/hooks.json"]
        for p in made:
            self.assertIn("verfy hook", p.read_text("utf-8"), p)
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        for p in made:
            self.assertFalse(p.exists(), p)

    def test_the_sandboxed_terminal_goes_too(self):
        settings = self.home / ".config" / "Code" / "User" / "settings.json"
        self.put(".config/Code/User/settings.json", {"editor.fontSize": 14})
        updated, _ = agents.with_sandbox_terminal({"editor.fontSize": 14}, True, sys.platform, {"path": "verfy", "args": ["run", "--sandbox"]})
        settings.write_text(json.dumps(updated), "utf-8")
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads(settings.read_text("utf-8")), {"editor.fontSize": 14})
        self.assertIn("sandboxed terminal removed", out)

    def test_undo_does_not_go_with_sandbox_terminal(self):
        code, out = self.cli("setup", "--undo", "--sandbox-terminal", "off")
        self.assertEqual(code, 2)

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs Python 3.11")
    def test_codex_config_toml_keeps_its_comments(self):
        before = ('# my codex\nmodel = "o4"\n\n[mcp_servers.fs]  # files\ncommand = "npx"\nargs = ["-y", "fs@1.0.0"]\nstartup_timeout_sec = 20\n\n'
                  '[mcp_servers.bare]\ncommand = "fs-server"\n')
        self.put(".codex/config.toml", before)
        self.cli("setup", "--agent", "codex", "--write")
        wrapped = (self.home / ".codex/config.toml").read_text("utf-8")
        self.assertIn('command = "verfy"', wrapped)
        code, out = self.cli("setup", "--undo", "--write")
        self.assertEqual(code, 0, out)
        import tomllib
        after = (self.home / ".codex/config.toml").read_text("utf-8")
        self.assertEqual(tomllib.loads(after), tomllib.loads(before))
        self.assertIn("# my codex", after)
        self.assertIn("# files", after)

    def test_what_counts_as_verfys_hook(self):
        yes = ["verfy hook cursor", "C:\\Tools\\verfy.exe hook pre-tool-use", "/usr/local/bin/verfy hook prompt",
               '"C:\\Program Files\\verfy\\verfy.exe" hook cursor', "verfy  hook codex"]
        no = ["myverfy hook x", "verfy hooks", "verfy proxy --name hook", "my-linter", None, 3]
        for command in yes:
            self.assertTrue(agents.is_verfy_hook(command), command)
        for command in no:
            self.assertFalse(agents.is_verfy_hook(command), command)

    def test_another_tools_hook_in_the_same_group_stays(self):
        cfg = {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "verfy hook pre-tool-use"},
                                                                   {"type": "command", "command": "audit-log"}]}],
                         "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]}}
        out, changed = agents.without_user_hooks(cfg, prune=True)
        self.assertTrue(changed)
        self.assertEqual(out, {"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "audit-log"}]}],
                                         "Stop": [{"hooks": [{"type": "command", "command": "notify"}]}]}})
        self.assertEqual(agents.without_user_hooks(out, prune=True), (out, False))

    def test_machine_wide_files(self):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        for platform in ("win32", "linux", "darwin"):
            items = agents.apply_system(agents.system_plan(platform, "verfy", root), [])
            self.assertTrue(all(i.get("done") for i in items), platform)
            cursor = agents.system_path("cursor", platform, root)
            cfg = json.loads(cursor.read_text("utf-8"))
            cfg["hooks"]["beforeShellExecution"].append({"command": "company-audit"})
            cursor.write_text(json.dumps(cfg), "utf-8")
            plan = agents.system_undo_plan(platform, root)
            self.assertEqual([(i["agent"].key, i["state"], bool(i.get("delete"))) for i in plan],
                             [("claude-code", "remove", True), ("cursor", "remove", False)], platform)
            agents.apply(plan)
            self.assertFalse(agents.system_path("claude-code", platform, root).exists())
            self.assertEqual(json.loads(cursor.read_text("utf-8")), {"version": 1, "hooks": {"beforeShellExecution": [{"command": "company-audit"}]}})
            self.assertEqual(agents.system_undo_plan(platform, root)[0]["state"], "off")

    def test_unwrap_leaves_what_verfy_did_not_write(self):
        mine = {"command": "verfy", "args": ["serve", "--", "x"]}  # runs verfy, but is not `verfy proxy ... --`
        text, names, left = wrapcfg.unwrap_text(Path("mcp.json"), json.dumps({"mcpServers": {"mine": mine, "plain": {"command": "npx"}}}))
        self.assertEqual((names, left), ([], {}))
        self.assertEqual(json.loads(text)["mcpServers"]["mine"], mine)


class PostureMoreAgentsTests(Home):
    def found(self):
        return {(f["agent"], f["setting"], f["severity"]) for f in posture.check(self.home, self.cwd)}

    def test_copilot_in_vs_code_also_with_comments(self):
        self.put(".config/Code/User/settings.json",
                 '{\n  // my settings\n  "chat.tools.global.autoApprove": true, /* yolo */\n  "url": "http://x//y",\n  "chat.permissions.default": "autopilot",\n}\n')
        self.put(".vscode/settings.json", {"chat.permissions.default": "autoApprove"}, self.cwd)
        self.assertEqual(self.found(), {("GitHub Copilot (VS Code)", "chat.tools.global.autoApprove = true", "high"),
                                        ("GitHub Copilot (VS Code)", 'chat.permissions.default = "autopilot"', "high"),
                                        ("GitHub Copilot (VS Code)", 'chat.permissions.default = "autoApprove"', "high")})

    def test_copilot_cli_and_devin(self):
        self.put(".copilot/settings.json", {"disableAllHooks": True, "askUser": True})
        devin = hook.devin_config_path(False, home=self.home)
        devin.parent.mkdir(parents=True)
        devin.write_text(json.dumps({"permission_mode": "dangerous", "permissions": {"allow": ["Exec(git status)", "exec", "Exec(**)"]}}), "utf-8")
        self.assertEqual(self.found(), {("GitHub Copilot CLI", "disableAllHooks = true", "high"), ("Devin", 'permission_mode = "dangerous"', "high"),
                                        ("Devin", "permissions.allow contains exec, Exec(**)", "medium")})

    def test_safe_values_are_not_reported(self):
        self.put(".config/Code/User/settings.json", {"chat.tools.global.autoApprove": False, "chat.permissions.default": "default"})
        self.put(".copilot/settings.json", {"disableAllHooks": False})
        self.put(".devin/config.json", {"permission_mode": "smart", "permissions": {"allow": ["Exec(npm test)", "Read(**)"]}}, self.cwd)
        self.assertEqual(self.found(), set())

    def test_jsonc(self):
        self.assertEqual(json.loads(posture.strip_jsonc('{"a": "x // not a comment", /* c */ "b": [1, 2,], // end\n}')),
                         {"a": "x // not a comment", "b": [1, 2]})


class PostureFixTests(Home):
    def test_fix_shows_then_writes(self):
        claude = self.put(".claude/settings.json", {"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(*)", "Bash(npm test)"]},
                                                    "disableAllHooks": True, "enableAllProjectMcpServers": True, "model": "opus"})
        before = claude.read_bytes()
        code, out = self.cli("posture", "--fix")
        self.assertEqual(code, 2)
        self.assertIn('would set permissions.defaultMode to "default"', out)
        self.assertIn("Nothing changed yet. Run `verfy posture --fix --write` to make these 4 edits", out)
        self.assertEqual(claude.read_bytes(), before)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read(".claude/settings.json"), {"permissions": {"defaultMode": "default", "allow": ["Bash(npm test)"]}, "model": "opus"})
        self.assertEqual((self.home / (".claude/settings.json" + posture.BACKUP)).read_bytes(), before)
        self.assertIn("Left: no risky setting found.", out)
        self.assertEqual(self.cli("posture")[0], 0)

    def test_only_the_high_ones(self):
        self.put(".claude/settings.json", {"disableAllHooks": True, "enableAllProjectMcpServers": True})
        code, out = self.cli("posture", "--fix", "--min", "high", "--write")
        self.assertEqual(code, 1, out)  # the medium one is left
        self.assertEqual(self.read(".claude/settings.json"), {"enableAllProjectMcpServers": True})
        self.assertIn("Left: 1 medium", out)

    def test_gemini_cursor_copilot_devin(self):
        self.put(".gemini/settings.json", {"hooksConfig": {"enabled": False, "disabled": ["other", "verfy"]}, "general": {"defaultApprovalMode": "auto_edit"}})
        self.put(".cursor/hooks.json", {"version": 1, "hooks": {"beforeShellExecution": [{"command": "verfy hook cursor"}, {"command": "other"}]}})
        self.put(".copilot/settings.json", {"disableAllHooks": True, "askUser": True})
        self.put(".devin/config.json", {"permission_mode": "dangerous", "permissions": {"allow": ["exec", "Read(**)"]}}, self.cwd)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(self.read(".gemini/settings.json"), {"hooksConfig": {"disabled": ["other"]}, "general": {"defaultApprovalMode": "default"}})
        self.assertEqual(self.read(".cursor/hooks.json")["hooks"]["beforeShellExecution"], [{"command": "verfy hook cursor", "failClosed": True}, {"command": "other"}])
        self.assertEqual(self.read(".copilot/settings.json"), {"askUser": True})
        self.assertEqual(self.read(".devin/config.json", self.cwd), {"permission_mode": "normal", "permissions": {"allow": ["Read(**)"]}})

    def test_a_file_with_comments_is_edited_in_place(self):
        text = ('{\n    // keep me\n    "editor.fontSize": 14, /* and me */\n    "chat.tools.global.autoApprove": true,\n'
                '    "chat.permissions.default": "autopilot" // mode\n}\n')
        settings = self.put(".config/Code/User/settings.json", text)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 0, out)
        self.assertEqual(settings.read_text("utf-8"),
                         '{\n    // keep me\n    "editor.fontSize": 14, /* and me */\n    "chat.permissions.default": "default" // mode\n}\n')
        self.assertEqual(settings.with_suffix(".json" + posture.BACKUP).read_text("utf-8"), text)

    def test_jsonc_edits(self):
        cases = [
            ('{"a": 1, "b": true}', ("del", ("b",)), '{"a": 1}'),
            ('{"b": true, "a": 1}', ("del", ("b",)), '{"a": 1}'),
            ('{\n  "b": true\n}', ("del", ("b",)), '{\n}'),
            ('{\n  "a": [1, {"b": 2}],\n  "b": {"x": [1]},\n}', ("del", ("b",)), '{\n  "a": [1, {"b": 2}],\n}'),
            ('{"a": {"b": 1}, "b": "x"} // end', ("set", ("b",), "y"), '{"a": {"b": 1}, "b": "y"} // end'),
            ('{\r\n  "a": 1,\r\n  "b": true\r\n}\r\n', ("del", ("a",)), '{\r\n  "b": true\r\n}\r\n'),
        ]
        for text, edit, want in cases:
            self.assertEqual(posture._jsonc_edit(text, edit), want, (text, edit))
        with self.assertRaises(ValueError):
            posture._jsonc_edit('{"a": {"b": 1}}', ("del", ("b",)))  # not at the top level
        with self.assertRaises(ValueError):
            posture._jsonc_edit('{"p": {"allow": ["exec"]}}', ("drop", ("p", "allow"), ("exec",)))

    def test_a_nested_change_in_a_file_with_comments_is_left_for_the_person(self):
        text = '{\n  // devin\n  "permissions": {"allow": ["exec", "Read(**)"]}\n}\n'
        config = self.put(".devin/config.json", text, self.cwd)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 1, out)
        self.assertIn("by hand", out)
        self.assertEqual(config.read_text("utf-8"), text)

    def test_line_endings_are_kept(self):
        claude = self.home / ".claude" / "settings.json"
        claude.parent.mkdir(parents=True)
        claude.write_bytes(b'{\r\n  "enableAllProjectMcpServers": true,\r\n  "model": "opus"\r\n}\r\n')
        self.cli("posture", "--fix", "--write")
        self.assertEqual(claude.read_bytes(), b'{\r\n  "model": "opus"\r\n}\r\n')

    def test_the_files_indent_is_kept(self):
        settings = self.put(".config/Code/User/settings.json", '{\n    "editor.fontSize": 14,\n    "chat.tools.global.autoApprove": true\n}\n')
        self.cli("posture", "--fix", "--write")
        self.assertEqual(settings.read_text("utf-8"), '{\n    "editor.fontSize": 14\n}\n')

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs Python 3.11")
    def test_codex_toml_line_by_line(self):
        before = ('# mine\napproval_policy = "never"  # fast\nmodel = "o4"\n\n[profiles.fast]\n  sandbox_mode = "danger-full-access"\n  approval_policy = "never"\n\n'
                  '[features]\nhooks = false\nweb = true\n')
        config = self.put(".codex/config.toml", before)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 0, out)
        import tomllib
        after = config.read_text("utf-8")
        self.assertEqual(tomllib.loads(after), {"approval_policy": "on-request", "model": "o4",
                                                "profiles": {"fast": {"sandbox_mode": "workspace-write", "approval_policy": "on-request"}},
                                                "features": {"web": True}})
        self.assertIn("# mine", after)
        self.assertIn('  sandbox_mode = "workspace-write"', after)

    @unittest.skipIf(sys.version_info < (3, 11), "TOML needs Python 3.11")
    def test_codex_toml_written_another_way_is_left(self):
        before = 'features = { hooks = false }\n'
        config = self.put(".codex/config.toml", before)
        code, out = self.cli("posture", "--fix", "--write")
        self.assertEqual(code, 2, out)
        self.assertIn("by hand", out)
        self.assertEqual(config.read_text("utf-8"), before)

    def test_write_needs_fix_and_json_is_unchanged(self):
        self.put(".claude/settings.json", {"disableAllHooks": True})
        self.assertEqual(self.cli("posture", "--write")[0], 2)
        code, out = self.cli("posture", "--json")
        finding = json.loads(out)["findings"][0]
        self.assertNotIn("edit", finding)
        self.assertEqual(finding["change"], "remove disableAllHooks")


if __name__ == "__main__":
    unittest.main()
