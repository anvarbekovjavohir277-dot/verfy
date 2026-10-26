"""Tests for `verfy update`, the update choice in `verfy init` and the opt-in daily check.
Run from verfy-cli/: ``python -m unittest discover -s tests``. No test goes online."""

from __future__ import annotations

import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from verfy import __version__, update  # noqa: E402
from verfy.cli import main as cli_main  # noqa: E402


def tmpdir(test: unittest.TestCase) -> Path:
    d = tempfile.TemporaryDirectory()
    test.addCleanup(d.cleanup)
    return Path(d.name)


def run_cli(home: Path, *args):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"VERFY_HOME": str(home)}), redirect_stdout(out), redirect_stderr(err):
        code = cli_main(list(args))
    return code, out.getvalue(), err.getvalue()


def offline(*_a, **_k):
    raise AssertionError("went online")


class VersionTests(unittest.TestCase):
    def test_package_version_matches_module(self):
        # pyproject.toml decides what PyPI gets; __version__ is what `verfy --version` prints
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertRegex(text, rf'(?m)^version = "{re.escape(__version__)}"$')

    def test_plugin_and_docs_carry_this_version(self):
        # scripts/bump.py X.Y.Z sets all of them; the README's CI example pins every release
        repo = ROOT.parent
        plugin = repo / "plugins" / "verfy" / ".claude-plugin" / "plugin.json"
        if not plugin.exists():
            self.skipTest("not a checkout of the verfy repository")
        self.assertEqual(json.loads(plugin.read_text(encoding="utf-8"))["version"], __version__)
        pins = re.findall(r"verfy==(\d+\.\d+\.\d+)", (ROOT / "README.md").read_text(encoding="utf-8"))
        self.assertTrue(pins)
        self.assertEqual(set(pins), {__version__}, "run python scripts/bump.py " + __version__)

    def test_newer(self):
        self.assertTrue(update.newer("0.3.0", "0.2.0"))
        self.assertTrue(update.newer("0.10.0", "0.9.9"))
        self.assertFalse(update.newer("0.2.0", "0.2.0"))
        self.assertFalse(update.newer("0.3.0rc1", "0.3.0"))
        self.assertTrue(update.newer("0.3.0", "0.3.0rc1"))

    def test_commands(self):
        self.assertIsNone(update.command("source"))
        cmd, env = update.command("pip")
        self.assertEqual(cmd[:4], [sys.executable, "-m", "pip", "install"])
        self.assertEqual(env["VERFY_NO_MODIFY_PATH"], "1")
        with mock.patch.object(sys, "executable", str(Path("/opt/verfy/0.2.0/verfy").resolve())):
            cmd, env = update.command("standalone")
        self.assertEqual(Path(env["VERFY_INSTALL_DIR"]), Path("/opt/verfy").resolve())
        self.assertIn(update.INSTALL_PS1 if os.name == "nt" else update.INSTALL_SH, " ".join(cmd))


class AutoCheckTests(unittest.TestCase):
    def test_manual_never_goes_online(self):
        home = tmpdir(self)
        update.save_settings(home, mode="manual")
        with mock.patch.object(update, "latest", offline), mock.patch.object(update, "start_in_background", offline):
            self.assertIsNone(update.maybe_auto(home, "0.2.0", now=10**9))
        self.assertIsNone(update.maybe_auto(tmpdir(self), "0.2.0"))  # no choice made yet counts as manual

    def test_auto_checks_once_a_day_and_starts_the_update(self):
        home = tmpdir(self)
        update.save_settings(home, mode="auto")
        started = []
        with mock.patch.object(update, "method", return_value="pip"), \
                mock.patch.object(update, "latest", return_value="9.0.0"), \
                mock.patch.object(update, "start_in_background", lambda how, log: started.append((how, log)) or True):
            line = update.maybe_auto(home, "0.2.0", now=1_000_000)
            self.assertIn("9.0.0", line)
            self.assertEqual(started, [("pip", home / "update.log")])
            self.assertIsNone(update.maybe_auto(home, "0.2.0", now=1_000_000 + 3600))  # checked an hour ago
        self.assertEqual(update.settings(home)["checked_at"], 1_000_000)

    def test_auto_stays_quiet_when_current_or_offline(self):
        home = tmpdir(self)
        update.save_settings(home, mode="auto")
        with mock.patch.object(update, "latest", return_value=__version__), mock.patch.object(update, "start_in_background", offline):
            self.assertIsNone(update.maybe_auto(home, __version__, now=10**9))
        update.save_settings(home, checked_at=0)
        with mock.patch.object(update, "latest", side_effect=update.UpdateError("no network")):
            self.assertIsNone(update.maybe_auto(home, __version__, now=10**9))

    def test_the_hook_never_runs_the_check(self):
        home = tmpdir(self)
        update.save_settings(home, mode="auto")
        with mock.patch.object(update, "maybe_auto", offline), mock.patch.object(sys.stderr, "isatty", return_value=True), \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}))):
            code, _, _ = run_cli(home, "hook", "pre-tool-use")
        self.assertEqual(code, 0)


class UpdateCommandTests(unittest.TestCase):
    def test_choose_auto_and_back(self):
        home = tmpdir(self)
        code, out, _ = run_cli(home, "update", "--auto", "on")
        self.assertEqual((code, update.settings(home)["mode"]), (0, "auto"))
        self.assertIn("Automatic updates on", out)
        run_cli(home, "update", "--auto", "off")
        self.assertEqual(update.settings(home)["mode"], "manual")

    def test_check_and_update(self):
        home = tmpdir(self)
        with mock.patch.object(update, "method", return_value="pip"), mock.patch.object(update, "latest", return_value=__version__):
            code, out, _ = run_cli(home, "update")
        self.assertEqual(code, 0)
        self.assertIn("newest version", out)
        ran = []
        with mock.patch.object(update, "method", return_value="pip"), mock.patch.object(update, "latest", return_value="9.0.0"), \
                mock.patch.object(update, "run", lambda how: ran.append(how) or 0):
            code, out, _ = run_cli(home, "update", "--check")
            self.assertEqual((code, ran), (1, []))
            code, out, _ = run_cli(home, "update")
        self.assertEqual((code, ran), (0, ["pip"]))
        self.assertIn("Updated to verfy 9.0.0", out)

    def test_failed_update_says_so(self):
        home = tmpdir(self)
        with mock.patch.object(update, "method", return_value="pip"), mock.patch.object(update, "latest", return_value="9.0.0"), \
                mock.patch.object(update, "run", return_value=1):
            code, _, err = run_cli(home, "update")
        self.assertEqual(code, 3)
        self.assertIn("still installed", err)
        with mock.patch.object(update, "latest", side_effect=update.UpdateError("could not reach pypi.org")):
            code, _, err = run_cli(home, "update")
        self.assertEqual(code, 3)

    def test_init_records_the_choice(self):
        home = tmpdir(self)
        code, out, _ = run_cli(home, "init", "--updates", "auto")
        self.assertEqual((code, update.settings(home)["mode"]), (0, "auto"))
        self.assertIn("Updates       auto", out)
        code, out, _ = run_cli(home, "init")  # not a terminal: keeps the earlier choice without asking
        self.assertEqual(update.settings(home)["mode"], "auto")
        home2 = tmpdir(self)
        run_cli(home2, "init")
        self.assertEqual(update.settings(home2)["mode"], "manual")
        with mock.patch("verfy.cli._interactive", return_value=True), mock.patch("builtins.input", return_value="2"):
            home3 = tmpdir(self)
            run_cli(home3, "init")
        self.assertEqual(update.settings(home3)["mode"], "auto")


if __name__ == "__main__":
    unittest.main()
