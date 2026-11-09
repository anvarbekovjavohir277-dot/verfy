"""verfy doctor reports a missing or broken hook and changes nothing."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def doctor(home: Path, project: Path) -> subprocess.CompletedProcess:
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home), "VERFY_HOME": str(home / ".verfy"),
           "PYTHONPATH": str(ROOT / "src"), "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"}
    return subprocess.run([sys.executable, "-m", "verfy", "doctor"], cwd=project, env=env, capture_output=True, text=True, encoding="utf-8", timeout=60)


class DoctorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.project = Path(self.tmp.name) / "project"
        (self.home / ".claude").mkdir(parents=True)
        self.project.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self) -> Path:
        return self.home / ".claude" / "settings.json"

    def test_claude_code_without_the_hook_is_a_problem(self):
        r = doctor(self.home, self.project)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("no Verfy hook is set", r.stdout)
        self.assertFalse(self.settings().exists(), "doctor must not write settings")

    def test_installed_hook_is_ok(self):
        self.settings().write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "verfy hook pre-tool-use"}]}]}}), "utf-8")
        before = self.settings().read_bytes()
        r = doctor(self.home, self.project)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("hook on", r.stdout)
        self.assertEqual(self.settings().read_bytes(), before)

    def test_broken_settings_file_is_a_problem(self):
        self.settings().write_text("{ not json", "utf-8")
        r = doctor(self.home, self.project)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("unreadable", r.stdout)

    def test_counts_receipts_and_locked_tools(self):
        self.settings().write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "verfy hook pre-tool-use"}]}]}}), "utf-8")
        sys.path.insert(0, str(ROOT / "src"))
        from verfy import lock as locks
        lk = locks.empty_lock()
        for name in ("a", "b"):
            locks.pin(lk, "demo", {"name": name, "description": "Tool " + name, "inputSchema": {"type": "object"}}, by="user")
        locks.save_lock(self.project / "verfy.lock", lk)
        r = doctor(self.home, self.project)
        self.assertIn("2 tools locked", r.stdout, r.stdout + r.stderr)
        self.assertIn("Receipts      none", r.stdout)


if __name__ == "__main__":
    unittest.main()
