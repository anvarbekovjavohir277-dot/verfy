"""Locking a server's code: the package version its config starts and the registry's hash of that release.

No network: the registry answers come from a dict, through `verfy.packages.fetch_json`."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verfy import cli, packages  # noqa: E402
from verfy import lock as locks  # noqa: E402

NPM_A = "sha512-" + "A" * 86 + "=="
NPM_B = "sha512-" + "B" * 86 + "=="
TOOLS = [{"name": "read_file", "description": "Read a text file.", "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}}}]


class Registry:
    """A fake npm and PyPI: url -> JSON answer."""

    def __init__(self):
        self.answers = {
            "https://registry.npmjs.org/@acme%2Fserver/1.2.3": {"dist": {"integrity": NPM_A}},
            "https://registry.npmjs.org/@acme%2Fserver/1.3.0": {"dist": {"integrity": NPM_B}},
            "https://registry.npmjs.org/@acme%2Fserver/latest": {"version": "1.3.0"},
            "https://pypi.org/pypi/acme-mcp/2.0.0/json": {"urls": [{"filename": "acme_mcp-2.0.0-py3-none-any.whl", "digests": {"sha256": "ab" * 32}},
                                                                    {"filename": "acme_mcp-2.0.0.tar.gz", "digests": {"sha256": "cd" * 32}}]},
            "https://pypi.org/pypi/acme-mcp/json": {"info": {"version": "2.0.0"}},
        }
        self.seen: list[str] = []

    def __call__(self, url: str) -> dict:
        self.seen.append(url)
        if url not in self.answers:
            raise packages.PackageError(f"404 {url}")
        return self.answers[url]


class PackageCheckTests(unittest.TestCase):
    def setUp(self):
        self.reg = Registry()
        self._old = packages.fetch_json
        packages.fetch_json = self.reg

    def tearDown(self):
        packages.fetch_json = self._old

    def test_names_and_integrity(self):
        self.assertEqual(packages.package_name("@acme/server@1.2.3", "npm"), "@acme/server")
        self.assertEqual(packages.package_name("acme-mcp==2.0.0", "pypi"), "acme-mcp")
        self.assertEqual(packages.integrity("@acme/server@1.2.3", "npm"), NPM_A)
        p = packages.integrity("acme-mcp==2.0.0", "pypi")
        self.assertTrue(p.startswith("pypi-files-sha256:"))
        self.assertEqual(p, packages.integrity("acme-mcp==2.0.0", "pypi"))  # same files, same value
        with self.assertRaises(packages.PackageError):
            packages.integrity("@acme/server@latest", "npm")

    def test_first_lock_then_same_then_changed(self):
        new = packages.check(None, None, "@acme/server@1.2.3", "npm")
        self.assertEqual((new["status"], new["integrity"]), ("new", NPM_A))
        self.assertEqual(packages.check("@acme/server@1.2.3", NPM_A, "@acme/server@1.2.3", "npm")["status"], "ok")
        bumped = packages.check("@acme/server@1.2.3", NPM_A, "@acme/server@1.3.0", "npm")
        self.assertEqual(bumped["status"], "changed")  # a new version is new code, even with the same tools
        self.assertEqual(bumped["integrity"], NPM_B)  # so --update can record it

    def test_registry_serving_other_files_for_the_same_version_fails(self):
        self.reg.answers["https://registry.npmjs.org/@acme%2Fserver/1.2.3"] = {"dist": {"integrity": NPM_B}}
        r = packages.check("@acme/server@1.2.3", NPM_A, "@acme/server@1.2.3", "npm")
        self.assertEqual(r["status"], "changed")
        self.assertIn("different files", r["what"])

    def test_unpinned(self):
        self.assertEqual(packages.check(None, None, "@acme/server@latest", "npm")["status"], "unpinned")
        self.assertEqual(packages.check(None, None, "acme-mcp", "pypi")["status"], "unpinned")
        # it was locked to a version, and now the config dropped the version: that is a change, not a warning
        self.assertEqual(packages.check("@acme/server@1.2.3", NPM_A, "@acme/server", "npm")["status"], "changed")
        self.assertEqual(self.reg.seen, [])  # nothing to look up for an unpinned package

    def test_no_longer_a_package(self):
        self.assertEqual(packages.check("@acme/server@1.2.3", NPM_A, None, None)["status"], "changed")
        self.assertEqual(packages.check(None, None, None, None)["status"], "ok")

    def test_lock_rejects_integrity_without_package(self):
        lk = locks.empty_lock()
        lk["servers"]["x"] = {"tools": {}, "package_integrity": NPM_A}
        with self.assertRaises(locks.LockError):
            locks.validate_lock(lk)


def run(*argv: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = cli.main(list(argv))
        except SystemExit as e:
            code = e.code if isinstance(e.code, int) else 1
    return code or 0, out.getvalue(), err.getvalue()


class LockCheckPackageTests(unittest.TestCase):
    """`verfy lock check` with the server's start faked, so the package runner never runs."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.dir, ignore_errors=True))
        self.reg = Registry()
        self._old = (packages.fetch_json, cli._live_server, os.environ.get("VERFY_HOME"))
        packages.fetch_json = self.reg
        cli._live_server = lambda spec, timeout: {"tools": TOOLS, "server": {"name": "acme", "version": "1"}}
        os.environ["VERFY_HOME"] = str(self.dir / "home")

    def tearDown(self):
        packages.fetch_json, cli._live_server, home = self._old
        os.environ.pop("VERFY_HOME") if home is None else os.environ.__setitem__("VERFY_HOME", home)

    def config(self, pkg: str) -> Path:
        cfg = self.dir / ".mcp.json"
        cfg.write_text(json.dumps({"mcpServers": {"acme": {"command": "npx", "args": ["-y", pkg]}}}))
        return cfg

    def check(self, cfg: Path, *flags: str) -> tuple[int, str, str]:
        return run("lock", "check", "--config", str(cfg), "--lock", str(self.dir / "verfy.lock"), *flags)

    def test_version_change_with_the_same_tools_fails(self):
        cfg = self.config("@acme/server@1.2.3")
        self.assertEqual(self.check(cfg)[0], 1)  # nothing locked yet
        self.assertEqual(self.check(cfg, "--update", "--yes")[0], 0)
        entry = locks.load_lock(self.dir / "verfy.lock")["servers"]["acme"]
        self.assertEqual((entry["package"], entry["package_integrity"]), ("@acme/server@1.2.3", NPM_A))
        code, out, _ = self.check(cfg)
        self.assertEqual(code, 0, out)
        self.assertIn("1 server packages", out)

        cfg = self.config("@acme/server@1.3.0")  # same tools, new code
        code, out, _ = self.check(cfg, "--json")
        self.assertEqual(code, 2)
        self.assertEqual([r["status"] for r in json.loads(out)["packages"]], ["changed"])
        self.assertEqual(self.check(cfg, "--update", "--yes")[0], 0)  # reviewed and accepted
        entry = locks.load_lock(self.dir / "verfy.lock")["servers"]["acme"]
        self.assertEqual((entry["package"], entry["package_integrity"]), ("@acme/server@1.3.0", NPM_B))

    def test_unpinned_warns_and_fails_with_require_pinned(self):
        cfg = self.config("@acme/server@latest")
        self.check(cfg, "--update", "--yes")
        code, out, _ = self.check(cfg)
        self.assertEqual(code, 0)
        self.assertIn("unpinned", out)
        self.assertEqual(self.check(cfg, "--require-pinned")[0], 1)
        self.assertNotIn("package", locks.load_lock(self.dir / "verfy.lock")["servers"]["acme"])

    def test_sarif(self):
        cfg = self.config("@acme/server@1.2.3")
        self.check(cfg, "--update", "--yes")
        cfg = self.config("@acme/server@1.3.0")
        sarif = self.dir / "verfy.sarif"
        self.assertEqual(self.check(cfg, "--sarif", str(sarif))[0], 2)
        doc = json.loads(sarif.read_text())
        self.assertEqual(doc["version"], "2.1.0")
        self.assertEqual([r["ruleId"] for r in doc["runs"][0]["results"]], ["VERFY-LOCK-PACKAGE"])
        self.assertEqual(doc["runs"][0]["results"][0]["level"], "error")

    def test_pin(self):
        cfg = self.config("@acme/server@latest")
        code, out, _ = run("lock", "pin", "--config", str(cfg), "--lock", str(self.dir / "verfy.lock"))
        self.assertEqual(code, 0)
        self.assertIn("@acme/server@1.3.0", out)  # the registry's latest, since the lock has no version
        self.assertIn("@latest", json.loads(cfg.read_text())["mcpServers"]["acme"]["args"][1])  # not written without --write
        run("lock", "pin", "--config", str(cfg), "--lock", str(self.dir / "verfy.lock"), "--write")
        self.assertEqual(json.loads(cfg.read_text())["mcpServers"]["acme"]["args"], ["-y", "@acme/server@1.3.0"])
        self.assertTrue((self.dir / ".mcp.json.verfy-backup").exists())

    def test_pin_takes_the_locked_version(self):
        self.check(self.config("@acme/server@1.2.3"), "--update", "--yes")
        cfg = self.config("@acme/server")
        run("lock", "pin", "--config", str(cfg), "--lock", str(self.dir / "verfy.lock"), "--write")
        self.assertEqual(json.loads(cfg.read_text())["mcpServers"]["acme"]["args"], ["-y", "@acme/server@1.2.3"])


if __name__ == "__main__":
    unittest.main()
