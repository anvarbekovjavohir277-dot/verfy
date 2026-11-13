"""The pre-commit hook `verfy-mcp-config` (https://pre-commit.com): a static check of the MCP configs in a commit.

It reads the files pre-commit passes and reports what `verfy scan --config` reports at medium or above: a package
with no pinned version, a download piped into a shell, plain http, a key written into the file, a privileged
container. It starts no server and makes no network call. Exit 1 when it finds something, so the commit stops.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import discover as cfgscan

SHOWN = ("critical", "high", "medium")


def main(argv: list[str] | None = None) -> int:
    files = sys.argv[1:] if argv is None else argv
    bad = 0
    for name in files:
        path = Path(name)
        if not path.is_file():
            continue
        found = cfgscan.read_configs([("given", path)], path.parent)
        for cfg in found:
            if cfg.get("error"):
                print(f"{name}: {cfg['error']}")
                bad += 1
        for s in cfgscan.scan_configs(found)["servers"]:
            for f in s["findings"]:
                if f["severity"] in SHOWN:
                    print(f"{name}: {s['server']}: {f['severity']} {f['rule']} {f['message']}")
                    bad += 1
    if bad:
        print(f"\nverfy: {bad} finding(s) in the MCP config. `verfy lock pin --write` writes exact versions; https://verfy.dev/check explains each rule.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
