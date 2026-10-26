"""Set the CLI version everywhere it appears: python scripts/bump.py 0.6.2

pyproject.toml decides what PyPI gets, __init__.py what `verfy --version` prints, plugin.json what Claude Code
shows, and the README's CI example pins this release. CHANGELOG.md needs a `## X.Y.Z (date)` section
written by hand; publish.yml refuses a tag without one. test_update.py fails when any of these disagree, and the
website's docs take the version from the CLI it vendors (npm run sync:cli in verfy-cloud).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FILES = [
    ("verfy-cli/pyproject.toml", r'(?m)^version = "[^"]+"$', 'version = "{v}"'),
    ("verfy-cli/src/verfy/__init__.py", r'__version__ = "[^"]+"', '__version__ = "{v}"'),
    ("plugins/verfy/.claude-plugin/plugin.json", r'"version": "[^"]+"', '"version": "{v}"'),
    ("verfy-cli/README.md", r"verfy==\d+\.\d+\.\d+", "verfy=={v}"),
]


def main(argv: list[str]) -> int:
    if len(argv) != 1 or not re.fullmatch(r"\d+\.\d+\.\d+", argv[0]):
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    v = argv[0]
    for rel, pattern, repl in FILES:
        p = REPO / rel
        text = p.read_text("utf-8")
        new, n = re.subn(pattern, repl.format(v=v), text)
        if new != text:
            p.write_bytes(new.encode("utf-8"))
        print(f"{rel}: {n} place(s)")
    if not re.search(rf"(?m)^## {re.escape(v)} ", (REPO / "CHANGELOG.md").read_text("utf-8")):
        print(f"CHANGELOG.md: add a `## {v} (YYYY-MM-DD)` section before tagging cli-v{v}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
