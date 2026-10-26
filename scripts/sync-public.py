"""Copy the public parts of this private repository into verfy-releases, the public one.

The CLI's source stays here. verfy-releases carries what people need without it: the Claude Code plugin
marketplace, the security policy and its limits, the CLA, the changelog, the research report and its
scripts, the advisories (open data) and the CI example. Run it after changing any of them, then review
and commit verfy-releases.

    python scripts/sync-public.py [PATH]    # PATH defaults to ../verfy-releases
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
# path here -> path in verfy-releases
MIRROR = {
    ".claude-plugin/marketplace.json": ".claude-plugin/marketplace.json",
    "plugins/verfy": "plugins/verfy",
    "SECURITY.md": "SECURITY.md",
    "CLA.md": "CLA.md",
    "CHANGELOG.md": "CHANGELOG.md",
    "docs/SECURITY_LIMITATIONS.md": "docs/SECURITY_LIMITATIONS.md",
    "docs/research": "docs/research",
    "research": "research",
    "advisories": "advisories",
    "verfy-cli/examples/ci": "examples/ci",
}
SKIP_SUFFIXES = (".pyc", ".lck")


def wanted(src: Path) -> dict[str, Path]:
    """Files under ``src`` by their path relative to it ("" for a single file)."""
    if src.is_file():
        return {"": src}
    return {p.relative_to(src).as_posix(): p for p in sorted(src.rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and not p.name.endswith(SKIP_SUFFIXES)}


def main(argv: list[str]) -> int:
    dest = Path(argv[0]) if argv else ROOT.parent / "verfy-releases"
    if not (dest / ".git").exists():
        raise SystemExit(f"{dest} is not a checkout of verfy-releases")
    changed = 0
    for src_rel, dst_rel in MIRROR.items():
        src, dst = ROOT / src_rel, dest / dst_rel
        files = wanted(src)
        if src.is_dir() and dst.exists():
            for p in sorted(dst.rglob("*")):
                if p.is_file() and p.relative_to(dst).as_posix() not in files:
                    p.unlink()
                    changed += 1
                    print("removed", p.relative_to(dest).as_posix())
        for rel, p in files.items():
            t = dst / rel if rel else dst
            if not t.exists() or t.read_bytes() != p.read_bytes():
                t.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(p, t)
                changed += 1
                print("copied ", t.relative_to(dest).as_posix())
    print(f"{changed} file(s) changed in {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
