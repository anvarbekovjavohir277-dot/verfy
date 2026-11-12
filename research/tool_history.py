"""How often do MCP servers change their tool definitions between releases?

For one server from servers.json: take its newest N releases from npm or PyPI, start each one
the way an MCP client would (npx / uvx), ask for tools/list, and record every tool definition,
its Verfy pin (SHA-256 of name, description, input schema and, when the server sends them, title,
annotations and output schema) and the Verfy scanner's findings. Prompts are listed as `prompt:NAME`.

    python research/tool_history.py SERVER_ID --versions 6 --out results/SERVER_ID.json

This starts third-party packages. Run it only in a throwaway machine with no credentials (the
GitHub workflow research.yml does that); it never needs real API keys.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "verfy-cli" / "src"))

from verfy.mcp_client import MCPError, list_tools  # noqa: E402
from verfy import __version__  # noqa: E402
from verfy.scanner import PINNED_EXTRAS, scan, tool_pin  # noqa: E402

STABLE = re.compile(r"^\d+(\.\d+)*$")


def fetch_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def releases(eco: str, pkg: str, n: int) -> list[tuple[str, str]]:
    """The newest n stable releases as (version, published), oldest first."""
    if eco == "npm":
        meta = fetch_json("https://registry.npmjs.org/" + pkg.replace("/", "%2F"))
        times = meta.get("time", {})
        vs = [(v, times.get(v, "")) for v in meta.get("versions", {}) if STABLE.match(v) and not meta["versions"][v].get("deprecated")]
    else:
        meta = fetch_json(f"https://pypi.org/pypi/{pkg}/json")
        vs = []
        for v, files in meta.get("releases", {}).items():
            live = [f for f in files if not f.get("yanked")]
            if STABLE.match(v) and live:
                vs.append((v, min(f["upload_time_iso_8601"] for f in live)))
    vs.sort(key=lambda x: x[1])
    return vs[-n:]


def command(server: dict, version: str, tmp: str) -> list[str]:
    args = [a.replace("{tmp}", tmp) for a in server.get("args", [])]
    if server["eco"] == "npm":
        npx = shutil.which("npx") or "npx"
        if server.get("bin"):
            return [npx, "-y", "-p", f"{server['pkg']}@{version}", server["bin"], *args]
        return [npx, "-y", f"{server['pkg']}@{version}", *args]
    uvx = shutil.which("uvx") or "uvx"
    if server.get("bin"):
        return [uvx, "--from", f"{server['pkg']}=={version}", server["bin"], *args]
    return [uvx, f"{server['pkg']}@{version}", *args]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("server")
    ap.add_argument("--servers", default=str(HERE / "servers.json"))
    ap.add_argument("--versions", type=int, default=6)
    ap.add_argument("--timeout", type=float, default=180)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    server = next(s for s in json.loads(Path(a.servers).read_text("utf-8")) if s["id"] == a.server)
    out: dict = {"server": server, "collected_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 # what this run's pins cover: results of runs that pinned different fields are compared by text, not by pin
                 "collector": {"verfy": __version__, "pin": ["name", "description", "inputSchema", *PINNED_EXTRAS], "prompts": True},
                 "releases": []}
    try:
        rel = releases(server["eco"], server["pkg"], a.versions)
    except Exception as e:  # noqa: BLE001 - recorded, not fatal
        out["error"] = f"registry: {e}"
        rel = []
    for version, published in rel:
        tmp = tempfile.mkdtemp(prefix="mcp-")
        env = dict(os.environ, **server.get("env", {}))
        entry: dict = {"version": version, "published": published}
        started = time.time()
        try:
            res = list_tools(command(server, version, tmp), timeout=a.timeout, env=env)
            tools = res["tools"]
            report = scan(tools, server["id"])
            entry.update(status="ok", server_info=res.get("server"), tools=[
                {"name": t.get("name"), "pin": tool_pin(t), "description": t.get("description", ""), "inputSchema": t.get("inputSchema"),
                 **{k: t[k] for k in ("title", "annotations") if k in t}}
                for t in tools if isinstance(t, dict)
            ], scan={"grade": report["grade"], "score": report["score"],
                     "findings": [{"tool": r["name"], **f} for r in report["tools"] for f in r["findings"]]})
        except (MCPError, OSError) as e:
            entry.update(status="error", error=str(e)[:300])
        entry["seconds"] = round(time.time() - started, 1)
        shutil.rmtree(tmp, ignore_errors=True)
        out["releases"].append(entry)
        print(f"{server['id']} {version}: {entry['status']} ({len(entry.get('tools', []))} tools, {entry['seconds']} s)", flush=True)
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", "utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
