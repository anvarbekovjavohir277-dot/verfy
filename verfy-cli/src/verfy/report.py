"""``verfy report``: one HTML page about this computer: which agents Verfy guards, risky agent settings, how MCP
servers are started, what is locked, and what the signed receipts say.

The page is a single file with no script and no outside resource, so it can be opened offline, attached to a ticket
or printed. Everything put into it is escaped. It holds no secret: receipts store hashes of arguments, and a key in
a config is named by its kind, never by its value.
"""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timedelta, timezone

E = html.escape
SEVERITIES = ("critical", "high", "medium", "low", "info")

CSS = """
:root{--bg:#fff;--fg:#0b0e17;--muted:#667085;--line:#e4e7ec;--card:#f8f9fc;--ok:#067647;--warn:#b54708;--bad:#d92d20;--accent:#2347f0}
@media (prefers-color-scheme:dark){:root{--bg:#07090f;--fg:#f5f6f9;--muted:#8d96a8;--line:#232a3a;--card:#0f131c;--ok:#4ade80;--warn:#fbbf24;--bad:#ff8a7a;--accent:#8aa3ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}h2{font-size:19px;margin:36px 0 10px}
p{margin:6px 0}.muted{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:12px 14px}.card b{display:block;font-size:24px;line-height:1.2}
.card span{color:var(--muted);font-size:13px}.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tr:last-child td{border-bottom:0}th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
code,.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:13px}
.tag{display:inline-block;border-radius:999px;padding:1px 9px;font-size:12px;font-weight:600;border:1px solid currentColor;white-space:nowrap}
.ok,.allow,.low,.info{color:var(--ok)}.warn,.ask,.medium{color:var(--warn)}.bad,.deny,.high,.critical{color:var(--bad)}
.bar{display:flex;align-items:flex-end;gap:3px;height:70px;margin:10px 0 2px}.bar i{flex:1;background:var(--accent);border-radius:3px 3px 0 0;min-height:2px}
footer{margin-top:40px;color:var(--muted);font-size:13px}@media print{body{background:#fff;color:#000}}
"""


def _tag(text: str, kind: str) -> str:
    return f'<span class="tag {E(kind)}">{E(text)}</span>'


def _table(head: list[str], rows: list[list[str]], empty: str) -> str:
    if not rows:
        return f'<p class="muted">{E(empty)}</p>'
    body = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in r) + "</tr>" for r in rows)
    return '<div class="wrap"><table><thead><tr>' + "".join(f"<th>{E(h)}</th>" for h in head) + f"</tr></thead><tbody>{body}</tbody></table></div>"


def receipt_stats(receipts: list[dict], now: datetime | None = None, days: int = 14) -> dict:
    """Counts for the report from a ledger's receipts."""
    now = now or datetime.now(timezone.utc)
    verdicts: Counter = Counter()
    rules: Counter = Counter()
    agents: Counter = Counter()
    per_day: Counter = Counter()
    for r in receipts:
        if not isinstance(r, dict):
            continue
        d = r.get("decision") or {}
        verdicts[str(d.get("verdict", "?"))] += 1
        for rule in d.get("rules") or []:
            rules[str(rule)] += 1
        agents[str(r.get("agent") or "?")] += 1
        per_day[str(r.get("issued_at", ""))[:10]] += 1
    daily = [((now - timedelta(days=i)).strftime("%Y-%m-%d")) for i in range(days - 1, -1, -1)]
    return {"total": sum(verdicts.values()), "verdicts": dict(verdicts), "rules": rules.most_common(12), "agents": agents.most_common(),
            "daily": [(d, per_day.get(d, 0)) for d in daily],
            "first": next((str(r.get("issued_at", "")) for r in receipts if isinstance(r, dict)), ""),
            "last": next((str(r.get("issued_at", "")) for r in reversed(receipts) if isinstance(r, dict)), "")}


def build(data: dict) -> str:
    """The report as one HTML document. `data` is what `verfy report --json` prints."""
    st = data["receipts"]
    v = st["verdicts"]
    chain = data.get("chain") or {}
    posture = data["posture"]
    high = sum(1 for f in posture if f["severity"] == "high")
    unguarded = [a for a in data["agents"] if a["state"] == "off"]
    parts = [f"<h1>Verfy report</h1><p class=\"muted\">verfy {E(data['version'])} · made {E(data['made'])} · this computer only; nothing was sent anywhere</p>"]

    cards = [
        (str(len([a for a in data["agents"] if a["state"] == "on"])) + " of " + str(len(data["agents"])), "agents guarded"),
        (str(st["total"]), "signed receipts"),
        (str(v.get("deny", 0)), "calls blocked"),
        (str(v.get("ask", 0)), "calls sent to you"),
        (str(high), "high-risk settings"),
        (str(data["lock"]["tools"]) if data["lock"].get("found") else "none", "tools locked"),
    ]
    parts.append('<div class="cards">' + "".join(f'<div class="card"><b>{E(a)}</b><span>{E(b)}</span></div>' for a, b in cards) + "</div>")

    parts.append("<h2>Agents</h2>")
    parts.append(_table(["Agent", "Verfy hook", "File"], [
        [E(a["label"]), _tag("on" if a["state"] == "on" else ("machine-wide" if a["state"] == "system" else a["state"]), "ok" if a["state"] in ("on", "system") else "bad"),
         f'<span class="mono">{E(a["path"])}</span>'] for a in data["agents"]], "No coding agent was found on this computer."))
    if unguarded:
        parts.append(f'<p>{_tag("not guarded", "bad")} {E(", ".join(a["label"] for a in unguarded))}: run <code>verfy setup --write</code>.</p>')

    parts.append("<h2>Risky agent settings</h2>")
    parts.append(_table(["Level", "Agent", "Setting", "Why it matters", "Fix"], [
        [_tag(f["severity"], f["severity"]), E(f["agent"]), f'<span class="mono">{E(f["setting"])}</span>', E(f["why"]), E(f["fix"])] for f in posture],
        "No risky setting was found in the agents' own configs."))
    if any(f.get("fixable") for f in posture):
        parts.append('<p class="muted"><code>verfy posture --fix</code> shows the edits that take these away.</p>')

    parts.append("<h2>How MCP servers are started</h2>")
    rows = []
    for s in data["servers"]:
        notes = "<br>".join(f'{_tag(f["severity"], f["severity"])} <span class="mono">{E(f["rule"])}</span> {E(f["message"])}' for f in s["findings"]) or _tag("nothing found", "ok")
        rows.append([f'<span class="mono">{E(s["server"])}</span>', E(s["transport"]), f'<span class="mono">{E(s["config"])}</span>', notes])
    parts.append(_table(["Server", "Kind", "Config", "Findings"], rows, "No MCP server was found in the agents' configs."))
    parts.append('<p class="muted">A static check of the configs; no server was started. <code>verfy scan --discover --live</code> also reads each server\'s tools.</p>')

    parts.append("<h2>Lock</h2>")
    lock = data["lock"]
    parts.append(f'<p>{E(str(lock["tools"]))} tools of {E(str(lock["servers"]))} servers are locked in <span class="mono">{E(lock["path"])}</span>.</p>' if lock.get("found")
                 else '<p class="muted">No verfy.lock in this folder. <code>verfy lock check --update</code> pins the tools your MCP servers serve today.</p>')

    parts.append("<h2>Receipts</h2>")
    if st["total"]:
        ok = chain.get("verified")
        parts.append(f'<p>{E(str(st["total"]))} receipts from {E(st["first"][:10])} to {E(st["last"][:10])}. '
                     + (f'{_tag("chain verified", "ok")} every signature and link checks out.' if ok
                        else (f'{_tag("chain broken", "bad")} {E(str(chain.get("problems", "?")))} problem(s): run <code>verfy verify</code>.' if ok is False
                              else f'{_tag("not verified", "warn")} the public key could not be read.')) + "</p>")
        top = max((n for _d, n in st["daily"]), default=0) or 1
        parts.append('<div class="bar" role="img" aria-label="Receipts per day, last 14 days">'
                     + "".join(f'<i style="height:{max(2, round(100 * n / top))}%" title="{E(d)}: {n}"></i>' for d, n in st["daily"]) + "</div>"
                     + f'<p class="muted">Receipts per day, {E(st["daily"][0][0])} to {E(st["daily"][-1][0])}</p>')
        parts.append(_table(["Verdict", "Receipts"], [[_tag(k, k if k in ("allow", "ask", "deny") else "info"), E(str(n))] for k, n in sorted(v.items(), key=lambda x: -x[1])], ""))
        parts.append("<h2>Rules that fired most</h2>")
        parts.append(_table(["Rule", "Times"], [[f'<span class="mono">{E(r)}</span>', E(str(n))] for r, n in st["rules"]], "No rule fired: every checked call was allowed."))
        parts.append("<h2>By agent</h2>")
        parts.append(_table(["Agent", "Receipts"], [[E(a), E(str(n))] for a, n in st["agents"]], ""))
        parts.append("<h2>Latest receipts</h2>")
        parts.append(_table(["#", "Time (UTC)", "Verdict", "Outcome", "Tool", "Rules"], [
            [E(str(r["seq"])), E(str(r["at"])[:19].replace("T", " ")), _tag(str(r["verdict"]), str(r["verdict"]) if r["verdict"] in ("allow", "ask", "deny") else "info"),
             E(str(r["status"] or "")), f'<span class="mono">{E(r["tool"])}</span>', f'<span class="mono">{E(", ".join(r["rules"]))}</span>'] for r in data["latest"]], ""))
        parts.append('<p class="muted">A receipt stores a hash of the arguments, not the arguments.</p>')
    else:
        parts.append('<p class="muted">No receipts yet: none are written until Verfy\'s hook or gateway has checked a call.</p>')

    parts.append('<footer>Made by <code>verfy report</code>. The rules are fixed patterns; no model decides allow or deny. '
                 "A receipt shows what Verfy checked on this computer, not that the work was safe.</footer>")
    return ("<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            f"<title>Verfy report, {E(data['made'][:10])}</title><style>{CSS}</style></head><body><main>" + "\n".join(parts) + "</main></body></html>\n")
