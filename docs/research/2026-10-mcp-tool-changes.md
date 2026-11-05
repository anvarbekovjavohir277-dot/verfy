# MCP tool definitions change between releases, often in patch releases

*Verfy research, run on 2026-10-24. Method and code: [`research/`](../../research). Anyone can re-run it.*

## Question

Verfy Lock is built on one assumption: the tool definitions an MCP server serves (name, description and input schema, which the model reads as instructions) change after you approved them. Is that true for real servers, or only for a demo?

## What we did

We took 46 popular MCP servers from npm and PyPI: the reference servers and well-known vendor and community servers. For each one we installed its newest releases, up to six, on a throwaway GitHub runner. We started each release the way an MCP client does (`npx` or `uvx`), asked it for `tools/list` and recorded every definition and its Verfy pin. The pin is the SHA-256 of the name, description and input schema. We then compared each release with the one before it.

Nothing was called: only `initialize` and `tools/list` were sent. Servers that wanted an API key got a placeholder.

## Results

| | |
|---|---|
| Servers that started and listed their tools | **34** of 46 |
| Servers where a tool was added, removed or changed within their last releases | **28 of 34** (82%) |
| Release-to-release updates that changed at least one tool definition | **61 of 128** (48%) |
| Patch releases (x.y.**z**) that changed at least one tool definition | **23 of 70** (33%) |
| Servers that changed the description of an existing tool | **15 of 34** |
| ... of which in a patch release | **7** |
| Tool descriptions changed in total | **119** |

- **A version range does not freeze what your agent reads.** `^1.2.3` and `~1.2.3` accept patch releases, and a third of patch releases changed a tool definition. (Three servers use date versions such as 2026.10.19; they are left out of the patch count.)
- **Remote servers do not even have a version.** They were not part of this run, but they can change their tools on any deploy.
- **We found no malicious change.** The changes we read were ordinary improvements and bug fixes. Many of them do add new instructions for the model. One server, for example, added a step where the user must agree to a cost before a project is created. These instructions are exactly what a rug pull would use, and today they reach agents without anyone reviewing them.

## Verfy's own mistakes, found by the same run

We also ran Verfy's scanner on the newest release of every server. With version 0.5.1 it reported **163 high or critical findings**, and they were **all false alarms**:

- A tool that mentioned another tool **on the same server** ("use `search` first, then `fetch`") was flagged as tool shadowing. That is normal documentation, not an attack. 154 findings came from this rule alone.
- "Do **not** include API keys or passwords in the query" was read as asking for API keys. The same happened with "include fields … to save **tokens**" and "pass a **conversation** URL". These were 5 critical findings, and the gateway would have hidden those tools: two from Context7, two from Apify and one from Sentry.
- "fails **silently**" was read as "do this secretly".

These are fixed in verfy 0.5.2:
- same-server mentions are no longer flagged;
- a match right after a negation is skipped;
- "tokens" and "conversation" only count in their sensitive senses;
- "silently" was dropped;
- merely mentioning a file such as `.env` is now medium, not high.

**Rescanned on 5 November 2026** with the scanner of verfy 0.13.0, on the same definitions: the newest release of the 34 servers that started, 532 tools. It reported **no high or critical findings** and one medium, a description that mentions a sensitive file. Two more words were dropped on the way, because `summary` and `metadata` are ordinary required fields in Jira and HubSpot tools. No server in this run was known to be malicious, so this measures false alarms, not how much the scanner catches.

On the same 34 servers the scanner now reports **0** high or critical findings. The real poisoning examples in `verfy-cli/examples/tools/` still get grade F. A new example file, `benign-real-world.json`, keeps these false alarms from coming back.

## Limits

- 12 servers are left out: 10 had no current stable release on their registry (every release deprecated, including the old reference servers such as `server-github`, or only pre-releases), one refused to start without a real API key, and one exited at start.
- A server can serve different definitions depending on configuration, account or time. We recorded one clean run per release.
- Six releases is a short window. Servers that release rarely had fewer comparisons.
- A changed description is not a vulnerability. This research measures how often the text your agent obeys changes, not how often it turns malicious.

## Re-run it

GitHub → Actions → "Research - MCP tool changes" → Run workflow, then `python research/report.py results/`. The raw results (including the full before-and-after text of every change) are kept as workflow artifacts, not in this repository.
