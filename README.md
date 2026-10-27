# Verfy

[![CI](https://github.com/anvarbekovjavohir277-dot/verfy/actions/workflows/ci.yml/badge.svg)](https://github.com/anvarbekovjavohir277-dot/verfy/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/verfy)](https://pypi.org/project/verfy/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

<img src="docs/assets/verfy-lock-demo.gif" width="494" alt="Verfy lock demo: the approved read_file tool is allowed; after the server quietly adds an instruction to its description, the same call is denied with VFY-TOOL-004.">

*The server changes the tool's description after you approved it. Verfy notices the new SHA-256 and blocks the call. Try it on [the website](https://verfy-tech.vercel.app/).*

▶ [The 60-second version](docs/assets/verfy-rug-pull.mp4) (MP4, 0.9 MB): pin the tools, the server ships an update, `verfy lock check` fails, the gateway hides the tool and denies the call. Recorded with verfy 0.5.0: every terminal line is real output of its demo server (`python -m verfy.demo_server --rugpull`).

**For teams using Claude Code and Cursor: if a tool your agent uses changes in secret, Verfy stops it and signs a receipt for every call it checks.**

**The Verfy CLI is MIT and always will be. Verfy Cloud is a paid hosted service** (in beta, not on sale yet). This repository is the CLI; the hosted service is developed separately.

Verfy checks every tool call a coding agent makes against your policy before it runs, locks the MCP tool definitions the agent may use, and writes an Ed25519-signed, hash-chained receipt for every call it checks. Verfy Cloud, the hosted service, gives an organization one policy, tool-change approvals, device management, an audit log and evidence exports that anyone can verify offline.

| Part | What it does |
| --- | --- |
| **Verfy Lock** | `verfy.lock` pins the SHA-256 of every tool definition, and of the files an agent loads (CLAUDE.md, AGENTS.md, rules, skills, hook settings); a changed tool is hidden and denied until someone reviews the diff, and `verfy lock check` (or the GitHub Action in `action.yml`) fails CI. Each change is explained in words with a risk level. |
| **Verfy Receipts** | `verfy.receipt/1`: signed, chained, hash-only by default; `verfy verify` detects edits, deletions and reordering; `verfy scitt export` writes SCITT signed statements (COSE_Sign1). |
| **Verfy Guard** | Deterministic `allow` / `ask` / `deny` for shell commands, file paths, URLs, SQL, payments and leaked secrets, through a Claude Code `PreToolUse` hook or an MCP gateway. Errors never become allow. |
| **Verfy Scan** | Finds MCP servers in Claude Code, Cursor, Claude Desktop, Codex CLI, Gemini CLI, VS Code and Windsurf configs; flags tool poisoning, hidden instructions, shadowing, invisible Unicode, unpinned packages, plain-http servers and secrets in configs. `verfy import` reads Snyk Agent Scan and Cisco MCP Scanner findings so the gateway can enforce them. |
| **Verfy Cloud** | Hosted by Verfy: one team policy, device enrollment, server-verified receipts, lock and call approvals, Slack and Telegram alerts, audit log, evidence exports. Devices connect with `verfy team enroll`. |

## Verfy and scanners

Scanners judge a tool when you scan it. Verfy is built for what happens after: the tool changes, the agent calls it, and someone later asks what ran. Use both. From each project's own documentation, checked 2026-10-24 ([full table and sources](https://verfy-tech.vercel.app/compare)):

| | [Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly Invariant mcp-scan) | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) | [mcp-context-protector](https://github.com/trailofbits/mcp-context-protector) (Trail of Bits) | Verfy |
| --- | --- | --- | --- | --- |
| How tools are judged | Local checks + Snyk API | YARA locally; optional LLM / AI Defense API | Pinning; optional guardrail model | Deterministic local rules |
| Account needed | Snyk account | No (YARA) | No | No |
| Notices a tool changed after approval | Not described | Not described | Yes (trust-on-first-use pinning) | Yes (`verfy.lock`) |
| Fails the pull request when a tool changed | Not described | Not described | Not described | Yes (GitHub Action) |
| Checks calls as they happen | Agent Guard hooks, answers from the Snyk API | No | Blocks unapproved servers; response guardrails | Claude Code hook (all tools) + MCP gateway |
| Signed record of each call | Not described | No | Not described | Ed25519, hash-chained, SCITT export |

They also do things Verfy does not: Snyk scans agent skills, Cisco reads server source code and scans packages and binaries, and context-protector can run a guardrail model over tool responses.

## Quick start: the CLI

```bash
pip install verfy                # Python ≥ 3.10, no dependencies (no Python? see "Without Python" below)
verfy init                       # signing key + starter policy in ~/.verfy
verfy scan --discover            # check the MCP servers your agents can reach
verfy lock check --update        # lock the tools in .mcp.json into ./verfy.lock (commit it)
verfy hook install --write       # guard every Claude Code tool call (or install the plugin, below)
verfy lock files --update        # lock CLAUDE.md, AGENTS.md, rules, skills and hook settings too
verfy check "rm -rf ~"           # exit 2: deny (VFY-SH-001)
verfy demo                       # a poisoned MCP server behind the gateway
verfy verify                     # every signature and link in your ledger
```

Without Python, an install script downloads a standalone build. Download it, read it, then run it (there is no `curl … | sh` one-liner on purpose: Verfy itself asks about that pattern, rule VFY-SH-005):

```bash
curl -fsSLO https://verfy-tech.vercel.app/install.sh && less install.sh && sh install.sh      # macOS, Linux
```
```powershell
powershell -c "irm https://verfy-tech.vercel.app/install.ps1 -OutFile install.ps1"           # Windows: download,
notepad install.ps1                                                                           # read,
powershell -ExecutionPolicy Bypass -File install.ps1                                         # run
```

### As a Claude Code plugin

```bash
claude plugin marketplace add anvarbekovjavohir277-dot/verfy-releases
claude plugin install verfy@verfy
```

The plugin installs the same hook for every session, plus a skill that lets Claude check your locks for you (approving changes stays with you). It calls the `verfy` command, so install the CLI first. Details: [`plugins/verfy/README.md`](plugins/verfy/README.md).

More: [`verfy-cli/README.md`](verfy-cli/README.md) and the docs at https://verfy-tech.vercel.app/docs.

## Repository layout

```
verfy-cli/           the Python CLI (guard, scan, lock, receipts, hook, gateway, team client) and its tests
verfy-cli/js/        the JavaScript twin of the rule engine, checked against the same fixtures
action.yml           the GitHub Action that runs `verfy lock check` in CI
plugins/verfy/       the Claude Code plugin (hook + skill); .claude-plugin/marketplace.json lists it
advisories/          Verfy Advisories: public, sourced vulnerabilities in MCP servers and agent tools (OSV), added by pull request
install/             the one-line installers served at verfy-tech.vercel.app/install.sh and /install.ps1
research/            how often MCP tool definitions change between releases (method, code, workflow)
docs/                limitations, research write-ups, assets
```

## Tests

```bash
cd verfy-cli && python -m unittest discover -s tests     # Python tests, incl. cross-engine checks (needs Node)
node verfy-cli/tests/test_engine.mjs                     # the JavaScript engine against the shared fixtures
```

## Limits

Verfy is not a sandbox: its rules are deterministic pattern matching, and it only sees calls that pass through its hook or gateway. A receipt proves what Verfy decided and that the record was not changed afterwards, not what a tool did internally. No independent penetration test has been done yet. Full list: [`docs/SECURITY_LIMITATIONS.md`](docs/SECURITY_LIMITATIONS.md).

## Contributing, security, trademarks

- Contributions are welcome: see [`CONTRIBUTING.md`](CONTRIBUTING.md). You sign the [CLA](CLA.md) once, by commenting on your first pull request.
- Found a way past Verfy? That is a vulnerability: report it privately as described in [`SECURITY.md`](SECURITY.md).
- "Verfy" and the logo are trademarks: forks need another name. See [`TRADEMARKS.md`](TRADEMARKS.md).

## License

The code in this repository is MIT licensed (see [`LICENSE`](LICENSE)), and the CLI will stay MIT. Earlier versions of this repository also contained the web platform that is now Verfy Cloud; those versions remain available under MIT in the history. New work on the hosted service is not open source.
