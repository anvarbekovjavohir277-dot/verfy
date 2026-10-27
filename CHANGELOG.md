# Changelog

What changed in the Verfy CLI (`pip install verfy`) and the website. Newest first. Every CLI version is on [PyPI](https://pypi.org/project/verfy/#history) and as standalone builds on the [releases page](https://github.com/anvarbekovjavohir277-dot/verfy-releases/releases).

## 0.6.3 (2026-10-26)

- **Security: the agent can no longer read Verfy's signing key or device token.** Up to 0.6.2 an agent could read `~/.verfy/key.json` (for example with `cat` or Claude Code's Read tool), and with it sign receipts of its own, or read the device token in `~/.verfy/team.json`. Now reading either file, listing, searching or copying `~/.verfy`, or naming the folder and one of those files in one command is denied (VFY-SELF-006), including `$HOME`, `%USERPROFILE%`, quoted, globbed and `cd`-then-read forms; archiving, copying or searching a folder that holds it, such as the home folder, or looking for files with those names needs approval (VFY-SELF-007). Both engines (Python and JavaScript) share the 26 new test cases. A program the agent writes and runs can still read the file: see [SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md). If an agent may have read your key, create a new one yourself with `verfy init --force` (it starts a new receipt chain) and, with Verfy Cloud, revoke the device and enroll it again. Found while reviewing a contribution.
- The end-to-end test also checks that the hook denies reading the signing key with `cat` and with the Read tool.
- Website (27 October): Verfy Advisories have `VERFY-YYYY-NNNN` ids. The old ids (such as ATLS-2025-0001) stay in `aliases`, and links to them lead to the new pages.
- **[verfy-releases](https://github.com/anvarbekovjavohir277-dot/verfy-releases) is the home for installing Verfy**: the standalone builds, the Claude Code plugin (`claude plugin marketplace add anvarbekovjavohir277-dot/verfy-releases`, then `claude plugin install verfy@verfy`), the security policy (report vulnerabilities and bypasses there), the advisories, the research and this changelog. The source stays here, under the MIT license. The GitHub Action is replaced by two steps, `pip install "verfy==0.6.3"` and `verfy lock check`, with the same annotations and step summary.

## 0.6.2 (2026-10-26)

- **Verfy Registry sends only pins.** `verfy team registry report` now sends only the SHA-256 pin of each locked tool definition, no longer the local server and tool names, which can be private. Verfy Cloud stores only the pins and when each was reported, and no longer has a place for names. Owners and admins can delete all of their team's pins in Dashboard → Locks, and a pin not reported for 180 days stops counting and is deleted. What is sent and what is not: https://verfy-tech.vercel.app/docs#registry
- **End-to-end test before every release.** The built wheel is installed on clean Linux, macOS and Windows runners and `scripts/e2e.py` runs `verfy init`, `lock files`, `lock check` (a changed CLAUDE.md and a rug pull must fail it), Snyk and Cisco imports, the Claude Code hook and the Claude Code plugin. Nothing goes to PyPI unless it passes; it also runs on every push.
- The GitHub Action example in the README pins this release (`@cli-v0.6.2`). `python scripts/bump.py X.Y.Z` sets the version in every file that carries it, and a test fails when one of them falls behind.

## 0.6.1 (2026-10-26)

- **Verfy Registry** (Verfy Cloud): `verfy team registry report` shares the pins in your `verfy.lock` (server name, tool name and SHA-256; never definitions), and `verfy team registry lookup` shows how many teams reported each pin, including a changed definition you have not approved yet. A change that few other teams have seen can be very new, or served only to you. Counts are shown only when at least 3 organizations reported a pin.
- Verfy Cloud (website): Dashboard → Reports, a compliance summary for a date range (checked calls by verdict, the rules behind denied and asked calls, lock and approval decisions, policy versions, devices, audit activity) with the SOC 2 and ISO/IEC 42001 controls it relates to. It points an auditor to the evidence; it does not certify anything.

## 0.6.0 (2026-10-26)

- **Lock explains what changed.** `verfy lock check`, `lock diff`, `lock approve` and `lock check --update` now say in words what changed in a tool and how risky it looks (low, medium or high): a new sentence that orders the model to send data somewhere, a new link, a new or newly required parameter, a new hidden-instruction pattern, or only a rewording. The GitHub annotations and step summary carry the same explanation. It is deterministic; no model is involved. On the 342 real tool changes from our October research it rated none high.
- **Lock the files an agent loads, not only MCP tools.** `verfy lock files` pins CLAUDE.md, AGENTS.md, GEMINI.md, Cursor and Windsurf rules, `.claude` skills, agents, commands and hook settings, and MCP configs in the `files` section of `verfy.lock`; `verfy lock check` then fails CI when one changes without a reviewed lock update. `verfy lock files --user` does the same for user-level instructions, skills and installed Claude Code plugins on your machine (`~/.verfy/agent-files.lock`).
- **Claude Code plugin.** This repository is now a plugin marketplace: `claude plugin marketplace add anvarbekovjavohir277-dot/verfy` and `claude plugin install verfy@verfy` install the guard hook and a skill for checking locks. It needs the CLI (`pip install verfy`).
- **More agents.** `verfy scan --discover` also reads Codex CLI (`~/.codex/config.toml`, Python 3.11+), Gemini CLI (`.gemini/settings.json`), VS Code (`.vscode/mcp.json` and the user `mcp.json`) and Windsurf (`~/.codeium/windsurf/mcp_config.json`).
- **Import other scanners' findings.** `verfy import FILE` reads Snyk Agent Scan (`--json`) and Cisco MCP Scanner (`--format raw`) output. With `--save`, the Verfy gateway hides the tools they rate high and denies calls to them (VFY-IMP-001).
- Self-protection: an agent may not run `verfy lock files --update` or `verfy import --save`, or edit `~/.verfy/agent-files.lock`, `~/.verfy/imported/` or the installed Verfy plugin.

## 0.5.5 (2026-10-25)

- The hosted service has one name, Verfy Cloud: `verfy team` and `verfy sync` say so in their help. The commands are unchanged.
- This repository is now the MIT CLI only; the website and the dashboard are developed separately as Verfy Cloud. The CLI is MIT and will stay MIT.
- Verfy Advisories are open data in [`advisories/`](https://github.com/anvarbekovjavohir277-dot/verfy-releases/tree/main/advisories): anyone can add a public, sourced advisory by pull request, checked by `node advisories/validate.mjs`.
- Contributors sign the [CLA](https://github.com/anvarbekovjavohir277-dot/verfy-releases/blob/main/CLA.md) once, by commenting on their first pull request.
- There is no 0.5.4: that tag was never published, because the package metadata still said 0.5.3 and PyPI refused it. A test and the release workflow now check that both version numbers match.

## 0.5.3 (2026-10-24)

- One tag now does the whole release in one workflow: tests, PyPI with attestations, then the GitHub release from this changelog with the same files, SHA256SUMS and Sigstore signatures. Only the newest version is marked "Latest".
- PyPI page links: Repository, Changelog and Releases.
- Verfy Cloud (website): Slack and Telegram notifications for calls that wait for approval, changed tool definitions, denied calls and devices that stop uploading receipts for a day (Dashboard → Notifications).

## 0.5.2 (2026-10-24)

Scanner fixes, found by scanning the newest releases of 34 popular MCP servers ([the research](https://github.com/anvarbekovjavohir277-dot/verfy-releases/blob/main/docs/research/2026-10-mcp-tool-changes.md)). Version 0.5.1 raised 163 high or critical findings there, all false alarms; 0.5.2 raises none.

- A tool that mentions another tool on the same server is no longer flagged as tool shadowing.
- A match right after a negation ("Do not include API keys") is skipped. Before, this hid tools from Context7, Apify and Sentry behind the gateway.
- "tokens" and "conversation" only count in their sensitive senses (access tokens, the conversation history).
- "silently" no longer counts as "secretly"; mentioning a file such as `.env` is medium instead of high.

## 0.5.1 (2026-10-24)

Fixes found while scanning public `.mcp.json` files and recording the demo video.

- `verfy lock check` and the gateway no longer crash with a traceback when a server's command cannot be started (for example an empty command). They report it and exit 3 (lock check) or 126 (gateway).
- Config scan: an unpinned package launched through `cmd /c` or `sh -c` is now reported.
- Config scan: `npx` of a package declared in the `package.json` next to the config is no longer reported, because the lockfile pins it.
- Config scan: VFY-CFG-007 (a remote server without credentials in the config) is now `info`. The client signs in with OAuth when the server asks, so a missing header is not a weakness.

## 0.5.0 (2026-10-24)

- Approval queue for teams. With `"on_ask": "team"`, a gateway call that needs approval waits in Dashboard → Approvals until an owner or admin decides, for up to `approval_timeout` seconds. Only the SHA-256 of the arguments leaves the machine.

## 0.4.0 (2026-10-24)

- The gateway replaces API keys, tokens and private keys in MCP tool results with `[REDACTED:<rule>]` before the agent reads them. Turn it off with `"redact_output": false`.
- Policy templates: `verfy policy use strict | read-only | ci`, and `verfy init --template`.
- Fixed: redaction of stored arguments hid only the first secret of each kind.
- Website: Next.js 16.4.3, which fixes two critical advisories.

## 0.3.0 (2026-10-22)

- Self-protection: the agent cannot switch Verfy off with its own tools (VFY-SELF-001 to 005).
- `verfy update`, and a choice between manual and automatic updates at `verfy init`.
- Windows paths are compared without regard to case, in the `/c/...` form.
- One-line installers that need no Python (standalone builds for Windows, macOS and Linux, checked against SHA256SUMS).

## 0.2.0 (2026-10-21)

- First release on PyPI as `verfy`: the Claude Code hook, the MCP gateway, `verfy scan`, `verfy lock` (including `lock check` and the GitHub Action for CI), signed receipts and SCITT export.

## Before PyPI (2026-10-14 to 2026-10-20)

- 2026-10-18: the website leads with Verfy Lock, with a rug-pull demo you can run in the browser.
- 2026-10-15: the project got its name, Verfy; Google and GitHub sign-in.
- 2026-10-14: first version of the guard, scanner, lock, signed receipts and the Team web app.
