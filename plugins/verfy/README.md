# Verfy plugin for Claude Code

Installs Verfy's PreToolUse hook for every Claude Code session, plus a skill that tells Claude how to check locked MCP tools and instruction files with the `verfy` CLI.

## Install

The plugin calls the `verfy` command, so install the CLI first:

```bash
pip install verfy
verfy init
```

Then add this repository as a plugin marketplace and install the plugin:

```bash
claude plugin marketplace add anvarbekovjavohir277-dot/verfy-releases
claude plugin install verfy@verfy
```

Inside a session, `/plugin marketplace add anvarbekovjavohir277-dot/verfy-releases` and `/plugin install verfy@verfy` do the same.

An organization can require the marketplace and the plugin on every machine through managed settings (`extraKnownMarketplaces` and `enabledPlugins`); see https://code.claude.com/docs/en/plugins/org.

## What it does

- **Hook:** runs `verfy hook pre-tool-use` before every tool call. Verfy answers `deny` or `ask` with the rule and the reason, or nothing (so Claude Code's own permissions still apply). It never answers `allow` itself and never fails open, and it writes a signed receipt for each checked call once `verfy init` has created a key.
- **Skill:** lets Claude answer "did my MCP tools / skills / CLAUDE.md change?" with `verfy lock check`, `verfy lock files` and `verfy lock diff`, and report the risk Verfy explains. Approving a change stays with you.

## Limits

- If the `verfy` command is not installed, the hook cannot run. Claude Code then reports a hook error and does not block the call, so install the CLI first.
- Use either this plugin or `verfy hook install`, not both: with both, every call is checked twice and gets two receipts.
- Verfy is not a sandbox. See [`docs/SECURITY_LIMITATIONS.md`](../../docs/SECURITY_LIMITATIONS.md).
