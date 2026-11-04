---
name: verfy
description: Check MCP tools and agent instruction files with the Verfy CLI. Use when the user asks whether their MCP servers, tools, skills, plugins or CLAUDE.md/AGENTS.md files changed, are locked, or look risky, or asks about Verfy receipts.
---

# Verfy

Verfy is installed as a command-line tool (`verfy`). It guards this session through a PreToolUse hook and keeps signed receipts. Use these read-only commands to answer the user:

| Question | Command |
| --- | --- |
| Which MCP servers can the agents reach, and how are they launched? | `verfy scan --discover` |
| Did any locked MCP tool change? | `verfy lock check` (starts the servers in `.mcp.json` and compares them with `verfy.lock`) |
| What exactly changed in a server's tools? | `verfy lock diff SERVER` |
| Did an instruction file, skill, command or hook setting in this repository change? | `verfy lock files` |
| Did a user-level skill, plugin or instruction file change on this machine? | `verfy lock files --user` |
| Are the receipts intact? | `verfy verify` |
| What did Verfy decide recently? | `verfy ledger show -n 20` |

Each change comes with a risk level (`low`, `medium`, `high`) and a short explanation, for example a new instruction that tells the model to send data somewhere. Report the risk and the explanation to the user, and quote the diff when it is short.

Approving a change is the user's decision, not yours. Do not run `verfy lock approve`, `verfy lock add`, `verfy lock check --update`, `verfy lock files --update` or `verfy policy use`: Verfy denies them when an agent runs them. Tell the user which command to run themselves after they have reviewed the change.

If `verfy` is not found, tell the user to install it with `pip install verfy` (or the installer described at https://verfy.dev/docs#install) and run `verfy init`.
