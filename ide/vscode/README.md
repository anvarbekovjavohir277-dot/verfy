# Verfy for VS Code, Cursor and Windsurf

Guard the AI agents in your editor. Verfy checks each tool call an agent makes before it runs: terminal commands, file reads and writes, and MCP tools. It locks the definition of every MCP tool and blocks one that changed after you approved it, and it signs a receipt for every call it checks. The rules are fixed patterns; no model decides allow or deny.

The checks are done by the [Verfy CLI](https://verfy.dev/install) (free, MIT). This extension sets it up and shows what it does:

- **Set up every agent on this computer.** It finds Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot, Windsurf and Claude Desktop. It adds Verfy's hook to each and puts their MCP servers behind the Verfy gateway. You see the list of changes first, and a backup of every changed file is kept.
- **Open the terminal inside the sandbox (beta).** The editor's AI agent runs its commands in the editor's terminal. With this on, that terminal starts inside `verfy run --sandbox`, so a command can write only in the project and reach only the hosts your policy allows. On Windows this needs WSL2 with `verfy` and `srt` inside it.
- **Fix risky agent settings** (`verfy posture --fix`): bypass modes and hooks switched off, each fixed with the smallest edit after you see it.
- **Take Verfy out again** (`verfy setup --undo`): its hooks, the gateway and the sandboxed terminal, everything else kept.
- **Check this computer** (`verfy doctor`) and **show the latest receipts** (`verfy ledger show`).

The status bar shows whether the agents found here are guarded. If the CLI is missing, the extension offers to install it in a terminal you can see.

The extension changes no file itself and makes no network call. Every change goes through the CLI.

## Commands

- `Verfy: Set up every agent on this computer`
- `Verfy: Open the terminal inside the sandbox` / `Stop opening the terminal inside the sandbox`
- `Verfy: Check this computer (doctor)`
- `Verfy: Show risky agent settings` (`verfy posture`: bypass modes, hooks switched off, a sandbox turned off)
- `Verfy: Fix risky agent settings` (`verfy posture --fix`)
- `Verfy: Take Verfy out of every agent (undo setup)` (`verfy setup --undo`)
- `Verfy: Show the latest receipts`
- `Verfy: Install the Verfy CLI`

## Settings

- `verfy.path`: the verfy command, if it is not on PATH.
- `verfy.offerSetup`: on start, offer to set up the agents that are not guarded yet (default on).

## Limits

The hooks for Cursor, Codex, Gemini CLI, Copilot and Windsurf are beta. They follow each agent's documentation and have not yet run inside every agent. A remote MCP server that signs in with OAuth is left as it is. Verfy's rules are pattern matching: a seat belt, not a wall.

[Docs](https://verfy.dev/docs) · [Security model](https://verfy.dev/security) · [Source](https://github.com/verfy-dev/verfy)
