# Changelog

What changed in the Verfy CLI (`pip install verfy`) and the website. Newest first. Every CLI version is on [PyPI](https://pypi.org/project/verfy/#history) and as standalone builds on the [releases page](https://github.com/anvarbekovjavohir277-dot/verfy-releases/releases).

## 0.20.0 (2026-11-11)

- **Machine-wide hooks: `verfy setup --system --write`** (run as administrator, or with sudo). It puts the Claude Code and Cursor hooks in the files an administrator deploys for the whole computer: `managed-settings.d/50-verfy.json` next to Claude Code's managed settings, and Cursor's enterprise `hooks.json`. An agent runs as you and cannot change those files, so even a script the agent writes and runs can no longer take Verfy's hook out. That was a known limit until now. Claude Code does not let user or project settings override a managed value. Verfy's own user-level hook is then taken out, so no call is checked twice; a backup of each file is kept. Verfy writes a drop-in file of its own, so an organisation's `managed-settings.json` is left as it is. Changes to these files are denied to the agent too.
- **Secrets in prompts are stopped before they are sent.** In Claude Code, Codex (UserPromptSubmit) and Cursor (beforeSubmitPrompt), a prompt that contains what looks like an API key, token or private key is blocked with the rule and a short reason, and gets a signed receipt (VFY-PROMPT-001). The secret itself is not shown or stored. Turn it off with `"prompt_secrets": "off"` in your policy.
- **Cursor: file writes, deletes and every other tool are checked.** Cursor's preToolUse hook now goes to Verfy too. File edits, which were the main gap in Cursor, get the same rules as Claude Code: for example, writing to `~/.bashrc` or deleting a hook file is denied. Terminal commands, file reads and MCP calls stay with their own hooks, so nothing is checked twice. MCP results are also cleaned of keys and tokens before the agent reads them (postToolUse), including those from remote servers that sign in with OAuth and so cannot go behind the gateway. `verfy setup --write` adds the new hooks to an existing install.
- **`verfy posture` shows risky settings in each agent's own config** and changes nothing. It covers:
  - Claude Code: `bypassPermissions`, `disableAllHooks`, a blanket `Bash` allow rule, `enableAllProjectMcpServers`;
  - Codex: `approval_policy = "never"` and `sandbox_mode = "danger-full-access"`, also in profiles, and `hooks = false`;
  - Gemini CLI: hooks switched off or Verfy's hook disabled, `auto_edit`;
  - Cursor: a Verfy hook that does not fail closed.
  
  It exits 2 when something high is found. `verfy doctor` shows the summary, and counts a setting that switches Verfy's hook off as a problem.
- **`verfy setup` sets Verfy up for every coding agent on the machine at once.** It finds Claude Code, Cursor, Codex CLI, Gemini CLI, GitHub Copilot (CLI and VS Code), Devin Desktop (Windsurf) and Claude Desktop by their folders and commands, then shows what it would change. For each agent that has hooks, it adds Verfy's hook. It puts the MCP servers in that agent's own config behind the gateway, which gives them scan, lock, pre-check, receipts and secrets taken out of answers. `verfy setup --write` makes the changes and keeps a backup of every file. Run it again after installing another agent. `--agent NAME` picks agents, `--project` works on this folder's files, and `--hooks-only` leaves the MCP configs alone. A remote server that signs in with OAuth is left as it is, because the gateway cannot sign in yet. In a terminal, `verfy init` now offers the same setup for every agent it finds; `--hook` still means yes.
- **Verfy for VS Code, Cursor and Windsurf (beta): an editor extension.** Each release now has `verfy-vscode.vsix`. Install it in the editor with Extensions > ... > Install from VSIX. It finds the Verfy CLI, or offers to install it in a terminal you can see. It shows what `verfy setup` would change and runs it after you agree. It shows in the status bar whether the agents here are guarded, and runs `doctor` and `ledger show`. The extension changes no file itself and makes no network call.
- **The editor's terminal inside the sandbox (beta).** The editor itself cannot run inside the sandbox, but its AI agent runs commands in the editor's terminal. `verfy setup --sandbox-terminal on` (or the extension) makes that terminal open inside `verfy run --sandbox` in VS Code, Cursor and Windsurf, so the agent's commands can write only in the project and reach only the hosts your policy allows. On Windows it goes through WSL2. `off` takes it away. A settings file with comments is not rewritten; Verfy prints the profile to add by hand.
- **`verfy wrap` edits Codex CLI's `config.toml`** (Python 3.11 or newer) in place. Comments and everything else in the file stay as they were, and the result is read back and compared before anything is written. Remote servers in it are left for `verfy proxy --url`.
- **`verfy run --sandbox --agent -- codex`** (or `gemini`, `copilot`) gives that agent its own key, service and folder inside the sandbox. It used to get Claude Code's. A command that is none of these still gets Claude Code's, as before. The new hook files in a project are closed to sandboxed commands.
- `verfy lock files` also watches the new hook files, Copilot CLI's MCP config and Windsurf's global rules, and `verfy scan --discover` reads `~/.copilot/mcp-config.json`.
- **Hooks for Codex CLI, Gemini CLI, GitHub Copilot, Devin Desktop (Windsurf) and Devin CLI.** `verfy hook install --codex`, `--gemini`, `--copilot`, `--devin` or `--windsurf` (or `verfy setup`) adds `verfy hook codex|gemini|copilot|devin|windsurf`. It checks each tool call with the same rules as the Claude Code hook and signs a receipt tagged with the agent. Codex's `apply_patch` is checked file by file. Input a hook cannot read is never allowed. Changes to these hook files are denied to the agent, and changes to `~/.codex/config.toml` need approval. How far each one was checked:
  - **Gemini CLI:** run through Gemini CLI 0.68.0's own hook runner on Windows, where Gemini runs hooks through PowerShell (`scripts/e2e_gemini_hooks.mjs`). Where Verfy would ask, Gemini asks you.
  - **Codex CLI:** checked against Codex's source: the hook input, the output schema, `apply_patch` and MCP tool names, hooks on by default, and trust in `/hooks`. Codex does not support "ask" from a hook (it would run the tool), so there Verfy blocks and tells the agent to ask you.
  - **Copilot (CLI and VS Code), Devin Desktop and Devin CLI (beta):** written from their documentation; their code is closed. Copilot asks you where Verfy would ask, and treats that as deny where nobody can answer. Devin has no "ask", so Verfy blocks with exit code 2. Windsurf has been called Devin Desktop since 2 June 2026. `--windsurf` remains for older Windsurf releases, and `verfy setup` adds both. Devin also reads Claude Code's settings, so a Devin call that reaches `verfy hook pre-tool-use` gets Devin's answer, or is left to `verfy hook devin` when that is installed.
- `verfy doctor` shows these hooks too.
- `--pub` takes a public key that starts with `-`. argparse used to read it as a flag.

## 0.19.0 (2026-11-10)

- **`verfy.lock` pins the server's code, not only its tools.** For a server that npx, bunx, pnpm dlx, yarn dlx, uvx or pipx starts with an exact version, `verfy lock check --update` records the package and the registry's hash of that release: npm's `dist.integrity` (sha512), or on PyPI the sha256 of every file of the release. `verfy lock check` fails with exit 2 when the config starts another version, drops the version, or the registry now reports other files for the locked version, even when every tool definition is unchanged. **After you upgrade, run `verfy lock check --update` once** to record the hashes; until then the check passes and says they are missing.
- **`verfy lock pin`** gives every server started as `pkg` or `pkg@latest` an exact version: the one in `verfy.lock` when the lock has the package, else the registry's latest today. It prints the change; `--write` saves it with a backup.
- **`verfy lock check --require-pinned`** exits 1 when a server is started with no exact version. Without it, such a server is a warning.
- **`verfy lock check --sarif FILE`** also writes the result as SARIF 2.1.0, so GitHub code scanning shows each changed tool, package or agent file. The GitHub Action has `sarif` and `require-pinned` inputs.

## 0.18.0 (2026-11-09)

- **`verfy doctor` checks this machine's setup and changes nothing.** It shows the signing key, how many receipts the ledger holds and when the last one was written, whether the Claude Code and Cursor hooks are in place, and how many tools `verfy.lock` pins. It exits 1 when Claude Code is installed without the Verfy hook or a settings file is not valid JSON, so a removed hook can be caught by a script. A removed hook still cannot report itself; with Verfy Cloud, a device that stops sending receipts shows in Dashboard > Devices.
- **`verfy proxy --url` starts its bridge with this same Verfy.** It used to run the first `verfy` found on PATH, which could be another version or another program. It now uses the standalone build itself or the Python that runs the proxy.
- The package lists its author, and issues go to [verfy-releases](https://github.com/anvarbekovjavohir277-dot/verfy-releases/issues) everywhere.

## 0.17.0 (2026-11-06)

A second internal attack test found these. The [report](https://github.com/anvarbekovjavohir277-dot/verfy-releases/blob/main/docs/SECURITY_TEST_2026-11.md) has the numbers, including what a fresh list still got through. It was not an independent test.

- **A `verfy.policy.json` that came with a repository can no longer switch Verfy off.** It used to replace your policy and your team's, so a cloned repo could disable every rule. Now it can only make Verfy stricter: anything that would loosen it is left out, and `verfy check` says so. If the file is yours, read it and run `verfy policy trust`; if it changes, you trust it again. `verfy policy use --project` trusts what it writes. A team policy is never loosened by a file in a folder. **If you rely on a project policy that loosens something, run `verfy policy trust` after you upgrade.**
- **Rules that guard Verfy itself cannot be disabled**, by any policy.
- **The guard reads Windows commands.** `Get-Content ~\.ssh\id_rsa`, `%USERPROFILE%`, `$env:USERPROFILE`, `rd /s /q`, `powershell -c`, `cmd /c` and encoded commands were mostly allowed. Registry run keys, scheduled tasks, Defender settings and download tools now need a person.
- **Shell structure no longer hides a command:** `if`, `for`, functions, `alias`, variables, `$(...)`, brace expansion, `find -exec`, `flock`, `strace`, `chroot`, `parallel` and `script -c`. A key file is noticed wherever the command names it.
- **More ways to read a key or run code need a person:** inline code in more languages, `LD_PRELOAD` and `GIT_SSH_COMMAND`, printing stored tokens (`gh auth token`, `aws secretsmanager`, `kubectl get secrets`), browser and keychain files, tunnels, the Docker socket, installing from a URL, wiping a database, removing logs, and skipping git hooks.
- **A sensitive path is seen under any argument name**, also nested, and whatever its case, because macOS and Windows ignore case.
- **SQL and URLs:** comments inside SQL, `COPY ... TO PROGRAM`, `pg_read_file`, `INTO OUTFILE`; `gopher:` and `dict:` URLs, metadata behind `nip.io`, the AWS IPv6 and ECS metadata addresses. Private network addresses need a person; `localhost` does not.
- **MCP prompts are pinned like tools,** as `prompt:<name>` in `verfy.lock`, and a changed one is hidden. Their text is scanned when fetched, and resources that fail the scan are hidden. **After you upgrade, servers with prompts show new entries once:** review them and run `verfy lock check --update`.
- **The scanner sees through disguises:** invisible characters, Unicode tags, leet, spaced letters, base64, other languages, annotations and output schemas, parameter names, look-alike tool names, and a fixed email address.
- **Secrets:** unquoted settings such as `DB_PASSWORD=...`, passwords in URLs, bearer tokens, JWTs, and keys from AWS, GitLab, npm, PyPI, Supabase, SendGrid, Hugging Face, Azure and others are now recognised.
- **`verfy wrap` no longer prints the values in `env` and `headers`,** and writes `verfy`, not a path on your machine, into a config in the project.
- **`verfy update` on a standalone build downloads the install script and then runs it,** instead of piping it into a shell.
- **`verfy verify --ledger FILE` on an empty file says so and exits 1.** A hook input with no tool name needs a person. A `VERFY_HOME` elsewhere gets the same protection as `~/.verfy`. Bad input gives a short error, not a Python traceback.
- **The hook accepts a byte order mark,** which Windows PowerShell adds when its output encoding is UTF-8.

## 0.16.1 (2026-11-06)

- **A sandboxed command can no longer create a missing `verfy.lock`, policy, `.mcp.json`, agent settings or git hooks on Linux.** 0.16.0 closed these only when they already existed there, so a command could write a new `.mcp.json` that runs later, outside the sandbox. A review found this. They are now closed on every system whether they exist or not, with a test for each.
- **The `.claude` and `.cursor` folders are closed as a whole in the sandbox,** so a command cannot add a skill, a rule or a hook script there either.
- **Verfy reads an empty policy or lock as a missing one.** On Linux the runtime leaves an empty placeholder while a sandboxed command runs, and a hook outside it in the same folder has to keep working.
- **The installers say what a checksum shows:** that the download is whole, not who built it. `SECURITY.md` and verfy.dev/security show how to check a file on PyPI and a standalone build.

## 0.16.0 (2026-11-05)

An internal attack test found these, and the [report](https://github.com/anvarbekovjavohir277-dot/verfy-releases/blob/main/docs/SECURITY_TEST_2026-11.md) lists them all. It was not an independent test.

- **`$HOME` no longer walks around a path check.** `cat $HOME/.ssh/id_rsa` was allowed while `cat ~/.ssh/id_rsa` was stopped.
- **The cloud metadata address is caught however it is written:** as a decimal, in hex or octal, or inside IPv6.
- **`file:` URLs are read as files,** and a tool that runs commands is checked when it takes them as `args`.
- **More shell tricks are stopped or need a person:** `busybox`, a computed command name, a here-string into a shell, inline code that deletes, fetches or names a key, download then run, `crontab`, `systemctl enable`, git settings that run a command, a new git remote, a container given the host's disk, and `pipx run verfy` or `uvx verfy`.
- **The gateway forwards only what it could read.** A line that is not strict JSON and a `tools/call` without an id are dropped, and a malformed message no longer stops it.
- **The lock also covers `title`, `annotations` and `outputSchema`** when a server sends them, because clients act on annotations. **After you upgrade, tools that have these fields show as changed once:** review them with `verfy lock diff` and approve. Verfy Cloud accepts the new fields.
- **A sandboxed command cannot change `verfy.lock`, the policy, `.mcp.json`, Claude Code's or Cursor's settings, git hooks or `.git/config` in its own folder,** because those decide what runs later, outside the sandbox. On Linux this covers the files that exist when it starts.

## 0.15.0 (2026-11-05)

- **API keys in your environment no longer reach a sandboxed command.** `verfy run --sandbox` closed `~/.aws` but still handed over `AWS_SECRET_ACCESS_KEY`. Now only `PATH`, `HOME` and other basics go in, and `--allow-env NAME` adds one. With `--agent`, its own `ANTHROPIC_*` and `CLAUDE_*` variables go in too. If a sandboxed MCP server needs a key, name it with `--allow-env`.
- `SECURITY.md` now says how long a fix may take: 90 days, then an advisory either way.

## 0.14.0 (2026-11-05)

- **Remote servers on the older SSE transport.** `verfy proxy --url`, `verfy wrap`, `verfy lock check` and `verfy scan --live` now fall back to HTTP+SSE when a server refuses the first POST the way the MCP specification describes. The address the server names for its messages must be on the same server, so a key does not go anywhere else. OAuth sign-in is still not supported.
- **The installers check more.** With a signed-in GitHub CLI they verify the build attestation before installing, because a checksum from the same release shows only that the download is whole. They refuse a version that does not look like 1.2.3 before it reaches `rm -rf`, and the shell installer no longer writes a `VERFY_BIN_DIR` with unsafe characters to your shell profile.
- `SECURITY.md` and `/.well-known/security.txt` now give an email address next to GitHub's private reporting.

## 0.13.0 (2026-11-05)

- **Cursor hook (beta).** `verfy hook install --cursor --write` adds `verfy hook cursor` to `~/.cursor/hooks.json`, so Cursor's terminal commands, file reads and MCP calls are checked before they run and each gets a signed receipt. Verfy sets `failClosed`, because by default Cursor lets an action through when a hook crashes, and `.cursor/hooks.json` is now protected from the agent. A file read cannot wait for a person, so `ask` becomes `deny` there. Cursor's file edits and web search are not covered. This follows Cursor's documentation and has not yet been run inside Cursor itself.
- **The sandbox from Windows.** On native Windows, `verfy run --sandbox` now hands over to `verfy run` inside WSL2. It needs verfy and `srt` installed there; without them the command does not run (exit 3). Native Windows itself still has no sandbox runtime.
- **Inside WSL, the Windows user's keys are closed too.** The sandbox denied `~/.ssh` but not `/mnt/c/Users/you/.ssh`, which Linux can read. Every credential folder is now closed for each Windows user it finds.
- **Fewer false alarms in the scanner.** `summary` and `metadata` no longer count as side channels: they are ordinary required fields in Jira and HubSpot tools. On the newest release of the 34 servers from the October research (532 tools), the scanner now reports no high or critical findings and one medium; version 0.5.1 reported 163 high or critical.
- The sandbox workflow now also runs on Windows: the full end-to-end test inside real WSL2, and a new one from native Windows, with a control next to every refusal.

## 0.12.0 (2026-11-05)

- **`verfy run --sandbox -- COMMAND`.** Starts one command inside Anthropic's sandbox runtime (`srt`), a separate open source tool, with settings written from your Verfy policy: no network except `network.allow` and `--allow-host`, writes only in this folder and `--allow-write` paths, and no reading credential paths, `~/.verfy` or what `files.sensitive` lists. This covers what Claude Code's sandbox leaves out, because it can hold an MCP server: `verfy proxy --name fs -- verfy run --sandbox -- npx ...`. The command does not run if `srt` is missing or sits in a folder the command could write to. It works on macOS and Linux and refuses on native Windows. `srt` is a research preview and you install it yourself.
- **`--agent` runs the agent itself in it.** The Verfy hook then runs inside the sandbox too, so Verfy's folder stays open to it, and the guard, not the sandbox, keeps the agent out of the signing key. Credentials stay unreadable. It opens `api.anthropic.com` and Claude Code's own files.
- **Receipts say when a call ran in a sandbox:** `"sandbox": "srt"` from `verfy run`, or `"claude-code"` when Claude Code's sandbox is on in the settings the hook can see. It is what this machine states, not a proof. Older receipts have no such field and stay valid.
- A new workflow runs all of this on real Linux and macOS and checks what the system refuses, including a real MCP server, the hook signing from inside, and that a command never runs unsandboxed. The scanner and `verfy lock rollback` see through `verfy run`, so a sandboxed server is still checked and pinned.

## 0.11.0 (2026-11-05)

- **`verfy proxy --name NAME --url https://...`.** Puts a remote server behind the gateway in one command. `--bearer-env VAR` reads a bearer token from the environment, so it is not on the command line, in `verfy.lock`, in receipts or in logs, and Verfy refuses to send it over plain http. Scans and `verfy lock check` treat the entry as the remote server it is. OAuth is not supported yet.
- **The package in the lock.** `verfy lock check --update` writes the pinned package (`pkg@1.2.3`) next to the version the server reports, and `verfy lock rollback` goes back to that package, because a server's own version number is often not its package's.
- **`verfy scan` checks the sandbox.** With Claude Code on the machine, `--config` and `--discover` add what `verfy sandbox status` finds, without changing the exit code. Two new findings: the Docker socket is open (VFY-SBX-007), and allowed domains reach most of the internet, such as `*` or `*.com` (VFY-SBX-008).
- **Session rules follow the list more closely.** After outside text, `git push`, reading a key file and writing outside the project now wait for a person too. A request to a site on `network.allow` no longer does. Both engines share the new cases.

## 0.10.0 (2026-11-04)

- **Work with Claude Code's sandbox.** Verfy is not a sandbox, and the two cover different ground: Claude Code's sandbox wraps shell commands at the operating system level, so it holds a script the agent wrote, and it leaves out MCP servers, hooks and the built-in file and web tools, which Verfy watches. It is off by default, and when on it still lets commands read most of the machine. `verfy sandbox status` reports what the settings leave open, and `verfy sandbox sync --write` turns it on, closes the retry outside it, blocks credential paths and `~/.verfy` from reads, and allows the hosts in your Verfy policy. It adds and never removes, and keeps a backup. The sandbox does not run on native Windows. The guard denies `verfy sandbox sync --write` when the agent runs it.
- **Rules that follow the session.** A web page or a tool's answer can carry instructions for the agent. With `"session": {"after_outside_text": "ask"}` (or `deny`, which the `strict` template uses), once a session has read outside text, what can do harm from then on needs a person: the network, messages, payments and deletes (VFY-SESSION-001). Ordinary work such as editing files and running tests goes on. It looks only at the order of events, so no model judges the text, and it does not prove the agent obeyed anything. It is off by default. The hook keeps this per session in `~/.verfy/sessions` (the tool's name only, never its arguments); each gateway keeps it for its own connection, and the two do not share it. Both engines share the new cases.
- **`verfy lock rollback SERVER`.** When a tool changed, go back to a release that matches the lock instead of stopping work. It starts that release, compares its tools with `verfy.lock`, and only if they all match pins the version in your MCP config (`--write`, with a backup). The default is the version the server reported when it was locked, which `verfy lock check --update` now records; `--to VERSION` picks another. It works for servers started through npx, bunx, uvx and pipx. A remote server cannot be rolled back: it runs whatever its owner deployed. The guard denies `verfy lock rollback --write` when the agent runs it.
- **The gateway guards remote MCP servers too.** `verfy wrap` now puts a remote server (a `url` in the config) behind the gateway, through a new `verfy bridge` that speaks stdio on one side and Streamable HTTP on the other, so rules, the lock, redaction and receipts apply to it as they do to a local server. Headers move to the server's `env`, so a key is not on a command line; `${VAR}` is filled in when the bridge starts. Verfy does not follow redirects. Not covered yet: the older SSE transport (`verfy wrap` leaves those servers alone and says so), servers that sign in with OAuth in your MCP client (the bridge has only the headers in the config), and messages a server sends outside an answer to a request.

## 0.9.0 (2026-11-04)

- **Salted hashes in receipts.** Receipts hold a hash of a call's arguments and result, not the values, and that is what reaches Verfy Cloud. A plain SHA-256 of a short argument such as `{"command": "ls"}` can be guessed by hashing likely values, so anyone with the database could have read it back. From this version the hash is SHA-256 of the value together with a secret salt that stays in `~/.verfy/key.json`, so it says nothing without that file. The format is unchanged (`args_sha256` and `result_sha256`, still `sha256:…`), signatures and chains work as before, and a key file without a salt gets one the first time it signs. Receipts written before this version keep their plain hashes. Hashes sent to the approval queue are salted too.
- `verfy ledger hash JSON` prints the hash this machine records for a value, so you can still match known arguments to a receipt. Someone without your `key.json` cannot.

## 0.8.1 (2026-11-04)

- The website moved to https://verfy.dev. `verfy update`, the installers, the package links and the docs use it. The old address leads there, and Verfy Cloud's API still answers at it, so devices enrolled there keep working.

## 0.8.0 (2026-11-01)

- **Set up a machine with one command.** `verfy init --url … --code …` creates the signing key and policy as before, prints one line about the MCP servers in your Claude Code, Cursor and Claude Desktop configs (it reads the files and starts nothing), offers to add the Claude Code hook when Claude Code is installed and you are in a terminal (`--hook` / `--no-hook`; never added without asking), and connects the machine to Verfy Cloud. Until now this took `verfy init`, `verfy hook install --write`, `verfy team enroll` and a `verfy sync` after every session.
- **Receipts upload on their own.** On a device enrolled with this version, after the hook or the gateway writes a receipt, Verfy starts `verfy sync` as a separate background process, at most every five minutes; the hook itself still never goes online, and a failed upload never affects the guard. What happened goes to `~/.verfy/sync.log`. `verfy team auto-sync off` goes back to uploading only with `verfy sync`; devices enrolled before this version stay that way until `verfy team auto-sync on`. `verfy team status` shows which.
- The guard denies `verfy team enroll`, `verfy init` with `--url` or `--code`, and `verfy team auto-sync off` when the agent runs them, so an agent cannot send this device's receipts to another Verfy Cloud or stop them from reaching your team. Five new cases, shared by both engines.

## 0.7.0 (2026-10-28)

- **Remote MCP servers.** `verfy lock check` and `verfy scan --live` now read the tools of remote servers (a `url` in the config) over Streamable HTTP instead of skipping them, so a CI check covers hosted servers too. Headers come from the config: `headers` (Claude Code, Cursor, VS Code and others) or Codex CLI's `http_headers`, `env_http_headers` and `bearer_token_env_var`, with `${VAR}` and `${VAR:-default}` filled in from the environment, so a key can come from a CI secret. A missing variable fails the check and names the variable, never a value. Verfy does not follow redirects, so a key only goes to the address in the config. Servers that only speak the older SSE transport are reported, not supported yet. The MCP gateway still runs in front of stdio servers only.
- Tested with a local fake server (sessions, server-sent events, pages of tools, a refused key, a redirect, a missing variable) and by hand against two public remote servers, DeepWiki and Context7.
- Fixed: inside GitHub Actions, `verfy lock check --json` printed annotations after the JSON, so the output did not parse. With `--json` there are no annotations now; the step summary is still written.
- The GitHub Action works again now that the source repository is public: `uses: anvarbekovjavohir277-dot/verfy@cli-v0.7.0`. It checks remote servers too.

## 0.6.3 (2026-10-26)

- **Security: the agent can no longer read Verfy's signing key or device token.** Up to 0.6.2 an agent could read `~/.verfy/key.json` (for example with `cat` or Claude Code's Read tool), and with it sign receipts of its own, or read the device token in `~/.verfy/team.json`. Now reading either file, listing, searching or copying `~/.verfy`, or naming the folder and one of those files in one command is denied (VFY-SELF-006), including `$HOME`, `%USERPROFILE%`, quoted, globbed and `cd`-then-read forms; archiving, copying or searching a folder that holds it, such as the home folder, or looking for files with those names needs approval (VFY-SELF-007). Both engines (Python and JavaScript) share the 26 new test cases. A program the agent writes and runs can still read the file: see [SECURITY_LIMITATIONS.md](docs/SECURITY_LIMITATIONS.md). If an agent may have read your key, create a new one yourself with `verfy init --force` (it starts a new receipt chain) and, with Verfy Cloud, revoke the device and enroll it again. Found while reviewing a contribution.
- The end-to-end test also checks that the hook denies reading the signing key with `cat` and with the Read tool.
- Website (27 October): Verfy Advisories have `VERFY-YYYY-NNNN` ids. The old ids (such as ATLS-2025-0001) stay in `aliases`, and links to them lead to the new pages.
- **[verfy-releases](https://github.com/anvarbekovjavohir277-dot/verfy-releases) is the home for installing Verfy**: the standalone builds, the Claude Code plugin (`claude plugin marketplace add anvarbekovjavohir277-dot/verfy-releases`, then `claude plugin install verfy@verfy`), the security policy (report vulnerabilities and bypasses there), the advisories, the research and this changelog. The source is in [anvarbekovjavohir277-dot/verfy](https://github.com/anvarbekovjavohir277-dot/verfy), under the MIT license. The GitHub Action is replaced by two steps, `pip install "verfy==0.6.3"` and `verfy lock check`, with the same annotations and step summary.

## 0.6.2 (2026-10-26)

- **Verfy Registry sends only pins.** `verfy team registry report` now sends only the SHA-256 pin of each locked tool definition, no longer the local server and tool names, which can be private. Verfy Cloud stores only the pins and when each was reported, and no longer has a place for names. Owners and admins can delete all of their team's pins in Dashboard → Locks, and a pin not reported for 180 days stops counting and is deleted. What is sent and what is not: https://verfy.dev/docs#registry
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
