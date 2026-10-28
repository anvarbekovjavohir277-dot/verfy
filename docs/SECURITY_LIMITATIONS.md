# Security limitations

Verfy reduces risk; it does not remove it. These are the limits we know about. Nothing in the product, the site or these docs claims otherwise.

## The guard

- Rules are deterministic pattern matching over commands, paths, URLs and arguments. They are not a sandbox and cannot understand every possible shell construct, interpreter or obfuscation. Run untrusted code in a container or VM as well.
- Verfy only sees calls that go through its Claude Code hook or its MCP gateway. Tools an agent reaches another way are not checked.
- The hook answers deny or ask, never allow; Claude Code's own permission settings still decide allowed actions.
- Anyone with write access to the developer's machine can remove the hook or edit the policy. Team policy and receipts make that visible, not impossible.
- The guard stops the agent from switching Verfy off through the paths it understands: editing Claude Code's hook settings, `verfy.lock`, `verfy.policy.json`, `~/.verfy` or the Verfy install (deny), editing MCP configs (ask), and running `verfy lock approve`, `verfy lock check --update`, `verfy init --force` or `pip uninstall verfy` (deny). A script the agent writes and then runs, or an interpreter one-liner, can still do these things; Verfy asks for the obvious one-liners but cannot follow every program.
- The agent may not read Verfy's signing key or device token (`~/.verfy/key.json`, `~/.verfy/team.json`). Reading either with a shell command or a file tool, listing, searching or copying `~/.verfy`, or naming the folder and one of those files in one command is denied (VFY-SELF-006); archiving, copying or searching a folder that holds `~/.verfy`, such as the home folder, or looking for files with those names, needs approval (VFY-SELF-007). The key is still an ordinary file your user account can read, so a program the agent writes and runs, or a path it builds while running, can read it; keeping the key out of the agent's reach altogether (for example in the operating system's keychain) is not built yet. A `VERFY_HOME` outside `~/.verfy` is not covered by these rules.
- On Windows, paths are compared without regard to case and in the `/c/...` form Git Bash uses. Rules written for Unix system folders do not apply there.

- The gateway replaces secrets in tool results and resources with `[REDACTED:<rule>]`. It recognises the formats in `patterns.json` (private key blocks, AWS, GitHub, Anthropic, OpenAI, Stripe, Slack, Google and Telegram keys, and `password = "..."`-style assignments); a secret in another format, split across lines or encoded, gets through. In Claude Code the output of built-in tools (Bash, Read, ...) is not redacted, because a PreToolUse hook cannot rewrite it; reading `.env` and similar files needs approval instead.
- Policy templates (`strict`, `read-only`, `ci`) match tool names by pattern. A write tool with an unusual name (not `*write*`, `*create*`, `*delete*` and so on) is not caught by `read-only`.

## The scanner and locks

- A clean scan is not a security certification. The scanner finds known warning signs in tool definitions and configs.
- `verfy scan --discover` is static and does not start servers. `--live` starts each configured stdio server and calls each remote server (with the headers in its config) to list their tools; only use it for servers you would run anyway.
- The first time a server is seen, its tools are locked as they are (trust on first use).
- A lock proves a definition did not change since it was approved, not that it is safe.
- The risk Verfy gives a change (low, medium, high) comes from deterministic patterns: new sentences that order the model to move data, new links, hidden-instruction patterns and schema changes. A cleverly worded instruction can still be rated low, so read the diff before you approve.
- `verfy lock files` pins the instruction files, skills, commands, hook settings and plugins it knows about (listed in the CLI README). An agent can also read files Verfy does not list; those are not pinned.
- `verfy import` follows the documented JSON formats of Snyk Agent Scan and Cisco MCP Scanner. Those formats may change between their releases, and the gateway matches imported findings by server and tool name only.
- `verfy lock check` (and the GitHub Action) starts every stdio server command in the given config, like `--live`, and calls every remote server with the headers in the config. In CI that runs those packages on the runner with whatever secrets you pass them; pin versions and keep the job's permissions read-only. The MCP gateway runs in front of stdio servers only: a remote server's tools are checked by `lock check`, not hidden or blocked while the agent runs. A server can serve different definitions to different clients or at different times, so a passing CI check does not replace the lock on each developer's machine.

## Updates

- `verfy update`, and the once-a-day check when automatic updates are on, ask GitHub (standalone builds) or PyPI (pip installs) for the newest version and then run the same install script or `pip install --upgrade` you would run by hand. Updating trusts those services and this project's release process exactly as much as the first install did.
- The standalone build is checked against `SHA256SUMS` from the same GitHub release. That catches a broken download, not a release someone was able to replace. The builds are not code-signed.
- Automatic updates are off unless you choose them in `verfy init` or with `verfy update --auto on`. The hook, the gateway and `verfy sync` never check for updates.

## Receipts

- A receipt proves the decision Verfy made, the hashes of arguments and results, and that the record was not changed afterwards. It does not prove what a tool did internally.
- A device key proves which device signed, not that the device was uncompromised.
- Whoever holds a device's private key can build a new chain from scratch and sign it, and `verfy verify` will accept that chain on its own: the check catches edits, deletions and reordering inside a chain, not a complete replacement. Receipts already synced to Verfy Cloud cannot be replaced this way, because the server keeps the hash of every stored receipt and refuses different content for the same position (`chain_conflict`). A ledger that was never synced has no outside copy to compare with.
- Deleting an entire local ledger together with its key is not detectable locally; it is detectable when the device had already synced to Verfy Cloud.
- There is no external timestamping or transparency-log anchoring yet, so receipts show order, not trusted wall-clock time. `verfy scitt export` produces SCITT signed statements that a transparency service could register, but Verfy does not register them anywhere.

## Verfy Cloud (the hosted service)

- Row-level security and server checks are tested on every build against the real migrations, but not yet reviewed by an independent penetration test.
- A database superuser (Supabase project owner) can technically alter data by disabling triggers. The audit log is hash-chained so silent edits are detectable when compared with an earlier copy or export, but it is not externally anchored.
- No software can promise to be unbreakable, and Verfy does not. It stacks independent layers so that one mistake is not enough: edge firewall, the in-app shield, Postgres rate limits, row-level security, two-factor authentication enforced in the database, append-only evidence.
- The shield's flood limits are per server instance (in memory); the limits that hold across all instances are the Postgres ones. Volumetric DDoS protection comes from Vercel's network; the WAF rules, bot protection and Attack Challenge Mode are settings of the Vercel project.
- Two-factor authentication is opt-in per user. Accounts without it are protected by their password (at least 12 characters), the per-account limits and, if configured, the CAPTCHA.
- The CAPTCHA is optional and only effective when both the Turnstile site key (Vercel) and secret key (Supabase) are configured.
- `TRACE` requests are refused by Next.js itself with a generic error page before any Verfy code runs; they should be denied at the edge.
- Exports are limited to 20,000 receipts per request; there is no background job queue yet.
- Notification channels: the Slack webhook URL or Telegram bot token is stored in the database for the server, which needs it to send. Browsers cannot read it (no grants, RLS on), but anyone with the Supabase secret key can. Messages go only to `hooks.slack.com` and `api.telegram.org`. "A device went quiet" is checked once a day from Vercel Cron; set `CRON_SECRET` so nobody else can trigger the check (without it, a caller can only cause alerts that are due anyway, once per silence).
- The approval queue (`"on_ask": "team"`) works through the MCP gateway only; the Claude Code hook does not wait on the network. The person approving sees the tool, the rules and their messages and a hash of the arguments, not the arguments, so they approve the kind of call rather than its exact content. Without a Slack or Telegram channel (Dashboard → Notifications), someone has to have Dashboard → Approvals open. A device can ask for at most 300 approvals an hour, and an organization can have 200 waiting at once.
- Invitations are links you share yourself; Verfy sends no email of its own (Supabase Auth sends sign-up and reset emails).
- Policy regexes are checked for nested quantifiers, but regular expressions can still be slow on adversarial input on developer machines.

## What we do not do

No language model takes part in verdicts or verification. No "100% secure", "hacker-proof" or "guaranteed" claims. No certification, insurance or guarantee products exist in this release.
