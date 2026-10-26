# Verfy CLI

Guard coding-agent tool calls, scan and lock MCP tools, and sign a verifiable receipt for every call Verfy checks. Plain Python (≥ 3.10), no required dependencies, MIT.

```bash
pip install verfy                  # Python ≥ 3.10, no dependencies
curl -fsSLO https://verfy-tech.vercel.app/install.sh && less install.sh && sh install.sh   # no Python: macOS, Linux (read it, then run it)
pip install "verfy[fast]"          # optional: faster Ed25519 via `cryptography`
```

## Guard Claude Code

```bash
verfy init                      # ~/.verfy: signing key (0600), starter policy
verfy hook install              # shows the change to ~/.claude/settings.json
verfy hook install --write      # saves it (a backup is kept); --project for ./.claude/settings.json
```

Claude Code then runs `verfy hook pre-tool-use` before every tool call. The agent cannot switch Verfy off through what Verfy sees: changes to the hook settings, `verfy.lock`, the policy, `~/.verfy` or the Verfy install are denied, changes to MCP configs need approval, and so do `verfy lock approve`, `verfy lock check --update`, `verfy init --force` and `pip uninstall verfy` when the agent runs them (denied). Verfy answers **deny** or **ask** with the rule and reason, or stays silent so Claude Code's own permissions decide; it never answers allow itself. Any error becomes `ask` (or `deny` with `"fail_mode": "deny"`). The hook never touches the network.

## Update

```bash
verfy update                    # install the newest version (standalone build, pip, pipx or uv: whichever you used)
verfy update --check            # only report; exit 1 when a newer version exists
verfy update --auto on          # once a day, when you run a verfy command, update in the background (off: --auto off)
```

`verfy init` asks which you prefer the first time; the default is manual, so Verfy never goes online on its own. The hook, the gateway and `verfy sync` never check for updates.

## Guard MCP servers (gateway)

```bash
claude mcp add filesystem -- verfy proxy --name filesystem -- npx -y @modelcontextprotocol/server-filesystem@2025.8.21 ~/project
verfy wrap ~/.cursor/mcp.json --write      # wrap every server in a config (backup kept)
```

The gateway scans each `tools/list` answer, hides poisoned or drifted tools, checks every `tools/call`, can ask the user through MCP elicitation (`"on_ask": "elicit"`), and writes a receipt for every call. Secrets in tool results and resources (API keys, tokens, private keys in the formats the scanner knows) are replaced with `[REDACTED:<rule>]` before the agent reads them; the receipt keeps the hash of the original result. Set `"redact_output": false` to turn this off.

With `"on_ask": "team"` (device enrolled in Verfy Cloud), a call that needs approval waits in Dashboard → Approvals until an owner or admin decides, for at most `"approval_timeout"` seconds (default 120, 10 to 900). The request carries the tool, the rules that asked and the SHA-256 of the arguments, never the arguments. A rejection, no answer in time or an unreachable server refuses the call; the receipt records `approved_by: "team:<name>"` when it runs. The Claude Code hook never waits on the network, so this works through the gateway only.

## Scan

```bash
verfy scan --discover                 # static check of Claude Code, Cursor, Claude Desktop configs
verfy scan --discover --live          # also start each stdio server and scan its tools
verfy scan tools.json --fail-under C  # a saved tools/list answer, for CI
```

Exit codes: config scan `0` ok, `1` medium, `2` high or worse; tool scan `1` with `--fail-under` when a server grades worse.

## Lock

```bash
verfy lock status                 # 0 ok · 1 new/removed · 2 drift
verfy lock diff filesystem        # what changed, invisible characters spelled out
verfy lock approve filesystem     # review, then accept (--yes after reviewing in CI)
verfy lock add tools.json --server remote-api
verfy lock verify                 # verfy.lock is well formed and untampered
```

A project-level `./verfy.lock` is used when present, otherwise `~/.verfy/verfy.lock`.

### In CI

```bash
verfy lock check --update         # start the servers in .mcp.json, review every definition, write ./verfy.lock
verfy lock check                  # 0 ok · 1 new/removed · 2 drift · 3 a server did not answer
```

Commit `verfy.lock`; a pull request that changes a tool then fails until someone reviews the diff and runs `--update`. Inside GitHub Actions the command also writes annotations and a step summary. The repository root has an `action.yml` that installs this CLI and runs the check:

```yaml
- uses: actions/setup-python@v7
  with: { python-version: "3.13" }
- uses: anvarbekovjavohir277-dot/verfy@cli-v0.5.5
  with: { config: .mcp.json, lock: verfy.lock }
```

`lock check` starts each stdio server command from the config, as your MCP client would: pin package versions and pass keys as CI secrets. Remote servers are skipped.

## Check and verify

```bash
verfy check "git push --force"                       # 0 allow · 1 ask · 2 deny
verfy check --tool send_payment --args '{"amount": 500}'
verfy ledger show
verfy ledger show --json -n 2                        # latest two signed receipts as a JSON array
verfy verify                                         # your own ledger
verfy verify --ledger receipts.jsonl --pub <key> --kid <chain> [--start-after <hash>]   # an evidence export
```

`ledger show --json` preserves the stored receipt fields, including signatures. It
returns up to the last `-n` receipts (20 by default), in ledger order, or `[]` when
the ledger is empty.

## Verfy Cloud

```bash
verfy team enroll --url https://verfy-tech.vercel.app --code atle_…   # code from Dashboard → Devices
verfy sync                     # upload new receipts (run from cron/CI, never in the hook)
verfy team pull                # team policy + team-approved locks
verfy team propose SERVER TOOL # ask admins to approve a changed tool
verfy team status
```

Only the public key is sent at enrollment. The device token is stored in `~/.verfy/team.json` (0600). Receipts are uploaded exactly as signed; they contain only hashes of arguments unless you enabled `receipts.include_args`, in which case `sync` needs `--allow-args`.

## Policy

Start from a template, or write your own:

```bash
verfy policy templates            # strict, read-only, ci
verfy policy show read-only       # print it
verfy policy use read-only        # ~/.verfy/policy.json (--project: ./verfy.policy.json, --force replaces, a backup is kept)
verfy init --template ci          # same, while setting up
```

- **strict**: anything risky is denied instead of asked, unknown hosts are blocked (package registries and GitHub are allowed), errors deny, new MCP tools are denied until approved.
- **read-only**: file edits (`Write`, `Edit`, ...) and write-style MCP tools (`*create*`, `*delete*`, `*push*`, ...) are denied; every shell command needs approval. Tool names are matched by pattern, so check `verfy policy show read-only` against your servers.
- **ci**: nobody is watching, so anything that would ask is denied; same network limits as strict.

The agent cannot change the policy itself: editing it is denied, and so is `verfy policy use` when the agent runs it.

JSON merged over `src/verfy/data/default_policy.json`. Precedence: `--policy FILE`, `./verfy.policy.json`, `~/.verfy/team/policy.json`, `~/.verfy/policy.json`.

```json
{
  "on_ask": "deny",
  "fail_mode": "ask",
  "tools": {"deny": ["github/delete_*"], "ask": ["merge_pull_request"]},
  "network": {"allow": ["github.com", "*.python.org"], "unknown": "ask"},
  "rules": [{"id": "no-prod-db", "pattern": "prod-db", "verdict": "deny", "message": "Production is off-limits."}],
  "lock": {"on_new": "ask"},
  "receipts": {"include_args": false}
}
```

## Receipt format (`verfy.receipt/1`)

One JSON object per line in `~/.verfy/ledger.jsonl`: `v, id, seq, prev, issued_at, agent, session, action{server, tool, kind, args_sha256, args?}, decision{verdict, rules, policy_sha256, approved_by?}, outcome{status, result_sha256}, tool_sha256, kid, sig`. `sig` is Ed25519 over the canonical JSON of all other fields; `prev` is the SHA-256 of the previous receipt. Writes are serialized with an OS file lock, so parallel sessions never fork the chain.

### SCITT signed statements

```bash
verfy scitt export --out statements/ [--issuer URL]     # one COSE_Sign1 per receipt
verfy scitt verify statements/*.cose --pub signer.json  # COSE signature, CWT subject and the receipt's own signature
```

Each statement is a COSE_Sign1 (RFC 9052) with alg EdDSA, content type `application/json`, the key id and CWT claims (`iss`, `sub` = the receipt hash) in the protected header, and the canonical receipt as payload: the signed-statement envelope of the IETF SCITT architecture draft. Verfy does not run a transparency service or issue SCITT receipts.

## Tests

```bash
cd verfy-cli && python -m unittest discover -s tests     # needs Node for the cross-engine tests
```

## Limits

Rules are pattern matching, not a sandbox. Verfy sees only calls that pass through its hook or gateway. A receipt proves what Verfy decided and that the log was not edited, not what a tool did internally. Keep `~/.verfy/key.json` private.
