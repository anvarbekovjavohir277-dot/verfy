# Internal attack test, November 2026

This is **not an independent penetration test**. It was run by the people who build Verfy, against Verfy's own code, on a local machine and in CI. Nobody outside has checked it, and we do not know what we did not think of. Verfy has still not had an independent test.

## What was tried

- 158 shell commands that should not pass: deleting home, running downloads, reading keys, sending data out, switching Verfy off, persistence. They went to the rule engine and were never run.
- 29 calls through Claude Code's tools and MCP tools, including paths and URLs written to look harmless.
- A gateway in front of a fake server: calling a changed tool in different ways, malformed messages, and a server that sends tricky tool lists.
- A receipt chain that was edited, cut, reordered, signed with another key, and signed with a malleable signature.
- A code review of how each Verfy Cloud API route checks who is calling.

## What got through, now fixed in 0.16.0

| Attack | Result before |
| --- | --- |
| `cat $HOME/.ssh/id_rsa` | allowed, while `cat ~/.ssh/id_rsa` was stopped |
| `http://2852039166/`, `http://0xa9fea9fe/`, `http://[::ffff:169.254.169.254]/` | the cloud metadata address got past the deny list |
| `{"uri": "file:///home/you/.ssh/id_rsa"}` | read as a URL, not as a file |
| `run_shell` with `{"args": ["rm", "-rf", "~"]}` | not read as a command |
| `busybox rm -rf ~`, `$(echo rm) -rf ~`, `x=rm; $x -rf ~`, `bash <<< '...'` | allowed |
| Inline code that deletes, fetches or reads a key (`python3 -c`, `node -e`, `perl -e`, `ruby -e`) | allowed |
| Download then run, `crontab`, `systemctl enable`, `git config core.hooksPath`, `docker run -v /:/h` | allowed |
| `pipx run verfy lock approve`, `uvx verfy lock approve`, `git rm verfy.lock` | allowed |
| `tools/call` without an id | passed the gateway unchecked |
| A line that is not strict JSON | passed the gateway unchecked |
| `params` of the wrong type | stopped the gateway |
| A changed `annotations`, `title` or `outputSchema` | the pin did not cover them |
| A sandboxed command writing `verfy.lock`, `verfy.policy.json`, `.claude/settings.json` or `.mcp.json` in its own folder | allowed by Verfy's settings |
| `AWS_SECRET_ACCESS_KEY` and other keys in the environment of a sandboxed command | passed in (fixed in 0.15.0) |

A review after 0.16.0 found that on Linux the last sandbox fix covered only files that existed when the command started, so a command could still create a missing `.mcp.json`. 0.16.1 closes that, with a test on Linux, macOS and WSL2. The rest is in the [limits](SECURITY_LIMITATIONS.md). After the fixes, 156 of the 158 commands are stopped or need a person. The other two do no harm: `verfy hook install` adds Verfy, and `export VERFY_HOME` does not reach the hook. Everyday commands stay allowed, and the cases above are now in the test suite both engines run.

## Second run, 6 November

Also internal, also not independent. We wrote new lists and measured 0.16.1 before changing anything.

| List | Tried | Got through before | After 0.17.0 |
| --- | --- | --- | --- |
| New shell attacks | 310 | 110 | 11, on purpose (below) |
| Windows commands through PowerShell and `cmd` | 51 | 43 | 0 |
| A fresh list, written after those fixes | 113 | 59 | 0 |
| Everyday commands that must stay allowed | 282 | | none stopped |

**The third row is the number to believe.** It was written after the first fixes and measured before its own: more than half got through. The 0 next to it means only that those commands are closed now. A new list will find more, so treat the guard as a seat belt and use `verfy run --sandbox` for code you do not trust.

The 11 still allowed are not attacks by themselves, or Verfy cannot judge them by name: `npx`, `uvx`, `npm i -g`, `nohup` or `setsid` around a script, `docker exec`, `git rebase -i`, `git config --list`, `aws sts get-caller-identity`, `cat /etc/passwd`, and a request to `localhost`.

The most serious finding was not a command. A `verfy.policy.json` in a repository replaced your policy and your team's, so cloning a repo could switch every rule off, let a changed tool through the gateway and write tokens into receipts. It now only tightens, until you trust the file.

Also fixed: MCP prompts were not pinned, the scanner gave an A to a fixed BCC address and to base64, other languages and spaced letters, secret redaction missed unquoted `.env` lines, and `verfy wrap` printed tokens. The [changelog](../CHANGELOG.md) has the full list.

## What held

- Every receipt attack, except cutting the end of a ledger, which is a [known limit](SECURITY_LIMITATIONS.md) that a copy in Verfy Cloud covers.
- A changed tool could not be called before or after `tools/list`, in a batch, or under a duplicate name.
- In Verfy Cloud, each route that uses the server's key first checks a session, a device token, a signature or an enrollment code, or is public on purpose. This was a reading of the code, on top of the row-level security tests. Nothing was tried against the live service.

## What this does not show

Rules are pattern matching, so someone will find more ways past them: a script the agent writes and then runs is the plain example, and it is why the sandbox exists. Found one? See [SECURITY.md](../SECURITY.md#find-a-bypass).
