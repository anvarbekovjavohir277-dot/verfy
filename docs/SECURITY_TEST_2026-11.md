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

After the fixes, 156 of the 158 commands are stopped or need a person. The other two do no harm: `verfy hook install` adds Verfy, and `export VERFY_HOME` does not reach the hook. Everyday commands stay allowed, and the cases above are now in the test suite both engines run.

## What held

- Every receipt attack, except cutting the end of a ledger, which is a [known limit](SECURITY_LIMITATIONS.md) that a copy in Verfy Cloud covers.
- A changed tool could not be called before or after `tools/list`, in a batch, or under a duplicate name.
- In Verfy Cloud, each route that uses the server's key first checks a session, a device token, a signature or an enrollment code, or is public on purpose. This was a reading of the code, on top of the row-level security tests. Nothing was tried against the live service.

## What this does not show

Rules are pattern matching, so someone will find more ways past them: a script the agent writes and then runs is the plain example, and it is why the sandbox exists. Found one? See [SECURITY.md](../SECURITY.md#find-a-bypass).
