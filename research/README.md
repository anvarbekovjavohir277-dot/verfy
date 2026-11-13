# Research: do MCP tool definitions change between releases?

Verfy Lock assumes that tool definitions change after you approve them. This folder measures how often that happens in practice, so the claim rests on data instead of on a demo server.

- `servers.json`: the servers we look at: popular npm and PyPI MCP servers, including the reference servers. The 53 added on 13 November 2026 each had at least 2,000 downloads a week.
- `tool_history.py`: for one server, takes its newest releases from the registry, starts each one with `npx` or `uvx` the way an MCP client would, and records every tool definition, its Verfy pin (SHA-256 of name, description, input schema and, when sent, title, annotations and output schema) and the Verfy scanner's findings.
- `report.py`: compares consecutive releases (added, removed and changed tools; description or schema; patch, minor or major release) and lists scanner findings.
- `.github/workflows/research.yml`: runs all of it on throwaway GitHub runners, every Monday and on demand. Each run looks at a server's newest releases; [verfy.dev/servers](https://verfy.dev/servers) merges the runs into one history per server.

## Safety

These are third-party packages. They run only on GitHub's ephemeral runners, in a job with no token permissions and no secrets. Servers that want an API key get a placeholder such as `placeholder`, which is enough for most of them to list their tools. Nothing calls a tool: only `initialize` and `tools/list` are sent.

## Limits

- A server that will not start without a real key or a running database is recorded as "did not start". Those releases are left out of the comparison.
- A server can serve different definitions depending on its configuration, account or time. We record what it served on a clean machine with placeholder settings, on the day of the run.
- A changed description is not a vulnerability. Most changes are ordinary improvements. The point is that they reach your agent without anyone reviewing them, unless something like Verfy Lock pins them.
- If a run finds a description that looks malicious, we report it privately to the author first and publish only after they had time to respond.

## Run it

Actions → "Research - MCP tool changes" → Run workflow. Download the artifacts into `results/`, then:

```bash
python research/report.py results/ > report.md
```
