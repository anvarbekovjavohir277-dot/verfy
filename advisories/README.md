# Verfy Advisories

Known vulnerabilities in MCP servers and other agent tooling, one [OSV](https://ossf.github.io/osv-schema/) file per advisory. They are published at https://verfy-tech.vercel.app/advisories and in the feed `/api/v1/advisories`.

Advisories are added by pull request to this folder. Anyone can send one.

## What belongs here

- A vulnerability in an MCP server, an agent tool or agent tooling that is **already public**: a CVE, a vendor advisory, a GitHub Security Advisory or a write-up by the people who found it.
- Not here: a vulnerability that has not been disclosed yet. Report it to the project's maintainers first. A way past Verfy itself is reported privately as described in [`SECURITY.md`](../SECURITY.md).

## Adding one

1. Copy an existing file, for example [`2025/VERFY-2025-0001.json`](2025/VERFY-2025-0001.json), into the folder for the year it was published.
2. Take the next free id (`VERFY-YYYY-NNNN`); the file name must equal the id.
3. Fill in:
   - `summary`: one line, 5–300 characters, starting with the package name;
   - `details`: what goes wrong, who can trigger it and how to fix or avoid it;
   - `severity_label`: `critical`, `high`, `medium` or `low`;
   - `affected`: the package (`ecosystem` and `name`) and the affected version ranges;
   - `aliases`: the CVE or GHSA ids, if there are any;
   - `references`: at least one `https://` link to a public source;
   - `published` and `modified`: RFC 3339 timestamps;
   - `database_specific.verfy_review`: `unreviewed`. A maintainer changes it to `reviewed` after reproducing the issue; the site never shows an unreviewed entry as verified.
4. Run `node advisories/validate.mjs` (Node 20 or newer, no install needed). CI runs the same check on your pull request.

You sign the [CLA](../CLA.md) once, by commenting on your first pull request.

## After it is merged

The hosted site copies this folder from a commit of this repository and publishes the advisories in its database, so a merged advisory appears on the site with the next update of the site, not instantly.

Until 27 October 2026 the ids began with `ATLS-`, an earlier working name of the project. Each old id is kept in `aliases`, and links to it lead to the new one.
