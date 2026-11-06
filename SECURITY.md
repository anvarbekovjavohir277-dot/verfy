# Security policy

## Reporting a vulnerability

Please report security issues **privately**:

Use GitHub → this repository → **Security** → **Report a vulnerability** (private vulnerability reporting, [direct link](https://github.com/anvarbekovjavohir277-dot/verfy-releases/security/advisories/new)), or email security@verfy.dev if you cannot use GitHub. The same is in [security.txt](https://verfy.dev/.well-known/security.txt). Only the maintainers see the report. If you cannot use GitHub, write to security@verfy.dev.

A way for an agent to get past Verfy (a command, path or tool call that should be denied or asked about but is allowed) counts as a vulnerability: report it privately the same way.

Include the affected component (CLI, web app, database migration), the version or commit, steps to reproduce, and the impact you observed. Please do not open public issues for vulnerabilities.

We aim to acknowledge reports within 2 business days, to keep you informed until a fix is released, and to fix a confirmed issue within 90 days. We publish an advisory when the fix is out, or after 90 days at the latest. We will credit you in the release notes unless you prefer otherwise.

## Find a bypass

Verfy has not had a professional penetration test yet, so we ask everyone to try to break it. Good places to start:

- a shell command, file path, URL or tool call that should be denied or asked about, but `verfy check "..."` (or `verfy check --tool NAME --args JSON`) allows;
- a way for an agent to switch Verfy off, change `verfy.lock` or the policy, or get a changed MCP tool past the gateway;
- a receipt chain that `verfy verify` accepts after it was edited;
- a way to read or change another organization's data in Verfy Cloud.

The limits in [`docs/SECURITY_LIMITATIONS.md`](docs/SECURITY_LIMITATIONS.md) are known and not bypasses (for example, a script the agent writes and then runs). Ideas for closing them are welcome as issues.

## Hall of fame

People who reported a valid bypass or vulnerability, with their permission:

*No reports yet. The first one goes here.*

## Scope

In scope:
- the `verfy` CLI as published on PyPI and as the standalone builds in this repository, the Claude Code plugin and the installers;
- the hosted service at https://verfy.dev (Verfy Cloud: the website, the Team dashboard and the API devices use).

Report issues in either the same way.

Out of scope: vulnerabilities in Supabase, Vercel or GitHub themselves (report to them), social engineering, denial-of-service testing, findings that require a fully compromised developer machine, and testing that touches other people's data or organizations.

## Safe harbor

We will not pursue legal action against good-faith research that stays within this policy, avoids privacy violations and service degradation, does not access other people's data, and gives us reasonable time to fix the issue before disclosure.

## Check a release

Files on PyPI carry a Sigstore attestation that names the repository that published them. `pip install verfy` does not check it for you, so run this for the version you have:

```bash
pip install pypi-attestations
pypi-attestations verify pypi --repository https://github.com/anvarbekovjavohir277-dot/verfy pypi:verfy-VERSION-py3-none-any.whl
```

It prints `OK:` and the file name, and fails if another repository published the file.

Each version also has a GitHub release in the [source repository](https://github.com/anvarbekovjavohir277-dot/verfy/releases) with the same files, each with a Sigstore bundle (`.sigstore.json`).

Standalone builds carry a build attestation: `gh attestation verify verfy-linux-x64.tar.gz -R anvarbekovjavohir277-dot/verfy-releases`. The install scripts run this themselves when a signed-in GitHub CLI is there. Without it they check only the SHA-256 list, which shows that the download is whole, not who built it, because the list comes from the same release.

Without the GitHub CLI, use [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 3 or newer. From 0.16.1 the list of each standalone release is signed, so checking the signature and then the list shows that this repository's workflow built the download:

```bash
cosign verify-blob SHA256SUMS --bundle SHA256SUMS.sigstore.json \
  --certificate-identity https://github.com/anvarbekovjavohir277-dot/verfy-releases/.github/workflows/build.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum -c SHA256SUMS --ignore-missing
```

The builds have no Apple or Microsoft code signature, so Windows or macOS may warn the first time you run one.

## Supported versions

Only the latest release receives security fixes during the MVP phase.

See also: [`docs/SECURITY_LIMITATIONS.md`](docs/SECURITY_LIMITATIONS.md).
