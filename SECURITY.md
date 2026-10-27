# Security Policy

## Supported versions

Security fixes are provided for the latest `main` (0.5.x) on a best-effort
basis. Older commits and deployments are not supported.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting:

1. Open the repository's **Security** tab.
2. Choose **Report a vulnerability**
   (`https://github.com/nechel12/proxpulse-judge/security/advisories/new`).
3. Include the affected commit/version, deployment type (Caddy, Cloudflare,
   Render, direct), a reproduction, and the impact.

Do not open a public issue or include real proxy credentials, API keys, or
personal data. If private reporting is unavailable, open a minimal public issue
asking the maintainer for a private channel without disclosing details.

## What to expect

- Acknowledgement within 7 days, best effort.
- Triage and a fix/mitigation plan; timelines depend on severity.
- No bug bounty.
- Credit in the advisory if desired.

## Scope

In scope:

- HTTP and header parsing, anonymity verdicts, rate limiting, IP/geo handling.
- Dockerfiles, entrypoint, database download scripts, and CI workflows.
- The public source code and published container images.

Out of scope:

- Accuracy or licensing of third-party databases (DB-IP, MaxMind).
- Availability, rate limits, or data of the shared public instances.
- Proxy behavior and verdicts: the judge is advisory, and a proxy can withhold
  or forge headers.
- Deployments that expose the service directly, disable the rate limit, or set
  `TRUST_PROXY`/`TRUST_CF` incorrectly. See the deployment notes.
- Social engineering, physical access, and third-party services.

## Security model

The judge does not authenticate clients and has no secrets. It is designed to
run behind a TLS-terminating reverse proxy with its HTTP port bound to
loopback. Trust in `X-Forwarded-For` / `CF-Connecting-IP` must match the actual
topology; a misconfigured trusted header lets clients spoof the reported
IP/geo and the rate-limit key. Verdicts are heuristics, not a security
boundary.

## Safe harbor

Good-faith research on your own instance is welcome. Do not test against the
shared public instances in a way that affects other users, and do not access
data or systems you do not own. Follow applicable law.
