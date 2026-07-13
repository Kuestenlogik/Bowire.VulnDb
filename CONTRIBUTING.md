# Contributing to Bowire.VulnDb

Thanks for considering a template contribution. The template set only stays useful if it grows with the protocols, frameworks, and CVEs the security community is actively watching — your PR is the mechanism.

## What belongs in this repo

A template belongs here if it probes for **a publicly-known vulnerability or misconfiguration pattern** against a multi-protocol API. Concretely:

- ✅ CVE-tracked vulnerabilities in widely-deployed frameworks (ASP.NET Core, Spring, HotChocolate, Apollo, Express, etc.)
- ✅ OWASP API Security Top 10 patterns (BOLA, BFLA, SSRF, mass assignment, …)
- ✅ Misconfigurations with well-understood remediation (introspection in prod, reflection in prod, missing security headers, weak TLS, …)
- ✅ Protocol-specific weaknesses (gRPC oversized-message, GraphQL deep-nesting DoS, SignalR group-membership bypass, …)

What does NOT belong:

- ❌ 0-day exploits (PR them to the affected vendor first, then here once the advisory is public)
- ❌ Org-internal proprietary findings (use a private template directory — `~/.bowire/vulndb-local/` is the convention)
- ❌ Functional API tests (use the regular `bowire test` harness instead)
- ❌ DoS / load-test patterns that send large traffic volume against the target

## Where template ideas come from

Two feeds:

- **Open a PR for anything you've seen in the wild** — the community feed.
- **The monthly NVD sync** ([`scripts/nvd-sync.mjs`](scripts/nvd-sync.mjs), run by [`.github/workflows/nvd-sync.yml`](.github/workflows/nvd-sync.yml)) queries the National Vulnerability Database for freshly-published CVEs on the protocol surfaces Bowire probes (gRPC, GraphQL, MQTT, OData, SignalR, WebSocket, Socket.IO, MCP) and opens an [`nvd-sync`-labelled issue](https://github.com/Kuestenlogik/Bowire.VulnDb/issues?q=label%3Anvd-sync) for each CVE that has no template yet. Those issues are the triage queue: assess whether the CVE maps to a request-shaped, probeable signal, then either author a template (listing the CVE id in `vulnerability.cve`) or close as not-applicable. The sync never writes a template itself, deduplicates against existing issues + covering templates, and caps how many it opens per run — so picking one up is a good first contribution.

## Authoring a template

1. **Pick a protocol folder** — `templates/<protocol>/`. Add a folder if your protocol isn't represented yet.
2. **Name the file** after the template's lowercased id with dashes: `bwr-graphql-deep-nesting.json` for id `BWR-GRAPHQL-DEEP-NESTING`.
3. **Copy [`docs/template-schema.md`](docs/template-schema.md)** as the field reference.
4. **Predicates**: pair an `anyOf` of detection signals (status code + body marker + JSONPath + …) rather than a single brittle regex. Real servers vary their response shape between framework patch versions; multi-signal predicates absorb that.
5. **Severity rubric**: use the table below.
6. **Remediation field**: the most important part of the template. State the concrete framework setting / middleware to add, plus a 1-line verification command. A finding without a fix is noise.

### Severity rubric

| Severity | CVSS hint | When to use |
|---|---|---|
| `critical` | 9.0+ | Unauthenticated RCE, mass data exfiltration, auth-bypass |
| `high` | 7.0–8.9 | Auth bypass under specific conditions, privilege escalation, sensitive data disclosure |
| `medium` | 4.0–6.9 | Information disclosure (introspection, reflection, stack traces), CSRF, BOLA |
| `low` | 0.1–3.9 | Configuration hygiene (missing headers, version banners) |
| `info` | — | Diagnostic only — never a "fix this now" finding |

When in doubt, drop one tier. Operators filter the high-severity templates first; better to be reported as `medium` and run than skipped because the severity was inflated.

## Validation

Every PR runs CI:

1. **Schema validation** — file parses as a Bowire recording with `attack: true` + populated `vulnerability` + `vulnerableWhen`.
2. **Positive test** — the template MUST fire against [`Kuestenlogik.Bowire.Samples.Vulnerable`](https://github.com/Kuestenlogik/Bowire.Samples/tree/main/src/Kuestenlogik.Bowire.Samples.Vulnerable) (or whichever target you wire it against — declare it in the PR description).
3. **Negative test** — the template MUST stay silent against the patched variant (so a "predicate matches when target is hardened" bug doesn't ship).

PRs without both passes are blocked.

## Tone of the `remediation` field

Operators read this under stress. Write like you'd brief a colleague over Slack at 23:00 on a Friday after a finding lands in their inbox:

- ✅ "ASP.NET Core: drop `app.MapGrpcReflectionService()` from the production build, OR gate behind `.RequireAuthorization(\"Admin\")`. Verify with `grpcurl -plaintext <host> list` → should error."
- ❌ "Disable gRPC Server Reflection in accordance with secure-development best practices."

Concrete framework, concrete code, concrete verification. The platitudes don't help.

## Per-template metadata

Required:

- `id` (stable, never reused — CI dashboards group by this)
- `vulnerability.id` (matches the file's id)
- `vulnerability.severity`
- `vulnerability.protocols` (one or more)
- `vulnerability.remediation`

Recommended:

- `vulnerability.cwe` (`CWE-NNN`)
- `vulnerability.owaspApi` (`APIn-YYYY-NAME`)
- `vulnerability.cvss` (3.1 base score)
- `vulnerability.cve` (list of NVD entries when applicable)
- `vulnerability.references` (1-3 authoritative links — NVD entry, vendor advisory, blog write-up)
- `vulnerability.authors` (your handle)
- `vulnerability.introduced` (ISO-8601 date the template was first published)

## Stable ids

Once a template lands in `main`, its `id` is frozen. The CI dashboards (GitHub Code Scanning, GitLab Security Dashboard, Azure DevOps) group findings by `id`; renaming breaks the timeline of every customer who's already running the scanner.

If you discover an `id` clash with an existing template, append a kind-qualifier to your version (`BWR-GRAPHQL-001-INTROSPECTION` vs `BWR-GRAPHQL-002-DEEP-NESTING`) rather than renaming the older one.

## Questions?

Open an issue on the repo. The maintainers are the same crew that ships [Bowire](https://github.com/Kuestenlogik/Bowire).
