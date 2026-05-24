# Bowire.VulnDb

**Community vulnerability database for the Bowire security scanner.**

Multi-protocol API security templates that `bowire scan` consumes. One YAML/JSON file per known vulnerability or misconfiguration pattern; the scanner walks the templates, replays each one's probe against a target, evaluates the predicate against the response, and emits findings.

Anchor repo for the security-testing lane defined in [Bowire's ADR](https://github.com/Kuestenlogik/Bowire/blob/main/docs/architecture/security-testing.md). MIT-licensed; community contributions welcome via PR.

## Quickstart

```bash
# Install bowire (skip if you already have it)
dotnet tool install -g Kuestenlogik.Bowire.Tool

# Clone the templates
git clone https://github.com/Kuestenlogik/Bowire.VulnDb.git ~/.bowire/vulndb

# Run every template against your target
bowire scan --target https://your-api.example.com --templates ~/.bowire/vulndb/templates
```

To run a single template (or one folder):

```bash
bowire scan --target https://your-api.example.com --template templates/graphql/introspection-enabled.json
bowire scan --target https://your-api.example.com --templates templates/graphql
```

## Template tree

```
templates/
  grpc/              ← gRPC-specific findings (reflection, oversized-message, …)
  graphql/           ← GraphQL-specific findings (introspection, deep-nesting, …)
  rest/              ← REST / generic HTTP findings (security headers, open redirect, …)
  odata/             ← OData-specific findings ($expand IDOR, $filter injection, …)
  signalr/           ← SignalR hub findings (method brute-force, group bypass, …)
  websocket/         ← WebSocket findings (origin check missing, subprotocol confusion)
  mqtt/              ← MQTT broker findings (anonymous access, retained-message disclosure)
  socketio/          ← Socket.IO findings
  sse/               ← Server-Sent Events findings
```

Each template is a JSON file with a stable filename matching the template id (lowercased, dash-separated).

## Template format

A template is a regular Bowire `BowireRecording` with three additional fields the scanner consumes. Minimal example:

```json
{
  "id": "bwr-graphql-001-introspection",
  "name": "GraphQL __schema introspection enabled in production",
  "attack": true,
  "vulnerability": {
    "id": "BWR-GRAPHQL-001",
    "cwe": "CWE-200",
    "owaspApi": "API3-2023-BOPLA",
    "severity": "medium",
    "cvss": 5.3,
    "protocols": ["graphql"],
    "remediation": "Disable introspection in production…"
  },
  "steps": [
    {
      "id": "probe-1",
      "protocol": "graphql",
      "httpVerb": "POST",
      "httpPath": "/graphql",
      "body": "{\"query\":\"{ __schema { types { name } } }\"}"
    }
  ],
  "vulnerableWhen": {
    "allOf": [
      { "status": 200 },
      { "bodyJsonPath": { "path": "$.data.__schema.types", "exists": true } }
    ]
  }
}
```

Full schema documented in [`docs/template-schema.md`](docs/template-schema.md).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the authoring conventions, naming rules, severity rubric, and the per-template CI-validation requirement.

Quick rules:

- One template per file. Filename = lowercased `id` with dashes.
- Stable `id` (never reuse). CI dashboards group findings by id; renaming breaks history.
- Always include a `remediation` field. A finding without an actionable fix is just noise.
- Pair an `anyOf` of detection-signals in the predicate rather than a single brittle regex. Multiple signals tolerate minor server-response variations.
- Lower the severity bound when unsure — operators filter the high-severity templates first; better to be reported as `medium` and run than skipped because the severity was inflated.

## CI validation

Every PR runs the new + changed templates against a target deliberately misconfigured to trip the finding ([`Kuestenlogik.Bowire.Samples.Vulnerable`](https://github.com/Kuestenlogik/Bowire.Samples/tree/main/src/Kuestenlogik.Bowire.Samples.Vulnerable)). Two passes per template:

- **Positive** — the template MUST fire against the vulnerable sample (otherwise the predicate is broken).
- **Negative** — the template MUST stay silent against a patched / hardened variant (otherwise the predicate is too loose).

PRs that don't satisfy both passes are blocked. See [`.github/workflows/validate.yml`](.github/workflows/validate.yml).

## License

**MIT** (see [`LICENSE`](LICENSE)).

Why MIT here, when every other Bowire repo is Apache 2.0? This repo is a template set, not software. The scanner that consumes the templates is Apache 2.0 in [`Kuestenlogik/Bowire`](https://github.com/Kuestenlogik/Bowire); the JSON files in this repo describe known-public vulnerabilities and misconfigurations. The de-facto convention for security-template sets is MIT — [`projectdiscovery/nuclei-templates`](https://github.com/projectdiscovery/nuclei-templates) ships under MIT, and Bowire's scanner reads both sets through the same engine. Matching the convention keeps the two interchangeable. Templates are factual descriptions of public vulnerabilities and misconfigurations; the JSON shape itself is the contribution.
