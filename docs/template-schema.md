# Template schema

A vulnerability template is a regular Bowire `BowireRecording` JSON file with three additional fields the security scanner consumes:

- `attack: true` — flags the file as a security probe, not a `bowire mock` fixture
- `vulnerability: { … }` — identifying + classification metadata
- `vulnerableWhen: { … }` — predicate-tree that fires when the response indicates vulnerability

The probe itself is the recording's first `steps[0]` entry. The scanner replays that step against the `--target` URL, evaluates `vulnerableWhen` against the response, emits a finding when the predicate matches.

## Full shape

```json
{
  "id": "bwr-graphql-001-introspection",
  "name": "GraphQL __schema introspection enabled in production",
  "description": "Free-form Markdown describing what the template tests for and why it matters.",
  "createdAt": 1747526400000,
  "recordingFormatVersion": 2,

  "attack": true,

  "vulnerability": {
    "id": "BWR-GRAPHQL-001",
    "cve": ["CVE-2024-XXXX"],
    "cwe": "CWE-200",
    "owaspApi": "API3-2023-BOPLA",
    "severity": "medium",
    "cvss": 5.3,
    "protocols": ["graphql"],
    "authors": ["your-github-handle"],
    "introduced": "2026-05-17",
    "references": [
      "https://graphql.org/learn/introspection/",
      "https://owasp.org/www-project-api-security/"
    ],
    "remediation": "Disable introspection in production. HotChocolate: …"
  },

  "steps": [
    {
      "id": "probe-1",
      "protocol": "graphql",
      "service": "graphql",
      "method": "introspection",
      "methodType": "Unary",
      "httpVerb": "POST",
      "httpPath": "/graphql",
      "metadata": { "Accept": "application/json" },
      "body": "{\"query\":\"{ __schema { types { name } } }\"}"
    }
  ],

  "vulnerableWhen": {
    "allOf": [
      { "status": 200 },
      { "bodyJsonPath": { "path": "$.data.__schema.types", "exists": true } },
      { "not": { "bodyJsonPath": { "path": "$.errors[0].message", "exists": true } } }
    ]
  }
}
```

## Predicate operators

### Leaf operators

Each tests one property of the response. Combine multiple leaves on one node via implicit AND.

| Operator | Matches when |
|---|---|
| `status: <int>` | HTTP status code equals |
| `statusIn: [int, …]` | HTTP status code is in the list |
| `bodyContains: "<substr>"` | Response body contains the literal substring |
| `bodyMatches: "<regex>"` | Response body matches the regex (.NET regex syntax, 1-second timeout) |
| `bodyJsonPath: { path, exists / equals / matches / anyValueMatches }` | See JSONPath section below |
| `headerEquals: { Name: "value", … }` | Header value equals (case-insensitive name) |
| `headerExists: ["Name", …]` | Header is present |
| `headerMissing: ["Name", …]` | Header is NOT present (useful for missing-security-header checks) |
| `latencyMsAtLeast: <int>` | Response latency ≥ N ms (blind-SQLi / timing-oracle detection) |

### Composite operators

Nest sub-predicates arbitrarily.

| Operator | Matches when |
|---|---|
| `allOf: [<pred>, …]` | Every sub-predicate matches |
| `anyOf: [<pred>, …]` | At least one sub-predicate matches |
| `not: <pred>` | The sub-predicate does NOT match |

### JSONPath subset

The `bodyJsonPath.path` field uses the same JSONPath subset Bowire's workbench supports:

- `$` — root
- `$.foo` — object property
- `$.foo.bar` — nested property
- `$.foo[0]` — array index
- `$.foo[*]` — array wildcard (returns every element)
- `$.foo[*].name` — wildcard + further navigation

Inner operators on the clause:

| Inner | Matches when |
|---|---|
| `exists: true` | At least one path-result exists |
| `exists: false` | No path-results (clause inverts) |
| `equals: "<value>"` | At least one path-result stringifies to this value |
| `matches: "<regex>"` | The combined (newline-joined) path-result text matches the regex |
| `anyValueMatches: "<regex>"` | At least one individual path-result matches the regex |

## Severity field

One of `critical` / `high` / `medium` / `low` / `info`. Drives the scanner's `--severity` filter.

- **critical** — unauthenticated RCE, mass data exfiltration, auth-bypass
- **high** — auth bypass under specific conditions, privilege escalation, sensitive data disclosure
- **medium** — information disclosure (introspection, reflection, stack traces), CSRF, BOLA
- **low** — configuration hygiene (missing headers, version banners)
- **info** — diagnostic only

## Stable ids

Once a template lands here, its `id` is frozen. CI dashboards (GitHub Code Scanning, GitLab Security Dashboard, Azure DevOps) group findings by id; renaming breaks the timeline of every customer who's already running the scanner.

## Protocol identifiers

The `vulnerability.protocols` array uses these canonical strings:

- `grpc`, `grpc-web`
- `rest`, `http`
- `graphql`
- `odata`
- `signalr`
- `websocket`
- `mqtt`
- `socketio`
- `sse`
- `mcp`
- `tacticalapi`
- `dis`
- `udp`
- `kafka`
- `surgewave`
- `akka`

If your template applies to multiple, list them all — the scanner's protocol filtering happens at scan time, not at template-load time.
