# Traceability

## Tickets

| Ticket | Change | Status |
|---|---|---|
| SCG-1 | Establish the supply chain governance core: canonical `evidence-graph/v1` schema and validator, conformance vectors, `dependency-policy/v1` format, shipped go/npm/python policies, source-quality gates, CodeQL, dependency admission review, Dependabot, Lefthook, and importable Rulesets. | In progress |

## Scope boundaries

- SCG-1 delivers the source-level core only. It does not deliver a versioned
  release, an artifact delivery lane, or any organization- or tenant-bound
  content.
- The `release/*` and `support/*` branch families and their Rulesets are
  activated only with a complete governed release lifecycle.
