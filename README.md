# Supply Chain Governance

`supply-chain-governance` is the organization-agnostic core for supply chain
governance: the canonical `evidence-graph/v1` schema, its conformance
vectors, versioned dependency policies, the centralized
`quality-gate-config/v4` configuration seam, and the capability-pack registry
for shared gate behavior.

This repository never contains concrete organization, tenant, project,
identity, network, secret, or registry bindings. Organization instances and
tenant instances consume this core only through versioned releases, immutable
digests, and schema version pins.

## Core boundary

The core owns:

- the canonical `evidence-graph/v1` document envelope, subject types,
  relation types, lifecycle status values, and evidence types;
- positive and negative conformance vectors for every subject type;
- the `dependency-policy/v1` admission and revocation policy format;
- the centralized `quality-gate-config/v4` schema — the one seam definition
  for every territory, with the language-keyed toolchain identity and the
  capability-pack `extends` declaration;
- the `capability-pack/v1` descriptor schema and the language-neutral
  capability registry under `capabilities/` (one definition for every
  territory, never copied or redefined);
- the conformance harness that proves every vector against the executable
  validator.

The core never contains:

- concrete organization or tenant values;
- credentials, tokens, private keys, or authorization headers;
- runtime, deployment, or infrastructure bindings.

## Quality gates

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-conformance
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

Every executable Go package must reach exactly 100.0% statement coverage.

`cmd/build` is the full source-level gate: formatting, module checksums and
metadata, the pinned build tool module, lint (staticcheck), unit tests,
conformance vectors, exact 100% statement coverage, race detector, static
analysis, fail-closed vulnerability analysis (govulncheck), fuzz smoke lanes
for the strict evidence-graph, dependency-policy, and capability-pack
parsers, Lefthook configuration validation, Linux/AMD64 build, and module
provenance.

The Go toolchain is pinned exactly (`toolchain go1.26.6`,
`GOTOOLCHAIN=local`); no lane downloads a toolchain at build time. CI re-runs
the full gate daily so newly disclosed vulnerabilities fail closed even
without source changes.

In CI the repository is a tenant of the canonical repo surface: the three
shared-line workflows (`ci.yml`, `codeql.yml`, `dependency-review.yml`) are
byte-identical callers of the repository-governance home, and the canonical
quality gate of the go-quality-authority territory home runs through the
tooling module. The `repo-bindings.json` manifest binds the adoption (home
pin, fleet classes, caller and file hashes, config-seam and tool-catalog
versions), and the `Canonical conformance` check re-proves it fail-closed on
every shared-line change.

## Repository layout

- `schemas/evidence-graph/v1/` contains the portable JSON Schema artifact.
- `schemas/evidence-graph/conformance/` contains the evidence-graph
  conformance vectors.
- `schemas/dependency-policy/v1/` contains the portable policy schema.
- `schemas/quality-gate-config/v4/` contains the centralized quality
  configuration seam schema.
- `schemas/capability-pack/v1/` contains the portable capability pack
  descriptor schema.
- `capabilities/<area>/<capability>/` contains the language-neutral pack
  registry: each capability carries its README contract, its versioned
  `v<major>/pack.json` descriptor, and its conformance vectors.
- `conformance/` contains the dependency-policy conformance vectors.
- `policies/dependency/` contains the shipped per-ecosystem policies.
- `exceptions/` contains top-level time-bounded exception records.
- `cmd/` contains the build, coverage, and conformance gate tooling.
- `internal/` contains the validators and whitebox contract tests.
- `repo-bindings.json` binds the canonical repo-surface adoption (home pin,
  fleet classes, caller and file hashes, config-seam and tool-catalog
  versions).
- `docs/` contains architecture, development, and hosting-platform
  convention documentation.

## Governance

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth. Branch
governance is bound through the organization-level rule-sets; see
`docs/conventions/hosting-plattform/github/rule-sets/` for the canonical
source and the rule-set family of this repository.
