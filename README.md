# Supply Chain Governance

`supply-chain-governance` is the organization-agnostic core for supply chain
governance: the canonical `evidence-graph/v1` schema, its conformance
vectors, and versioned dependency policies.

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

## Repository layout

- `schemas/evidence-graph/v1/` contains the portable JSON Schema artifact.
- `schemas/evidence-graph/conformance/` contains the evidence-graph
  conformance vectors.
- `schemas/dependency-policy/v1/` contains the portable policy schema.
- `conformance/` contains the dependency-policy conformance vectors.
- `policies/dependency/` contains the shipped per-ecosystem policies.
- `exceptions/` contains top-level time-bounded exception records.
- `cmd/` contains the build, coverage, and conformance gate tooling.
- `internal/` contains the validators and whitebox contract tests.
- `docs/` contains architecture, development, and GitHub Ruleset
  documentation.

## Governance

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth. See
`docs/hosting-platforms/github/rulesets/` for the importable shared-line
Rulesets and their import timing.
