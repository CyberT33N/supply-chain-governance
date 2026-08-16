# Verification

This document binds the local and CI verification contract for the supply
chain governance core. It exists so every instance and every tenant consumer
can re-run the same gates.

## Local gates

Run from the repository root with the pinned Go toolchain (`go 1.26`,
`toolchain go1.26.6`):

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-conformance
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

`cmd/build` is the full source-level gate: formatting, module checksums,
module metadata, build tool download, build tool checksums, build tool
metadata, lint (staticcheck), unit tests, conformance vectors, exact 100%
statement coverage, race detector, static analysis, fail-closed
vulnerability analysis (govulncheck), fuzz smoke lanes for the strict
evidence-graph and dependency-policy parsers, Lefthook configuration
validation, Linux/AMD64 build, and module provenance.

## Build tooling

Build tools live in the separate `tools/` module and are resolved through
its own verified `go.mod` and committed `go.sum`; they never join the source
module graph. The module pins `govulncheck`, `staticcheck`, and `lefthook`
via the Go tool directive and shares the repository toolchain pin.

## Toolchain and vulnerability re-scans

The Go toolchain is pinned exactly (`toolchain go1.26.6`,
`GOTOOLCHAIN=local`); CI asserts `go env GOVERSION` before any gate runs and
no lane may download a toolchain at build time. `govulncheck` is part of the
full source gate, and CI re-runs the full gate on a daily schedule so newly
disclosed vulnerabilities in the pinned toolchain or dependency graph fail
closed even without source changes.

## Conformance harness

`cmd/check-conformance` proves:

- every positive `evidence-graph/v1` vector validates;
- every negative `evidence-graph/v1` vector is rejected;
- every positive and negative `dependency-policy/v1` vector behaves as
  classified;
- every shipped policy under `policies/dependency/` is conformant.

Empty vector directories fail closed. A vector that changes classification
fails the gate.

## CI gates

The `Quality gates (linux-amd64)` check runs the full source-level gate on
every push and pull request to the shared lines and once per day on a
schedule. The `Dependency admission review` check blocks unreviewed
dependency changes. CodeQL code scanning runs with all alerts blocking once
the shared-line Rulesets are imported.

Lefthook provides the local `commit-msg` hook (`git-governance --interactive
never commit validate --message-file`) and the pre-push source-quality gate.

## Instance and tenant consumption

An organization instance or tenant instance pins this core by module version,
artifact digest, and schema version. An instance never copies the schema or
policy source into its own boundary; it references the pinned version and
proves conformance in its own CI.
