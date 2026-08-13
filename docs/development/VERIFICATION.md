# Verification

This document binds the local and CI verification contract for the supply
chain governance core. It exists so every instance and every tenant consumer
can re-run the same gates.

## Local gates

Run from the repository root with the pinned Go toolchain (`go 1.26`,
`toolchain go1.26.5`):

```text
gofmt
go test ./...
go run -mod=readonly ./cmd/check-conformance
go run -mod=readonly ./cmd/check-coverage
go run -mod=readonly ./cmd/build
```

`cmd/build` is the full source-level gate: formatting, module checksums,
module metadata, unit tests, conformance vectors, exact 100% statement
coverage, race detector, static analysis, Linux/AMD64 build, and module
provenance.

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

The `Quality gates (linux-amd64)` check runs the full source-level gate. The
`Dependency admission review` check blocks unreviewed dependency changes.
CodeQL code scanning runs with all alerts blocking once the shared-line
Rulesets are imported.

## Instance and tenant consumption

An organization instance or tenant instance pins this core by module version,
artifact digest, and schema version. An instance never copies the schema or
policy source into its own boundary; it references the pinned version and
proves conformance in its own CI.
