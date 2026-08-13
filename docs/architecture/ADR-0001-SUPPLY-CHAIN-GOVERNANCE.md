# ADR-0001: Supply Chain Governance Core

## Status

Accepted

## Context

The federated multi-tenant supply chain fortress separates
organization-agnostic cores from versioned organization and tenant
instances. The evidence graph profile `evidence-graph/v1` is the single
canonical definition of subject documents, relation types, lifecycle status
values, and evidence objects. Without an executable, versioned home for that
profile, every consumer would re-implement validation and drift from the
canonical contract.

## Decision

This repository is the organization-agnostic supply chain governance core.

1. It owns the canonical `evidence-graph/v1` JSON Schema, the executable Go
   validator, and the positive and negative conformance vectors for every
   subject type.
2. It owns the `dependency-policy/v1` admission and revocation policy format
   and the shipped per-ecosystem policies for `go`, `npm`, and `python`.
3. The executable validator is the conformance harness: positive vectors must
   validate, negative vectors must be rejected, and empty vector sets fail
   closed.
4. Policy documents are JSON so the validator needs no external dependency;
   the portable JSON Schema artifacts remain the interop surface for
   non-Go consumers.
5. This core never contains concrete organization bindings.
   This core never contains tenant bindings.
   It contains no credentials, tokens, private keys, or authorization
   headers, and the validator rejects documents that carry credential-like
   content.
6. Instances consume this core only through the three-pin consumption
   contract: module version pins for infrastructure, artifact digest pins for
   runtime, and schema version pins for policies and evidence.

## Consequences

- Every schema or policy change is a governed, reviewable change with
  conformance vectors for the new behaviour.
- A semantically incompatible change requires a new major schema identifier;
  additive optional fields remain valid within `evidence-graph/v1`.
- Organization and tenant instances validate their overlays and documents
  against these schema versions in their own CI.
- The core never references a concrete organization or tenant; instances
  reference only the core.
