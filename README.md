# Supply Chain Governance

`supply-chain-governance` is the organization-agnostic core for supply chain
governance: the canonical `evidence-graph/v1` schema, its conformance
vectors, and versioned dependency policies.

This repository never contains concrete organization, tenant, project,
identity, network, secret, or registry bindings. Instances consume this core
only through versioned releases, immutable digests, and schema version pins.

Governed changes land through ticket branches and pull requests into
`develop`. `main` is the production and control-plane truth.
