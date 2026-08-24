# Capability pack: opentofu

The `opentofu` pack carries the shared OpenTofu infrastructure gate behavior
for every tenant that declares `extends: ["opentofu@1"]` in its
`git-governance.quality.json`. It is language-neutral: its provisioning
installs `tofu` and its gates run `tofu`, with no dependency on the tenant's
language toolchain, so it lives in the shared kernel.

## What the pack binds

- **Provisioning (`recipe`):** the orchestrator downloads the pinned
  `tofu_1.12.5_<os>_<arch>.zip` release artifact for the runner platform,
  verifies the bound `sha256` digest fail-closed, verifies the bound cosign
  signature reference, and installs the tool into the tool cache. The enforced
  environment (`OPENTOFU_ENFORCE_GPG_VALIDATION=true`, `TF_IN_AUTOMATION=true`,
  `TF_INPUT=false`) is part of the descriptor.
- **Version assertion:** before any gate runs, the pack proves the toolchain
  banner `OpenTofu v1.12.5` from `tofu version`.
- **Gates:**
  - `opentofu-fmt-check` — `tofu fmt -check -recursive` once at the repository
    root;
  - `opentofu-init` — `tofu init -backend=false -input=false -no-color` once
    per discovered HCL root;
  - `opentofu-validate` — `tofu validate -no-color` once per discovered HCL
    root.
- **Discovery:** the parent directories of `**/*.tf` form the per-root set;
  `.build`, `.git`, `.cache`, `.terraform`, `coverage`, `dist`, and `vendor`
  are excluded.

## Bound versions and platforms

OpenTofu `1.12.5` is the only bound version of this pack major. The descriptor
binds the release artifacts for `linux-amd64`, `windows-amd64`, and
`darwin-arm64` by URL and digest; a diverging artifact never executes. A
version or artifact change ships as a new pack major version, never as an
in-place edit.

## Usage

A tenant declares the pack and nothing else changes:

```json
{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "extends": ["opentofu@1"]
}
```

The reusable CI payload stays constant; the orchestrator provisions the tool
from the recipe and composes the pack gates after the built-in core and before
the project gates. A declared-but-unknown reference is a fail-closed finding,
never a silent skip.

## Verification

`go run -mod=readonly ./cmd/check-conformance` proves the positive and
negative vectors under `conformance/` and validates the shipped descriptor
`v1/pack.json` against the executable `capability-pack/v1` validator.
