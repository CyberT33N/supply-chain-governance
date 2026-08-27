# Capability pack: cosign

The `cosign` pack is the fleet's signature verifier bootstrap: the single
engine-bound pack that provisions the Sigstore `cosign` binary every
signature-bound pack needs for its proof. It is language-neutral — its
provisioning installs `cosign` and its assertion runs `cosign`, with no
dependency on a language toolchain — so it lives in the shared kernel's
`security` area.

A tenant never declares this pack: the engine binds the verifier's capability
identity as machinery configuration, resolves it against this registry at the
tenant's pinned stand, and provisions the verifier before any signature-bound
pack. The `extends` list of a tenant carries capabilities only.

## What the pack binds

- **Provisioning (`recipe`):** the engine downloads the pinned
  `cosign-<os>-<arch>` release binary for the runner platform, verifies the
  bound `sha256` digest fail-closed, and installs the tool into the tool
  cache.
- **The digest-only bootstrap exception:** this pack is the single documented
  form verified digest-only. A signature proof of the verifier by itself
  would be circular, and its anchor is the same integrity-pinned module
  channel the engine travels through — exactly as strong as the engine's own
  anchor, never weaker. No second identity may claim this exception.
- **Version assertion:** the install proof runs inside provisioning, not as a
  tenant gate — `cosign version` must carry the banner `v3.0.6`.
- **No gates, no discovery:** the verifier executes inside the engine's
  provisioning of other packs, so the descriptor carries no gate surface and
  no discovery surface.

## Bound versions and platforms

cosign `3.0.6` is the only bound version of this pack major — the version the
fleet's signer identity already executes. The descriptor binds the release
binaries for `linux-amd64`, `windows-amd64`, and `darwin-arm64` by URL and
digest from the official release checksums; a diverging artifact never
executes. A version or artifact change ships as a new pack major version,
never as an in-place edit.

## Usage

There is no tenant usage to declare. The engine provisions the verifier
before any signature-bound pack; a signature-bound pack whose verifier cannot
be provisioned fails closed before any pack gate.

## Verification

`go run -mod=readonly ./cmd/check-conformance` proves the positive and
negative vectors under `conformance/` and validates the shipped descriptor
`v1/pack.json` against the executable `capability-pack/v1` validator.
