# Traceability

## Tickets

| Ticket | Change | Status |
|---|---|---|
| SCG-1 | Establish the supply chain governance core: canonical `evidence-graph/v1` schema and validator, conformance vectors, `dependency-policy/v1` format, shipped go/npm/python policies, source-quality gates, CodeQL, dependency admission review, Dependabot, Lefthook, and importable Rulesets. | In progress |
| SCG-2 | Migrate the module path, schema `$id` URLs, and Go import paths to the `t33n-software` organization namespace; add the LF line-ending contract (`.gitattributes`) and the push-protections Ruleset source `00-push-protections.json` in the verified GitHub export format. | In progress |
| SCG-3 | Align the Go 1.26.6 toolchain and source gates with the supply chain fortress contract: pinned `tools/` module with govulncheck, staticcheck, and Lefthook; fail-closed vulnerability analysis; fuzz smoke lanes for the strict parsers; Lefthook configuration validation and commit-msg hook; daily CI re-scan. | In progress |
| SCG-5 | Adopt the canonical repo surface: schema-v3 quality configuration, version surfaces on the development tools, canonical tool pins (go-quality-authority v1.0.1, repository-governance verifier), the canonical file family and CODEOWNERS, the three byte-identical workflow callers, the tenant binding manifest, and the canonical conformance check. | In progress |
| SCG-6 | Extend the shared kernel with the capability-pack registry: the centralized `quality-gate-config/v4` seam schema (language-keyed toolchain, `extends` declaration), the `capability-pack/v1` descriptor schema and executable validator, the language-neutral `opentofu@1` pack with digest- and signature-bound provisioning, conformance vectors and shipped-descriptor proofs, the third fuzz lane, and the repository's own schema-v4 configuration. | In progress |

## Scope boundaries

- SCG-1 delivers the source-level core only. It does not deliver a versioned
  release, an artifact delivery lane, or any organization- or tenant-bound
  content.
- The `release/*` and `support/*` branch families and their Rulesets are
  activated only with a complete governed release lifecycle.
