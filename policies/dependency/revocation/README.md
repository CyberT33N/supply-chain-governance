# Dependency Revocation Policy

Revocation is enforced actively before download, not only recorded as
evidence. A revoked or quarantined dependency version must be blocked at the
approved-zone boundary through a download rule or an approved policy gateway.

A revocation decision binds:

- the affected package and version set;
- the affected consumers and module graphs;
- the block decision and its issuer;
- the replacement or rebuild decision;
- the blast radius and the recovery evidence.

The `dependency-policy/v1` `revocation.download_block` flag must remain `true`
for every shipped ecosystem policy.
