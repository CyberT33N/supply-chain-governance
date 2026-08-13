# Dependency Policy Exceptions

This directory holds the schema-bound, time-bounded exception records for
dependency admission decisions.

Every exception record:

- references the `dependency-policy/v1` exception contract;
- is time-bounded through a mandatory `expires_at` value;
- is reviewed like any other governed change through a pull request into
  `develop`;
- never contains credentials, tokens, private keys, or authorization headers.

Expired exceptions must be removed or renewed through a new governed change.
An expired exception never authorizes admission, promotion, or download.
