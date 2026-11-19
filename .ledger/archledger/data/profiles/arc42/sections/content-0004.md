---
schema_version: 4
id: content-0004
kind: content
type: section
section: solution_strategy
title: Solution Strategy
order: 40
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/config.py
  - vaultconfig/formats
  - vaultconfig/secrets/api.py
---

The configuration path normalizes format-specific input to Python mappings, optionally validates those mappings against a schema, and serializes them independently of encryption. The secret-storage path instead exposes a small `SecretStore` protocol for named strings. This keeps callers independent of the selected secret backend without coupling secret storage to configuration parsing.
