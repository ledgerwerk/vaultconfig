---
schema_version: 4
id: content-0009
kind: content
type: section
section: architecture_decisions
title: Architecture Decisions
order: 90
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/formats
  - vaultconfig/config.py
  - vaultconfig/crypt.py
  - vaultconfig/secrets/api.py
  - vaultconfig/secrets/encrypted_file.py
---

These decisions describe the current implementation:

| Decision                                                         | Consequence                                                                                                                                          |
| ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| Keep format handling behind adapters.                            | The manager can share validation and encryption across formats. Supported types and round-trip behavior still depend on the selected adapter.        |
| Keep V1 encrypted configuration separate from V2 secret storage. | Existing configurations remain readable. Moving credentials into a secret vault requires an explicit application or operator workflow.               |
| Update local files through atomic replacement.                   | Each replacement is atomic. Multi-file configuration updates use backups and best-effort rollback rather than a single atomic directory transaction. |
