---
schema_version: 4
id: content-0012
kind: content
type: section
section: glossary
title: Glossary
order: 120
status: accepted
version: 2
body_format: markdown
source_refs:
  - vaultconfig/config.py
  - vaultconfig/schema.py
  - vaultconfig/secrets/api.py
  - vaultconfig/secrets/envelope.py
---

| Term | Meaning |
| --- | --- |
| Config entry | A named configuration mapping held by `ConfigManager`. |
| Sensitive path | A schema-derived dotted path that identifies a value for optional obscuring. |
| Secret store | A backend that reads, writes, and deletes opaque string values by name. |
| Envelope | The versioned on-disk representation of a V2 file vault, containing metadata and ciphertext. |
