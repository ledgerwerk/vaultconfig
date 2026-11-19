---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 1
entry_id: entry-0003
release_version: v0.3.0
kind: fixed
summary:
  Fixed handling of schema-marked sensitive fields inside nested configuration values
status: accepted
audience: null
scopes: []
source_refs:
  - git:f9f2c90b2121e1ad2364f4eb526c562476b95153
paths:
  - vaultconfig/schema.py
  - vaultconfig/config.py
issues: []
prs: []
sources:
  - git:0938a81017fe3cce141e326f7a89d4c553de80b4
contributors: []
breaking: false
internal: false
order: 3
---

Sensitive paths are discovered recursively and can address fields in lists and mappings.
