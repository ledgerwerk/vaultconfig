---
schema_version: 2
object_type: release_entry
versioning:
  schema_version: 1
  revision: 2
entry_id: entry-0002
release_version: v0.3.1
kind: changed
summary:
  Changed new-vault Argon2id policy to pin defaults at 2 operations and 64 MiB while
  preserving V2 compatibility
status: accepted
audience: null
scopes: []
source_refs: []
paths:
  - vaultconfig/secrets/crypto.py
  - tests/test_secrets_file.py
issues: []
prs: []
sources:
  - tl:task-0004
contributors: []
breaking: false
internal: false
order: 2
---
